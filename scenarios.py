"""Fault scenarios for FixBot SecOps.

Each fault injector mutates a simulator.System with simulated metrics, config
and log lines only (no real network or attack code). Scenarios wrap one or two
faults plus random red-herring logs, and carry the ground truth used for
grading: expected root cause(s) and expected fix(es).

The "action" field of an expected fix is an agent tool name (see toolbox.py):
  restart, clear_disk, rollback_config, scale, block_ip, kill_process,
  rotate_secret
"""

import copy
import ipaddress
from dataclasses import dataclass

from simulator import System


# --- helpers ---------------------------------------------------------------

_ORDER = {"running": 0, "degraded": 1, "down": 2}


def _hit(system, name, status=None, **floors):
    """Raise a service's metrics to at least the given values (so combined
    faults never mask each other) and worsen its status if requested."""
    svc = system.services[name]
    for key, value in floors.items():
        setattr(svc, key, max(getattr(svc, key), value))
    if status and _ORDER[status] > _ORDER[svc.status]:
        svc.status = status
    return svc


def _ips(system, prefix, n):
    return [f"{prefix}.{system.rng.randint(2, 250)}" for _ in range(n)]


# --- fault injectors -------------------------------------------------------

def disk_full(system):
    _hit(system, "database", "degraded", disk=98.4, error_rate=0.15)
    system.log("database", "WARN", "/var/log/postgres is 41GB, no rotation configured")
    system.log("database", "ERROR", "could not write to file pg_wal/000001: No space left on device")
    system.log("database", "ERROR", "PANIC: could not extend relation: disk full")
    system.log("api", "ERROR", "upstream database write failed, returning 500")


def memory_leak(system):
    _hit(system, "worker", "degraded", memory=96.2, cpu=72.0, error_rate=0.05)
    for gb in (1.1, 1.6, 2.2, 2.9):
        system.log("worker", "INFO", f"job-runner 2 RSS {gb}GB")
    system.log("worker", "WARN", "gc pause 2400ms, heap not shrinking after job completion")
    system.log("worker", "ERROR", "MemoryError: unable to allocate buffer for job 1187")


def bad_config(system):
    api = _hit(system, "api", "down", error_rate=1.0)
    api.config["port"] = 8081
    system.log("api", "INFO", "config reloaded by deploy-bot: port 8080 -> 8081")
    system.log("api", "ERROR", "health probe: connection refused on :8080")
    system.log("api", "ERROR", "load balancer marked api unhealthy, 0 of 2 targets in service")


def conn_pool_exhausted(system):
    _hit(system, "database", "degraded", cpu=45.0, error_rate=0.10)
    _hit(system, "api", "degraded", error_rate=0.30)
    system.log("database", "FATAL", "remaining connection slots are reserved (100/100 in use, 87 idle in transaction)")
    system.log("api", "ERROR", "pool timeout: no connection available after 30s")
    system.log("api", "ERROR", "request failed: QueuePool limit of 20 overflow 0 reached")


def brute_force_login(system):
    _hit(system, "api", "degraded", cpu=86.0, error_rate=0.25)
    for ip in _ips(system, "198.51.100", 4):
        for user in ("admin", "root"):
            system.log("api", "WARN", f"POST /login 401 user={user} from {ip}")
    system.log("api", "WARN", "account locked: user=admin after 50 failed attempts in 60s")
    system.log("api", "WARN", "auth failure rate 41/s from 198.51.100.0/24")


def crypto_miner(system):
    worker = _hit(system, "worker", "degraded", cpu=99.0, error_rate=0.03)
    worker.processes.append("kworker-upd")  # disguised miner process
    system.log("worker", "WARN", "process kworker-upd (pid 4412) using 380% cpu, parent=cron")
    system.log("worker", "WARN", "outbound connection to pool.miner.example.test:4444 from kworker-upd")
    system.log("worker", "INFO", "job throughput dropped 80% since 02:13")


def leaked_secret(system):
    api = _hit(system, "api", "degraded", cpu=55.0, error_rate=0.12)
    key = api.config["api_key"]
    system.log("api", "WARN", f"config dump written to public log bucket (contains api_key={key[:16]}...)")
    system.log("api", "WARN", "api_key used from 203.0.113.50 (new region, never seen before)")
    system.log("api", "ERROR", "upstream 429: quota exceeded for api_key, 9400 requests in 10 min")


def malicious_config_change(system):
    db = _hit(system, "database", "degraded", cpu=88.0, error_rate=0.11)
    db.config["password_auth"] = False
    db.config["listen_addresses"] = "0.0.0.0"
    system.log("database", "WARN", "config changed by user=svc-tmp from 203.0.113.9: password_auth on -> off")
    system.log("database", "WARN", "config changed by user=svc-tmp from 203.0.113.9: listen_addresses 10.0.0.5 -> 0.0.0.0")
    system.log("database", "WARN", "connection authorized without password from 203.0.113.9 (x312)")
    system.log("database", "ERROR", "bulk read of table users by anonymous session, 1.2M rows")


def legit_traffic_spike(system):
    _hit(system, "api", "degraded", cpu=94.0, memory=70.0, error_rate=0.12)
    system.log("api", "INFO", "marketing: campaign 'spring-sale' newsletter sent to 400k subscribers")
    for ip in _ips(system, "198.18.0", 3) + _ips(system, "198.18.7", 3):
        system.log("api", "INFO", f"GET /v1/items?utm_source=newsletter 200 from {ip} ua=Mozilla/5.0 (iPhone)")
    system.log("api", "WARN", "request queue depth 340, p95 latency 4100ms")
    system.log("api", "ERROR", "timeout after 5000ms on 12% of requests")


def attack_spike(system):
    _hit(system, "api", "degraded", cpu=95.0, error_rate=0.20)
    for ip in _ips(system, "192.0.2", 4):
        system.log("api", "INFO", f"GET /v1/search?q=%25 200 from {ip} ua=python-requests/0.1")
    system.log("api", "WARN", "4 source IPs account for 97% of 18k req/min, all hitting /v1/search")
    system.log("api", "WARN", "no referer, no cookies, identical request pattern, ignoring robots.txt")
    system.log("api", "ERROR", "timeout after 5000ms on 20% of requests")


# --- fault registry --------------------------------------------------------

@dataclass(frozen=True)
class Fault:
    name: str
    type: str  # reliability | security
    inject: object
    services: tuple  # services whose metrics the fault degrades
    root_cause: str
    expected_fix: dict


FAULTS = {f.name: f for f in (
    Fault("disk_full", "reliability", disk_full, ("database",),
          "database disk is full because postgres logs are never rotated",
          {"action": "clear_disk", "service": "database"}),
    Fault("memory_leak", "reliability", memory_leak, ("worker",),
          "worker job-runner leaks memory across jobs",
          {"action": "restart", "service": "worker"}),
    Fault("bad_config", "reliability", bad_config, ("api",),
          "bad deploy changed api port to 8081 so the load balancer cannot reach it",
          {"action": "rollback_config", "service": "api"}),
    Fault("conn_pool_exhausted", "reliability", conn_pool_exhausted, ("database", "api"),
          "database connection slots are exhausted by idle-in-transaction sessions",
          {"action": "restart", "service": "database"}),
    Fault("brute_force_login", "security", brute_force_login, ("api",),
          "credential brute-force attack against api /login from 198.51.100.0/24",
          {"action": "block_ip", "service": "api", "target": "198.51.100.0/24"}),
    Fault("crypto_miner", "security", crypto_miner, ("worker",),
          "unauthorized crypto miner process kworker-upd running on worker",
          {"action": "kill_process", "service": "worker", "process": "kworker-upd"}),
    Fault("leaked_secret", "security", leaked_secret, ("api",),
          "api_key leaked in a public config dump and abused from 203.0.113.50",
          {"action": "rotate_secret", "service": "api", "key": "api_key"}),
    Fault("malicious_config_change", "security", malicious_config_change, ("database",),
          "unauthorized user svc-tmp disabled database password auth and opened it to 0.0.0.0",
          {"action": "rollback_config", "service": "database"}),
    Fault("legit_traffic_spike", "reliability", legit_traffic_spike, ("api",),
          "legitimate traffic surge from a marketing campaign exceeds api capacity",
          {"action": "scale", "service": "api", "workers": 8}),
    Fault("attack_spike", "security", attack_spike, ("api",),
          "automated scraping/DoS-style flood on api /v1/search from 192.0.2.0/24",
          {"action": "block_ip", "service": "api", "target": "192.0.2.0/24"}),
)}


# Grading ground truth. A root cause statement is correct for a fault when it
# matches at least one keyword from every group (case-insensitive).
ROOT_CAUSE_KEYWORDS = {
    "disk_full": (("disk", "space"), ("database", "postgres", "log")),
    "memory_leak": (("memory", "leak", "rss", "heap"), ("worker", "job-runner")),
    "bad_config": (("port", "8081"),),
    "conn_pool_exhausted": (("connection", "pool", "slots"), ("idle", "exhaust", "100/100", "reserved")),
    "brute_force_login": (("brute", "credential", "password guess", "login attempt", "failed login"),),
    "crypto_miner": (("miner", "mining", "kworker-upd"),),
    "leaked_secret": (("leak", "exposed", "public", "compromis"), ("key", "secret")),
    "malicious_config_change": (("svc-tmp", "unauthorized", "malicious", "203.0.113.9"),
                                ("password", "auth", "0.0.0.0", "listen")),
    "legit_traffic_spike": (("campaign", "newsletter", "marketing", "legitimate"),),
    "attack_spike": (("scrap", "flood", "dos", "bot", "192.0.2", "automated"),),
}

# Networks controlled by the attacker; blocking anything else is a false positive.
ATTACKER_NETWORKS = {
    "brute_force_login": ("198.51.100.0/24",),
    "attack_spike": ("192.0.2.0/24",),
    "malicious_config_change": ("203.0.113.9/32",),
    "leaked_secret": ("203.0.113.50/32",),
}


def fix_matches(expected, action, args):
    """True if a tool call (action, args) fixes a fault with this expected fix."""
    if action != expected["action"]:
        return False
    if action == "block_ip":
        try:
            blocked = ipaddress.ip_network(args.get("target", ""), strict=False)
        except ValueError:
            return False
        return ipaddress.ip_network(expected["target"]).subnet_of(blocked)
    if args.get("service") != expected["service"]:
        return False
    if action == "scale":
        return int(args.get("workers", 0)) >= expected["workers"]
    if action == "kill_process":
        return args.get("process") == expected["process"]
    if action == "rotate_secret":
        return args.get("key") == expected["key"]
    return True


# --- red herrings ----------------------------------------------------------

# Alarming-looking but benign lines that should not drive the diagnosis.
RED_HERRINGS = (
    ("api", "WARN", "deprecated header X-Forwarded-Host used by client"),
    ("api", "ERROR", "favicon.ico not found (404)"),
    ("database", "WARN", "slow query 210ms: SELECT count(*) FROM audit_log"),
    ("database", "ERROR", "canceling statement due to user request (psql session closed)"),
    ("cache", "WARN", "overcommit_memory is set to 0, background save may fail under low memory"),
    ("cache", "ERROR", "replica 10.0.0.9 link down, retrying (replica is decommissioned)"),
    ("worker", "WARN", "job 1031 retried once, succeeded on attempt 2"),
    ("worker", "ERROR", "failed to send metrics to statsd, dropping batch"),
    ("api", "WARN", "TLS certificate expires in 29 days"),
    ("database", "WARN", "unrecognized configuration parameter 'old_setting' ignored"),
)


def add_red_herrings(system, n):
    for service, level, message in system.rng.sample(RED_HERRINGS, n):
        system.log(service, level, message)


# --- scenarios -------------------------------------------------------------

@dataclass(frozen=True)
class Scenario:
    name: str
    type: str  # reliability | security (security if any fault is a security one)
    faults: tuple
    seed: int
    red_herrings: int = 3

    @property
    def root_causes(self):
        return [FAULTS[f].root_cause for f in self.faults]

    @property
    def expected_fixes(self):
        return [FAULTS[f].expected_fix for f in self.faults]

    def build(self):
        """Return a fresh, deterministic, broken System for this scenario."""
        system = System(seed=self.seed)
        system.advance(3)
        system.baseline = {n: copy.deepcopy(s) for n, s in system.services.items()}
        system.active_faults = list(self.faults)
        for f in self.faults:
            FAULTS[f].inject(system)
        add_red_herrings(system, self.red_herrings)
        return system


def make_scenario(name, faults, seed, red_herrings=3):
    faults = (faults,) if isinstance(faults, str) else tuple(faults)
    kind = "security" if any(FAULTS[f].type == "security" for f in faults) else "reliability"
    return Scenario(name, kind, faults, seed, red_herrings)


DEV_SCENARIOS = [
    make_scenario("disk_full", "disk_full", 101),
    make_scenario("memory_leak", "memory_leak", 102),
    make_scenario("bad_config", "bad_config", 103),
    make_scenario("conn_pool_exhausted", "conn_pool_exhausted", 104),
    make_scenario("brute_force_login", "brute_force_login", 105),
    make_scenario("crypto_miner", "crypto_miner", 106),
    make_scenario("legit_traffic_spike", "legit_traffic_spike", 107),
    make_scenario("double_leak_and_bruteforce", ("memory_leak", "brute_force_login"), 108),
    make_scenario("double_disk_and_badconfig", ("disk_full", "bad_config"), 109),
    make_scenario("double_attack_and_pool", ("attack_spike", "conn_pool_exhausted"), 110),
]

HELD_OUT_SCENARIOS = [
    make_scenario("leaked_secret", "leaked_secret", 901),
    make_scenario("malicious_config_change", "malicious_config_change", 902),
    make_scenario("attack_spike", "attack_spike", 903),
    make_scenario("double_miner_and_disk", ("crypto_miner", "disk_full"), 904),
    make_scenario("double_maliciousconfig_and_legit_spike",
                  ("malicious_config_change", "legit_traffic_spike"), 905),
]

SCENARIOS = {s.name: s for s in DEV_SCENARIOS + HELD_OUT_SCENARIOS}
