"""Simulated system for FixBot SecOps.

Four services (api, database, cache, worker) with status, metrics, config,
processes and log lines. Everything is deterministic from a seed. There is no
real network or attack code: incidents are only simulated logs and metrics.
"""

import copy
import random
from dataclasses import dataclass, field

SERVICE_NAMES = ("api", "database", "cache", "worker")

# Thresholds used by health_check().
CPU_WARN, CPU_CRIT = 75.0, 90.0
MEM_WARN, MEM_CRIT = 80.0, 92.0
DISK_WARN, DISK_CRIT = 80.0, 92.0
ERR_WARN, ERR_CRIT = 0.02, 0.10

_BASE = {
    "api": {
        "cpu": 25, "memory": 40, "disk": 30, "port": 8080,
        "config": {"port": 8080, "workers": 4, "rate_limit_per_min": 600,
                   "debug": False, "allowed_origins": ["https://app.example.test"],
                   "api_key": "FAKE-sk_live_0riginal0000key0"},
        "processes": ["gunicorn: master", "gunicorn: worker 1", "gunicorn: worker 2"],
        "logs": ["GET /health 200 3ms", "GET /v1/items 200 18ms", "POST /v1/orders 201 42ms"],
    },
    "database": {
        "cpu": 30, "memory": 55, "disk": 45, "port": 5432,
        "config": {"port": 5432, "max_connections": 100, "password_auth": True,
                   "listen_addresses": "10.0.0.5"},
        "processes": ["postgres: main", "postgres: checkpointer", "postgres: walwriter"],
        "logs": ["checkpoint complete", "connection authorized: user=app", "autovacuum: done"],
    },
    "cache": {
        "cpu": 15, "memory": 45, "disk": 10, "port": 6379,
        "config": {"port": 6379, "maxmemory_mb": 512, "requirepass": True,
                   "bind": "10.0.0.6"},
        "processes": ["redis-server"],
        "logs": ["DB saved on disk", "0 keys expired", "client connected"],
    },
    "worker": {
        "cpu": 35, "memory": 50, "disk": 20, "port": None,
        "config": {"concurrency": 4, "queue": "default", "max_retries": 3},
        "processes": ["worker: main", "worker: job-runner 1", "worker: job-runner 2"],
        "logs": ["job 1042 done", "job 1043 done", "queue depth 2"],
    },
}


@dataclass
class Service:
    name: str
    status: str = "running"  # running | degraded | down
    cpu: float = 0.0
    memory: float = 0.0
    disk: float = 0.0
    error_rate: float = 0.0  # fraction of failed requests, 0..1
    config: dict = field(default_factory=dict)
    processes: list = field(default_factory=list)
    logs: list = field(default_factory=list)

    def metrics(self):
        return {"cpu": self.cpu, "memory": self.memory, "disk": self.disk,
                "error_rate": self.error_rate}


class System:
    def __init__(self, seed=0):
        self.seed = seed
        self.rng = random.Random(seed)
        self.tick = 0
        self.services = {}
        self.baseline = {}  # name -> healthy Service copy, set by Scenario.build()
        self.active_faults = []  # unresolved fault names, set by Scenario.build()
        for name in SERVICE_NAMES:
            base = _BASE[name]
            svc = Service(
                name=name,
                cpu=base["cpu"], memory=base["memory"], disk=base["disk"],
                error_rate=0.002,
                config=copy.deepcopy(base["config"]),
                processes=list(base["processes"]),
            )
            self.services[name] = svc
        # Seeded jitter makes each seed a slightly different healthy system.
        for svc in self.services.values():
            svc.cpu = self._jitter(svc.cpu, 4)
            svc.memory = self._jitter(svc.memory, 4)
            svc.disk = self._jitter(svc.disk, 3)
            svc.error_rate = round(self.rng.uniform(0.0, 0.006), 4)
            for line in _BASE[svc.name]["logs"]:
                self.log(svc.name, "INFO", line)

    def _jitter(self, value, spread):
        return round(min(100.0, max(0.0, value + self.rng.uniform(-spread, spread))), 1)

    def log(self, name, level, message):
        self.services[name].logs.append(f"[t={self.tick:04d}] {level} {message}")

    def advance(self, n=1):
        """Advance simulated time: healthy services get small seeded metric drift."""
        for _ in range(n):
            self.tick += 1
            for svc in self.services.values():
                if svc.status == "down":
                    continue
                svc.cpu = self._jitter(svc.cpu, 1.5)
                svc.memory = self._jitter(svc.memory, 0.8)
                self.log(svc.name, "INFO", self.rng.choice(_BASE[svc.name]["logs"]))

    def snapshot(self):
        """Plain-dict view of the whole system (e.g. to hand to an agent)."""
        return {
            "seed": self.seed, "tick": self.tick,
            "services": {n: {"status": s.status, **s.metrics(), "config": s.config,
                             "processes": s.processes, "logs": s.logs[-10:]}
                         for n, s in self.services.items()},
        }


def _service_health(svc):
    issues = []
    level = "healthy"

    def bump(new):
        nonlocal level
        order = ["healthy", "degraded", "critical"]
        if order.index(new) > order.index(level):
            level = new

    if svc.status == "down":
        bump("critical")
        issues.append("service is down")
    elif svc.status == "degraded":
        bump("degraded")
        issues.append("service reports degraded status")
    if not svc.processes:
        bump("critical")
        issues.append("no processes running")
    for label, value, warn, crit in (
        ("cpu", svc.cpu, CPU_WARN, CPU_CRIT),
        ("memory", svc.memory, MEM_WARN, MEM_CRIT),
        ("disk", svc.disk, DISK_WARN, DISK_CRIT),
        ("error_rate", svc.error_rate, ERR_WARN, ERR_CRIT),
    ):
        if value >= crit:
            bump("critical")
            issues.append(f"{label} critical ({value})")
        elif value >= warn:
            bump("degraded")
            issues.append(f"{label} high ({value})")
    return {"status": level, "issues": issues}


def health_check(system):
    """Return overall health plus a per-service breakdown.

    overall is "healthy", "degraded" or "critical" (the worst service wins).
    """
    services = {n: _service_health(s) for n, s in system.services.items()}
    order = ["healthy", "degraded", "critical"]
    overall = max((v["status"] for v in services.values()), key=order.index)
    return {"overall": overall, "healthy": overall == "healthy", "services": services}
