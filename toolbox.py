"""Agent tools over a simulated System.

Read-only tools inspect the system. Action tools change it: an action that
matches an active fault's expected fix resolves that fault, and a service
whose faults are all resolved returns to its healthy baseline. Wrong actions
don't fix anything (some log why). No tool deletes data: clear_disk archives
and compresses logs, rollback_config restores the last known-good config.

isolate and IP-range blocks need approval through the approve callback.
"""

import copy
import ipaddress
import json
import re

from scenarios import FAULTS, fix_matches
from simulator import SERVICE_NAMES, health_check

READ_ONLY = {"get_metrics", "read_logs", "get_config", "list_processes",
             "get_auth_logs", "health_check"}
ACTIONS = {"restart", "clear_disk", "rollback_config", "scale", "block_ip",
           "kill_process", "isolate", "rotate_secret"}
SECRET_KEYS = {"api_key"}
# Keys managed by scale / rotate_secret, which rollback_config leaves alone.
OPERATIONAL_KEYS = SECRET_KEYS | {"workers"}
AUTH_PATTERN = re.compile(r"login|401|auth|password|api_key|config changed|account locked", re.I)
LEGIT_RANGE = ipaddress.ip_network("198.18.0.0/15")


class ToolError(Exception):
    pass


class Toolbox:
    def __init__(self, system, approve):
        self.system = system
        self.approve = approve  # approve(tool_name, args) -> bool
        self.classification = None
        self.actions = []  # {"tool", "args", "reason", "approved", "result"}
        self.verified = False  # health_check called since the last action
        self.damaged = set()  # services broken by the agent, healed by restart

    def call(self, name, args):
        """Run a tool. Returns (result_text, is_error)."""
        try:
            if name in ACTIONS:
                if self.classification is None:
                    raise ToolError("classify the incident with classify_incident before acting")
                return self._act(name, args), False
            if name in READ_ONLY:
                return json.dumps(getattr(self, name)(**args), indent=1), False
            if name == "classify_incident":
                return self.classify_incident(**args), False
            raise ToolError(f"unknown tool {name}")
        except ToolError as e:
            return f"error: {e}", True
        except TypeError as e:
            return f"error: bad arguments: {e}", True

    # --- read-only ----------------------------------------------------------

    def _svc(self, service):
        if service not in self.system.services:
            raise ToolError(f"unknown service {service!r}, expected one of {SERVICE_NAMES}")
        return self.system.services[service]

    def get_metrics(self, service=None):
        names = [service] if service else SERVICE_NAMES
        return {n: {"status": self._svc(n).status, **self._svc(n).metrics()} for n in names}

    def read_logs(self, service, limit=40, contains=None):
        lines = self._svc(service).logs
        if contains:
            lines = [l for l in lines if contains.lower() in l.lower()]
        return lines[-min(int(limit), 100):]

    def get_config(self, service):
        config = copy.deepcopy(self._svc(service).config)
        for key in SECRET_KEYS & config.keys():
            config[key] = config[key][:13] + "...(redacted)"
        return config

    def list_processes(self, service):
        return self._svc(service).processes

    def get_auth_logs(self, service=None):
        names = [service] if service else SERVICE_NAMES
        return {n: [l for l in self._svc(n).logs if AUTH_PATTERN.search(l)][-40:] for n in names}

    def health_check(self):
        self.verified = True
        return health_check(self.system)

    def classify_incident(self, classification, rationale):
        if classification not in ("reliability", "security"):
            raise ToolError("classification must be 'reliability' or 'security'")
        self.classification = classification
        return f"classified as {classification}; you may now take actions"

    # --- actions ------------------------------------------------------------

    def _act(self, name, args):
        args = dict(args)
        reason = args.pop("reason", "")
        if not reason:
            raise ToolError("every action needs a 'reason'")
        record = {"tool": name, "args": args, "reason": reason, "approved": None}
        if self._needs_approval(name, args):
            record["approved"] = bool(self.approve(name, {**args, "reason": reason}))
            if not record["approved"]:
                record["result"] = "denied by operator"
                self.actions.append(record)
                return "denied by operator; choose a different action or ask with a better reason"
        result = getattr(self, "_" + name)(**args)
        self._resolve(name, args)
        self.system.advance(1)
        self._settle()
        self.verified = False
        record["result"] = result
        self.actions.append(record)
        return result + " (run health_check to verify)"

    @staticmethod
    def _needs_approval(name, args):
        if name == "isolate":
            return True
        if name == "block_ip":
            try:
                net = ipaddress.ip_network(args.get("target", ""), strict=False)
            except ValueError:
                return False  # rejected later as invalid
            return net.num_addresses > 1
        return False

    def _resolve(self, name, args):
        for fault in list(self.system.active_faults):
            if fix_matches(FAULTS[fault].expected_fix, name, args):
                self.system.active_faults.remove(fault)

    def _settle(self):
        """Return services with no remaining fault to their healthy baseline."""
        affected = {s for f in self.system.active_faults for s in FAULTS[f].services}
        for name, svc in self.system.services.items():
            if name in affected or name in self.damaged:
                continue
            base = self.system.baseline.get(name)
            if base is None:
                continue
            was_unhealthy = health_check(self.system)["services"][name]["status"] != "healthy"
            svc.status = base.status
            svc.cpu, svc.memory, svc.disk = base.cpu, base.memory, base.disk
            svc.error_rate = base.error_rate
            svc.processes = list(base.processes)
            if was_unhealthy:
                self.system.log(name, "INFO", "metrics back to normal range")

    def _restart(self, service):
        svc = self._svc(service)
        self.damaged.discard(service)
        miner = "kworker-upd" in svc.processes
        svc.processes = list(self.system.baseline[service].processes)
        if miner:
            svc.processes.append("kworker-upd")
            self.system.log(service, "WARN", "kworker-upd respawned by cron 4s after restart")
        self.system.log(service, "INFO", f"{service} restarted")
        return f"{service} restarted"

    def _clear_disk(self, service):
        svc = self._svc(service)
        svc.disk = max(0.0, round(svc.disk - 5.0, 1))
        self.system.log(service, "INFO", "old logs compressed and moved to archive storage (nothing deleted)")
        return f"rotated and archived old logs on {service}; nothing deleted"

    def _rollback_config(self, service):
        svc = self._svc(service)
        base = self.system.baseline[service].config
        changed = {k: (svc.config.get(k), v) for k, v in base.items()
                   if k not in OPERATIONAL_KEYS and svc.config.get(k) != v}
        for k, (_, v) in changed.items():
            svc.config[k] = copy.deepcopy(v)
        self.system.log(service, "INFO", f"config rolled back to last known-good: {sorted(changed)}")
        if not changed:
            return f"{service} config already matches last known-good; nothing changed"
        return "rolled back " + ", ".join(f"{k}: {old!r} -> {new!r}" for k, (old, new) in changed.items())

    def _scale(self, service, workers):
        workers = int(workers)
        if not 1 <= workers <= 32:
            raise ToolError("workers must be between 1 and 32")
        svc = self._svc(service)
        old = svc.config.get("workers", svc.config.get("concurrency"))
        svc.config["workers"] = workers
        if "attack_spike" in self.system.active_faults and service == "api":
            self.system.log(service, "WARN", "extra capacity absorbed by the same 4 source IPs; load unchanged")
        return f"{service} scaled from {old} to {workers} workers"

    def _block_ip(self, target):
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ToolError(f"invalid IP or CIDR {target!r}")
        if net.prefixlen < 16:
            raise ToolError("refusing to block a range wider than /16")
        if net.overlaps(LEGIT_RANGE):
            self.system.log("api", "WARN", f"blocked range {net} includes recent legitimate customer traffic")
        for fault in self.system.active_faults:
            expected = FAULTS[fault].expected_fix
            if expected["action"] == "block_ip" and net.num_addresses == 1 and \
                    net.subnet_of(ipaddress.ip_network(expected["target"])):
                self.system.log("api", "WARN", f"traffic continues from other addresses in {expected['target']}")
        self.system.log("api", "INFO", f"firewall: deny from {net}")
        return f"blocked {net} at the edge firewall"

    def _kill_process(self, service, process):
        svc = self._svc(service)
        if process not in svc.processes:
            raise ToolError(f"no process {process!r} on {service}; see list_processes")
        svc.processes.remove(process)
        if process != "kworker-upd":
            self.damaged.add(service)
            svc.status = "degraded"
            self.system.log(service, "ERROR", f"{process} killed; service degraded until restart")
        else:
            self.system.log(service, "INFO", f"{process} killed, cron entry quarantined")
        return f"killed {process} on {service}"

    def _isolate(self, service):
        svc = self._svc(service)
        svc.config["network"] = "isolated"
        self.system.log(service, "WARN", "network isolated: outbound traffic blocked, internal traffic only")
        return f"{service} isolated from external network (containment only, root cause not fixed)"

    def _rotate_secret(self, service, key):
        svc = self._svc(service)
        if key not in svc.config:
            raise ToolError(f"{service} has no secret {key!r}")
        svc.config[key] = "FAKE-sk_live_" + "".join(
            self.system.rng.choice("0123456789abcdef") for _ in range(16))
        self.system.log(service, "INFO", f"{key} rotated; old value revoked")
        return f"rotated {key} on {service}; old value revoked"
