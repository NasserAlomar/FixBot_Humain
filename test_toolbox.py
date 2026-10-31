from scenarios import SCENARIOS
from toolbox import Toolbox

ALLOW = lambda name, args: True
DENY = lambda name, args: False


def _box(name, approve=ALLOW):
    box = Toolbox(SCENARIOS[name].build(), approve)
    box.call("classify_incident", {"classification": SCENARIOS[name].type, "rationale": "test"})
    return box


def _apply(box, fix):
    args = {k: v for k, v in fix.items() if k != "action"}
    if fix["action"] in ("block_ip",):
        args.pop("service")
    return box.call(fix["action"], {**args, "reason": "test"})


def test_expected_fixes_recover_every_scenario():
    for name, s in SCENARIOS.items():
        box = _box(name)
        for fix in s.expected_fixes:
            _, err = _apply(box, fix)
            assert not err, (name, fix)
        health = box.call("health_check", {})[0]
        assert '"healthy": true' in health, (name, health)


def test_actions_blocked_before_classification():
    box = Toolbox(SCENARIOS["crypto_miner"].build(), ALLOW)
    text, err = box.call("kill_process", {"service": "worker", "process": "kworker-upd", "reason": "x"})
    assert err and "classify" in text


def test_restart_does_not_remove_miner():
    box = _box("crypto_miner")
    box.call("restart", {"service": "worker", "reason": "x"})
    assert "kworker-upd" in box.list_processes("worker")
    assert not box.health_check()["healthy"]


def test_single_ip_block_does_not_stop_brute_force():
    box = _box("brute_force_login")
    ip = next(l.split("from ")[1] for l in box.read_logs("api", 100) if "401" in l)
    box.call("block_ip", {"target": ip, "reason": "x"})
    assert not box.health_check()["healthy"]
    assert box.actions[-1]["approved"] is None  # single IP needs no approval


def test_range_block_needs_approval():
    box = _box("brute_force_login", DENY)
    text, _ = box.call("block_ip", {"target": "198.51.100.0/24", "reason": "x"})
    assert "denied" in text and box.actions[-1]["approved"] is False
    assert not box.health_check()["healthy"]
    text, _ = box.call("isolate", {"service": "api", "reason": "x"})
    assert "denied" in text


def test_scaling_does_not_fix_attack():
    box = _box("attack_spike")
    box.call("scale", {"service": "api", "workers": 16, "reason": "x"})
    assert not box.health_check()["healthy"]


def test_killing_legit_process_damages_until_restart():
    box = _box("crypto_miner")
    box.call("kill_process", {"service": "worker", "process": "worker: main", "reason": "x"})
    box.call("kill_process", {"service": "worker", "process": "kworker-upd", "reason": "x"})
    assert not box.health_check()["healthy"]
    box.call("restart", {"service": "worker", "reason": "x"})
    assert box.health_check()["healthy"]


def test_secrets_redacted_and_rollback_keeps_rotation():
    box = _box("leaked_secret")
    assert "redacted" in box.get_config("api")["api_key"]
    box.call("rotate_secret", {"service": "api", "key": "api_key", "reason": "x"})
    new = box.system.services["api"].config["api_key"]
    box.call("rollback_config", {"service": "api", "reason": "x"})
    assert box.system.services["api"].config["api_key"] == new


def test_clear_disk_keeps_data():
    box = _box("disk_full")
    text, _ = box.call("clear_disk", {"service": "database", "reason": "x"})
    assert "nothing deleted" in text


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
