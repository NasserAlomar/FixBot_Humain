from scenarios import (DEV_SCENARIOS, FAULTS, HELD_OUT_SCENARIOS, RED_HERRINGS,
                       add_red_herrings, make_scenario)
from simulator import System, health_check

ALL = DEV_SCENARIOS + HELD_OUT_SCENARIOS


def test_sizes_and_disjoint():
    assert len(DEV_SCENARIOS) == 10
    assert len(HELD_OUT_SCENARIOS) == 5
    names = [s.name for s in ALL]
    assert len(set(names)) == len(names)
    assert not {s.seed for s in DEV_SCENARIOS} & {s.seed for s in HELD_OUT_SCENARIOS}
    assert all(any(len(s.faults) == 2 for s in group)
               for group in (DEV_SCENARIOS, HELD_OUT_SCENARIOS))


def test_every_fault_is_covered_once():
    covered = [f for s in ALL for f in s.faults if len(s.faults) == 1]
    assert set(covered) == set(FAULTS)


def test_each_fault_alone_fails_health():
    for name in FAULTS:
        health = health_check(make_scenario(name, name, 1).build())
        assert not health["healthy"], name


def test_each_scenario_fails_health():
    for s in ALL:
        system = s.build()
        health = health_check(system)
        print(f"{s.name} [{s.type}]: {health['overall']}")
        for svc, h in health["services"].items():
            if h["issues"]:
                print(f"    {svc}: {h['issues']}")
        assert not health["healthy"], s.name
        assert s.type in ("reliability", "security")
        assert s.root_causes and len(s.root_causes) == len(s.expected_fixes) == len(s.faults)


def test_fixed_services_failing_per_fault():
    # every fault's own service must be flagged, so combos are really double faults
    for s in ALL:
        health = health_check(s.build())
        for f in s.faults:
            assert not health["services"][FAULTS[f].expected_fix["service"]]["status"] == "healthy", (s.name, f)


def test_deterministic():
    for s in ALL:
        assert s.build().snapshot() == s.build().snapshot(), s.name


def test_red_herrings_are_benign():
    system = System(seed=3)
    add_red_herrings(system, len(RED_HERRINGS))
    assert health_check(system)["healthy"]
    assert sum("WARN" in l or "ERROR" in l for svc in system.services.values() for l in svc.logs) >= len(RED_HERRINGS)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok")
