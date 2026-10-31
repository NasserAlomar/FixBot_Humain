from simulator import System, health_check


def test_healthy_system():
    health = health_check(System(seed=42))
    print(f"overall: {health['overall']}")
    for name, svc in health["services"].items():
        print(f"  {name}: {svc['status']} {svc['issues']}")
    assert health["healthy"]


def test_deterministic():
    a, b = System(seed=7), System(seed=7)
    a.advance(5)
    b.advance(5)
    assert a.snapshot() == b.snapshot()
    assert System(seed=7).snapshot() != System(seed=8).snapshot()


if __name__ == "__main__":
    test_healthy_system()
    test_deterministic()
    print("ok")
