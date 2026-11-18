from .endpoints import ssh_gateway


def test_acquire_stops_at_the_limit() -> None:
    counter = ssh_gateway.SessionCounter()
    key = ("tenant", 1)

    assert counter.acquire(key, 2)
    assert counter.acquire(key, 2)
    assert not counter.acquire(key, 2)


def test_release_frees_a_slot() -> None:
    counter = ssh_gateway.SessionCounter()
    key = ("tenant", 1)
    counter.acquire(key, 1)

    counter.release(key)

    assert counter.acquire(key, 1)


def test_limits_are_per_tenant_and_identity() -> None:
    counter = ssh_gateway.SessionCounter()

    assert counter.acquire(("a", 1), 1)
    assert counter.acquire(("a", 2), 1)
    assert counter.acquire(("b", 1), 1)
