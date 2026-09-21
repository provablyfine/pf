"""Concurrent requests against one server.

Each request is one transaction. Independent requests must all succeed,
and a race for the same thing must have exactly one winner and a clean answer for the others.
"""

import collections
import collections.abc
import concurrent.futures
import os
import tempfile

import provablyfine_client as pfc
import requests

import provablyfine.client
import tests.test_identity_self_token
import tests.tui_support

CONCURRENCY = 8
ROOT = "00000000-0000-0000-0000-000000000001"


def _run_all(calls: list[collections.abc.Callable[[], object]]) -> collections.Counter[str]:
    """Run the calls at the same time and count the outcomes."""
    outcomes: collections.Counter[str] = collections.Counter()
    with concurrent.futures.ThreadPoolExecutor(len(calls)) as pool:
        for future in [pool.submit(call) for call in calls]:
            try:
                outcomes[str(future.result())] += 1
            except pfc.exceptions.UI as e:
                outcomes[f"error: {e}"] += 1
    return outcomes


def _session_factory(api, tmpdir: str) -> collections.abc.Callable[[], pfc.SessionClient]:
    tests.tui_support._setup(api, tmpdir)
    config = provablyfine.client.Config.load(os.path.join(tmpdir, "config.json"))
    # A session is not thread safe: every call gets its own.
    return lambda: provablyfine.client.Factory(config, timeout=30).session()


def test_initialize_has_one_winner(api) -> None:
    url = f"http://127.0.0.1:{api.port}/pf/t/{ROOT}/initialize"
    outcomes = _run_all([lambda: requests.post(url, timeout=30).status_code for _ in range(CONCURRENCY)])
    assert outcomes == {"200": 1, "204": CONCURRENCY - 1}


def test_independent_creates_all_succeed(api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session = _session_factory(api, tmpdir)

        def creates(kind: str) -> list[collections.abc.Callable[[], object]]:
            def one(i: int) -> collections.abc.Callable[[], object]:
                def call() -> str:
                    sc = session()
                    match kind:
                        case "tag":
                            sc.create_tag(f"t{i}", "v")
                        case "role":
                            sc.create_role(f"r{i}", "")
                        case "boundary":
                            sc.create_boundary(f"b{i}", "")
                        case _:
                            sc.create_auth_http_sig(f"a{i}", "cli", "")
                    return "ok"

                return call

            return [one(i) for i in range(CONCURRENCY)]

        for kind in ("tag", "role", "boundary", "auth"):
            assert _run_all(creates(kind)) == {"ok": CONCURRENCY}, kind


def test_same_name_create_has_one_winner(api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session = _session_factory(api, tmpdir)

        def create() -> str:
            session().create_tag("same", "v")
            return "ok"

        outcomes = _run_all([create for _ in range(CONCURRENCY)])
        assert outcomes["ok"] == 1
        assert sum(outcomes.values()) == CONCURRENCY
        assert not [k for k in outcomes if "Internal Server Error" in k or "busy" in k], outcomes


def test_concurrent_tenant_creates_all_succeed(api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session = _session_factory(api, tmpdir)

        def create(i: int) -> collections.abc.Callable[[], object]:
            def call() -> str:
                session().create_tenant(f"acme{i}", f"Acme {i}")
                return "ok"

            return call

        assert _run_all([create(i) for i in range(CONCURRENCY)]) == {"ok": CONCURRENCY}


def test_reads_and_writes_at_the_same_time(api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session = _session_factory(api, tmpdir)

        def write(i: int) -> collections.abc.Callable[[], object]:
            def call() -> str:
                session().create_tag(f"w{i}", "v")
                return "ok"

            return call

        def read() -> str:
            session().list_tags()
            return "ok"

        # Every request holds one connection per database until it ends.
        # The pool has 15, so stay below that.
        calls: list[collections.abc.Callable[[], object]] = []
        for i in range(6):
            calls.append(write(i))
            calls.append(read)
        assert _run_all(calls) == {"ok": 12}


def test_first_tokens_create_one_signing_key(api, tmp_path) -> None:
    """The first token of a tenant creates its OIDC signing key, from a GET request."""
    factory, identity_name, _role_id = tests.test_identity_self_token._setup_session(api.port, tmp_path)

    def token() -> str:
        factory.session().get_self_token("bastion", hostname=identity_name, purpose="register")
        return "ok"

    assert _run_all([token for _ in range(CONCURRENCY)]) == {"ok": CONCURRENCY}
