"""A request is only answered after its transaction has committed."""

import os
import sqlite3
import tempfile
import threading
import time

import provablyfine.client
import tests.tui_support

from . import utils


def test_response_waits_for_the_commit(api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tests.tui_support._setup(api, tmpdir)
        config = provablyfine.client.Config.load(os.path.join(tmpdir, "config.json"))
        session = provablyfine.client.Factory(config, timeout=30).session()

        # An open read transaction from outside makes the server's COMMIT wait.
        reader = sqlite3.connect(utils.root_tenant_db_path(api), isolation_level=None)
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM tag").fetchall()

        errors: list[BaseException] = []

        def create() -> None:
            try:
                session.create_tag("committed", "yes")
            except BaseException as e:
                errors.append(e)

        request = threading.Thread(target=create)
        request.start()
        try:
            time.sleep(1.5)
            assert request.is_alive(), "the response was sent before the transaction committed"
        finally:
            reader.execute("ROLLBACK")
            request.join(30)
        assert not request.is_alive()
        assert not errors
