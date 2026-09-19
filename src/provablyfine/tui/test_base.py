import pytest
import textual.css.query
import textual.worker

from . import base


def _late_widget_lookup_failure() -> textual.worker.WorkerFailed:
    """What a worker reports when it looks up a widget that is already gone."""
    return textual.worker.WorkerFailed(textual.css.query.NoMatches("No nodes match 'DataTable'"))


def test_widget_lookup_failure_is_ignored_once_the_app_stopped_running() -> None:
    app = base.App()
    assert not app.is_running
    app._handle_exception(_late_widget_lookup_failure())  # pyright: ignore[reportPrivateUsage]
    assert app._exception is None  # pyright: ignore[reportPrivateUsage]


def test_bare_widget_lookup_failure_is_ignored_once_the_app_stopped_running() -> None:
    app = base.App()
    app._handle_exception(textual.css.query.NoMatches("No nodes match 'DataTable'"))  # pyright: ignore[reportPrivateUsage]
    assert app._exception is None  # pyright: ignore[reportPrivateUsage]


def test_other_errors_are_still_fatal_once_the_app_stopped_running() -> None:
    app = base.App()
    error = ValueError("a real bug")
    try:
        raise error
    except ValueError:
        # Textual reports errors from inside an `except` block, and its
        # fatal error rendering needs the active exception.
        app._handle_exception(error)  # pyright: ignore[reportPrivateUsage]
    assert app._exception is error  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_widget_lookup_failure_is_still_fatal_while_the_app_runs() -> None:
    """A missing widget in a live app is a real bug and must not be hidden."""
    app = base.App()
    with pytest.raises(textual.worker.WorkerFailed):
        async with app.run_test() as pilot:
            assert app.is_running
            app._handle_exception(_late_widget_lookup_failure())  # pyright: ignore[reportPrivateUsage]
            await pilot.pause()
