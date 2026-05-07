"""Tests for bastion/atomic deferred-cancellation utility."""

from __future__ import annotations

import asyncio

import pytest

from . import atomic


@pytest.mark.anyio
async def test_run_normal_completion() -> None:
    """A quick coroutine returns its value unchanged."""

    async def quick() -> str:
        return "ok"

    result = await atomic.run(quick())
    assert result == "ok"


@pytest.mark.anyio
async def test_run_reraises_coro_exception() -> None:
    """If the coroutine raises, the exception propagates through atomic.run."""

    async def failing() -> None:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await atomic.run(failing())


@pytest.mark.anyio
async def test_run_defers_cancellation() -> None:
    """Cancellation is absorbed until the inner coroutine completes."""
    completed = False

    async def slow() -> str:
        nonlocal completed
        await asyncio.sleep(0.1)
        completed = True
        return "done"

    runner = asyncio.create_task(atomic.run(slow()))
    await asyncio.sleep(0)  # let runner start
    runner.cancel()

    with pytest.raises(asyncio.CancelledError):
        await runner

    # Inner coro must have finished before CancelledError was re-raised.
    assert completed is True


@pytest.mark.anyio
async def test_run_caller_blocks_until_completion() -> None:
    """The cancelling task cannot proceed until the atomic block finishes."""
    timeline: list[str] = []

    async def slow() -> None:
        await asyncio.sleep(0.05)
        timeline.append("coro_done")

    runner = asyncio.create_task(atomic.run(slow()))
    await asyncio.sleep(0)  # let runner start
    runner.cancel()

    # Immediately schedule work after awaiting the runner — if cancellation
    # were not deferred, this would run before the coro finishes.
    waiter = asyncio.create_task(asyncio.sleep(0))

    try:
        await runner
    except asyncio.CancelledError:
        pass

    await waiter
    timeline.append("caller_proceeded")

    assert timeline == ["coro_done", "caller_proceeded"]


@pytest.mark.anyio
async def test_run_already_done_coro() -> None:
    """A coroutine that completes instantly returns without delay."""

    async def instant() -> int:
        return 42

    # Wrap in ensure_future so it's already scheduled and done before we call run.
    fut = asyncio.ensure_future(instant())
    await asyncio.sleep(0)  # let it run
    assert fut.done()

    result = await atomic.run(fut)
    assert result == 42
