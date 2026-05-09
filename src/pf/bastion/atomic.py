import asyncio
import sys
import typing

T = typing.TypeVar("T")


async def run(coro: typing.Awaitable[T]) -> T:
    """
    Await coro with deferred cancellation.

    If the current task is cancelled while coro is running, the cancellation
    is held until coro completes, then re-raised.  Callers that await this
    task after cancelling it will block until the atomic block is done.
    """
    task = asyncio.current_task()
    fut: asyncio.Future[T] = asyncio.ensure_future(coro)
    deferred = 0

    while not fut.done():
        try:
            await asyncio.shield(fut)
        except asyncio.CancelledError:
            deferred += 1
            # 3.11+: tell the task we absorbed this cancellation ourselves;
            # without this the task's internal cancel counter stays incremented
            # and the next await after we return will immediately re-fire.
            if sys.version_info >= (3, 11):
                task.uncancel()  # type: ignore[union-attr]

    if deferred:
        raise asyncio.CancelledError()

    return fut.result()  # re-raises any exception coro itself raised
