import asyncio
import typing


async def run[T](coro: typing.Awaitable[T]) -> T:
    """
    Await coro with deferred cancellation.

    If the current task is cancelled while coro is running, the cancellation
    is held until coro completes, then re-raised.  Callers that await this
    task after cancelling it will block until the atomic block is done.
    """
    task = asyncio.current_task()
    assert task is not None
    fut: asyncio.Future[T] = asyncio.ensure_future(coro)
    deferred = 0

    while not fut.done():
        try:
            await asyncio.shield(fut)
        except asyncio.CancelledError:
            deferred += 1
            task.uncancel()

    if deferred:
        raise asyncio.CancelledError()

    return fut.result()  # re-raises any exception coro itself raised
