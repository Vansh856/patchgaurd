import asyncio
import logging
from typing import Callable, Awaitable, Optional
from patchguard.domain.models import AttackEvents

logger = logging.getLogger("patchguard.queue")


class AsyncIncidentQueue:


    def __init__(self,maxsize: int = 1000):
        """
        1. Initializes the AsyncIncidentQueue with a specified maximum size.
        2. Creates an asyncio.Queue to hold AttackEvents instances.
        """
        self._queue:asyncio.Queue[AttackEvents] = asyncio.Queue(maxsize=maxsize)
        self._worker_task: Optional[asyncio.Task] = None
        self._handler: Optional[Callable[[AttackEvents], Awaitable[None]]] = None


    def enqueue(self, event: AttackEvents)-> bool:

        try:
            self._queue.put_nowait(event)
            logger.info(f"Enqueued attack event: {event.id} for async remediation.")
            return True
        except asyncio.QueueFull:
            logger.error(f"Incident queue is full. Dropping attack event offload: {event.id}.")
            return False


    def start_worker(self, handler: Callable[[AttackEvents], Awaitable[None]]) -> None:

        """
        1. Sets the handler function to be used for processing AttackEvents instances.
        2. Starts the background worker task if it is not already running.
        """
        self._handler = handler
        if self._worker_task is None or self._worker_task.done(): # if the worker task is not running, start it
            self._worker_task = asyncio.create_task(self._worker_loop())
            logger.info("Background incident remediation worker task started.")


    async def _worker_loop(self) -> None:
        """
        1. Continuously processes AttackEvents instances from the queue.
        2. Calls the provided handler function for each event.
        """

        while True:
            try:
                event = await self._queue.get()
                if self._handler:
                    try:
                        await self._handler(event)
                    except Exception as e:
                        logger.exception(f"Error processing attack event in Background worker: {e}")

                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Unexpected error in Background worker loop: {e}")

    async def stop(self)-> None:
        """
        1. Stops the background worker task if it is running.
        2. Cancels the task and waits for it to finish."""
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                logger.info("Background incident remediation worker  stopped.")