"""Task Broker and Event Management for MASA."""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger("MASABroker")


class TaskBroker:
    """
    Abstracts task distribution for horizontal scaling.

    Supports multiple backend implementations:
    - Local asyncio queues (default, no dependencies)
    - Redis-backed distributed queues (requires redis library)

    Thread-safe and async-friendly for use with MultiAgentFramework.

    Attributes:
        backend_url: Optional Redis connection string (format: redis://user:pass@host:port/db)
        _local_queue: Internal asyncio.Queue for local task distribution
        _local_results: Internal queue for collecting local results
        _redis: Optional Redis client for distributed deployments
    """

    def __init__(self, backend_url: Optional[str] = None):
        """
        Initialize the TaskBroker.

        Args:
            backend_url: Optional Redis URL for distributed task distribution.
                        If provided and starts with 'redis://', enables Redis backend.
                        Otherwise uses local asyncio queues (faster, no external deps).

        Example:
            # Local deployment (default)
            broker = TaskBroker()

            # Distributed deployment with Redis
            broker = TaskBroker(backend_url="redis://user:pass@localhost:6379/0")
        """
        self.backend_url = backend_url
        self._local_queue: asyncio.Queue = None  # type: ignore
        self._local_results: asyncio.Queue = None  # type: ignore
        self._redis: Optional[Any] = None

        if backend_url and backend_url.startswith("redis://"):
            try:
                import redis.asyncio as redis

                self._redis = redis.from_url(backend_url)
                logger.info(
                    f"TaskBroker initialized with Redis backend at {backend_url}"
                )
            except ImportError:
                logger.warning(
                    "Redis backend requested but redis library not installed. "
                    "Falling back to local asyncio queue."
                )
                self._redis = None

    async def enqueue_task(self, task: dict) -> None:
        """
        Add a task to the broker's task queue.

        Args:
            task: Dictionary containing task metadata and payload.
                  Expected keys: "task_id", "skill", "model", "description", "input_data"

        Example:
            >>> await broker.enqueue_task({
            ...     "task_id": "subtask-001",
            ...     "skill": "data_refinement",
            ...     "model": "claude-3.5-sonnet",
            ...     "input_data": {"raw_data": [...]},
            ... })
        """
        if self._redis:
            # Distributed: Push to Redis queue
            await self._redis.lpush("masa:task_queue", json.dumps(task))
            logger.debug(f"Enqueued task {task['task_id']} to Redis queue")
        else:
            # Local: Add to asyncio Queue (blocking for simplicity)
            await self._local_queue.put(task)
            logger.debug(f"Enqueued task {task['task_id']} to local queue")

    async def dequeue_task(self) -> Optional[dict]:
        """
        Retrieve and remove the next task from the queue.

        Returns:
            dict or None: Task dictionary if available, None if queue is empty (blocking).

        Raises:
            asyncio.QueueEmpty: If timeout expires and no tasks are available.

        Example:
            >>> while True:
            ...     task = await broker.dequeue_task()
            ...     if task is None:
            ...         break
            ...     # Process task
        """
        if self._redis:
            # Distributed: BRPOP with 0 timeout (non-blocking)
            result = await self._redis.brpop("masa:task_queue", timeout=0)
            return json.loads(result[1]) if result else None

        else:
            # Local: Get from asyncio Queue (blocks until task available)
            return await self._local_queue.get()

    async def push_result(self, result: dict, task_id: str) -> None:
        """
        Store a completed task result.

        Args:
            result: Task execution result dictionary.
                    Expected keys: "status", "data_table", "metrics", "audit_trail", "errors"
            task_id: The ID of the task this result corresponds to.

        Example:
            >>> await broker.push_result({
            ...     "status": "SUCCESS",
            ...     "task_id": "subtask-001",
            ...     "data_table": "| Column | Value |\n| --- | --- |",
            ... }, "subtask-001")
        """
        if self._redis:
            # Distributed: Store in Redis list by task ID
            await self._redis.lpush(f"masa:results:{task_id}", json.dumps(result))
            logger.debug(f"Stored result for task {task_id} in Redis")
        else:
            # Local: Add to results queue (non-blocking put)
            self._local_results.put_nowait(result)
            logger.debug(f"Stored result for task {task_id} in local queue")

    @property
    def is_distributed(self) -> bool:
        """Check if this broker is using distributed Redis backend."""
        return self._redis is not None

    async def close(self) -> None:
        """Close the broker and release resources."""
        if self._redis:
            await self._redis.close()
            logger.info("TaskBroker Redis connection closed")
