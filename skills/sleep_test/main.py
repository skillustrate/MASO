"""
Sleep test skill used for timeout verification.
"""

import time
from typing import Any, Dict


def execute_skill(task_context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    task_id = task_context.get("task_id", "task-sleep")
    sleep_seconds = parameters.get("sleep_seconds", 5)

    # Sleep in small increments
    start = time.time()
    while time.time() - start < sleep_seconds:
        time.sleep(0.2)

    return {
        "status": "SUCCESS",
        "task_id": task_id,
        "slept_seconds": sleep_seconds
    }
