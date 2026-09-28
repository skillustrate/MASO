import asyncio
import os
import sys

import pytest

# Add skills/sample_skill to path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(root_dir, "masa", "skills", "sample_skill"))

from skill import execute_skill


def test_skill_success_execution():
    context = {"task_id": "task_100"}
    inputs = {
        "raw_data": [
            {"id": 1, "sensor": "temp", "val": 25.4},
            {"id": 2, "sensor": "humidity", "val": 60},
        ]
    }
    result = execute_skill(context, inputs)
    assert result["status"] == "SUCCESS"
    assert result["task_id"] == "task_100"
    assert "| id | sensor | val |" in result["data_table"]
    assert "| 1 | temp | 25.4 |" in result["data_table"]
    assert result["metrics"]["rows_processed"] == 2
    assert result["metrics"]["error_count"] == 0
    assert len(result["audit_trail"]) > 0
    assert len(result["errors"]) == 0


def test_skill_handles_missing_keys_with_na():
    context = {"task_id": "task_101"}
    inputs = {"raw_data": [{"id": 1, "col_a": "val_a"}, {"id": 2, "col_b": "val_b"}]}
    result = execute_skill(context, inputs)
    assert result["status"] == "SUCCESS"
    assert "N/A" in result["data_table"]
    assert result["metrics"]["rows_processed"] == 2


def test_skill_missing_raw_data_raises_failure():
    context = {"task_id": "task_fail"}
    inputs = {}
    result = execute_skill(context, inputs)
    assert result["status"] == "FAILURE"
    assert result["metrics"]["error_count"] == 1
    assert any("CRITICAL_VALIDATION_FAILURE" in e for e in result["errors"])


def test_skill_invalid_raw_data_type():
    context = {"task_id": "task_fail2"}
    inputs = {"raw_data": "not a list"}
    result = execute_skill(context, inputs)
    assert result["status"] == "FAILURE"
    assert any("CRITICAL_VALIDATION_FAILURE" in e for e in result["errors"])
