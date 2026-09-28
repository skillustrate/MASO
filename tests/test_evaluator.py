import asyncio

import pytest

from masa.evals.eval_template import AuditorAssertionEngine


def test_evaluator_valid_skill_output():
    engine = AuditorAssertionEngine()
    payload = {
        "status": "SUCCESS",
        "task_id": "test_001",
        "data_table": "| col1 | col2 |\n| --- | --- |\n| a | b |",
        "metrics": {"rows_processed": 1, "error_count": 0},
        "audit_trail": ["step 1"],
        "errors": [],
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is True
    assert res["score_matrix"]["status_success"] == 1
    assert res["score_matrix"]["schema_conformity"] == 1
    assert res["score_matrix"]["data_integrity"] == 1
    assert len(res["failures_checklist"]) == 0


def test_evaluator_fails_on_missing_fields():
    engine = AuditorAssertionEngine()
    # Missing data_table and audit_trail
    payload = {
        "status": "SUCCESS",
        "task_id": "test_002",
        "metrics": {"rows_processed": 1, "error_count": 0},
        "errors": [],
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is False
    assert res["score_matrix"]["schema_conformity"] == 0
    assert any(
        "Missing mandatory schema fields" in f for f in res["failures_checklist"]
    )


def test_evaluator_fails_on_nonzero_error_count():
    engine = AuditorAssertionEngine()
    payload = {
        "status": "SUCCESS",
        "task_id": "test_003",
        "data_table": "| a |\n| --- |\n| 1 |",
        "metrics": {"rows_processed": 1, "error_count": 2},
        "audit_trail": [],
        "errors": [],
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is False
    assert any("error_count must be 0" in f for f in res["failures_checklist"])


def test_evaluator_master_result_holistic_check():
    engine = AuditorAssertionEngine()
    valid_task = {
        "task_id": "subtask-001",
        "result": {
            "status": "SUCCESS",
            "task_id": "subtask-001",
            "data_table": "| id |\n| --- |\n| 1 |",
            "metrics": {"rows_processed": 1, "error_count": 0},
            "audit_trail": ["ok"],
            "errors": [],
        },
    }
    failed_task = {
        "task_id": "subtask-002",
        "result": {
            "status": "FAILURE",
            "task_id": "subtask-002",
            "data_table": "",
            "metrics": {"rows_processed": 0, "error_count": 1},
            "audit_trail": ["failed"],
            "errors": ["Sample failure"],
        },
    }

    # All pass
    master_pass = {
        "run_id": "run_test_1",
        "objective": "Test",
        "sub_tasks": [valid_task],
    }
    res_pass = engine.verify_master_result(master_pass)
    assert res_pass["passed"] is True
    assert res_pass["verdict"] == "PASS"

    # One fails
    master_fail = {
        "run_id": "run_test_2",
        "objective": "Test",
        "sub_tasks": [valid_task, failed_task],
    }
    res_fail = engine.verify_master_result(master_fail)
    assert res_fail["passed"] is False
    assert res_fail["verdict"] == "FAIL"
    assert len(res_fail["failures_checklist"]) > 0
