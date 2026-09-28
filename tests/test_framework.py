import asyncio
import os
import tempfile

import pytest

from masa.framework import MultiAgentFramework


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create minimal skeleton
        os.makedirs(os.path.join(tmpdir, "masa", "core"))
        os.makedirs(os.path.join(tmpdir, "masa", "skills", "sample_skill"))
        os.makedirs(os.path.join(tmpdir, "masa", "evals"))
        os.makedirs(os.path.join(tmpdir, "mailboxes"))

        # Copy existing skill.py and eval_template.py into tempdir
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with open(
            os.path.join(root_dir, "masa", "skills", "sample_skill", "skill.py"), "r"
        ) as f:
            content = f.read()
        with open(
            os.path.join(tmpdir, "masa", "skills", "sample_skill", "skill.py"), "w"
        ) as f:
            f.write(content)

        with open(
            os.path.join(root_dir, "masa", "evals", "eval_template.py"), "r"
        ) as f:
            content = f.read()
        with open(os.path.join(tmpdir, "masa", "evals", "eval_template.py"), "w") as f:
            f.write(content)

        yield tmpdir


def test_environment_initialization(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    fw.initialize_environment()
    for d in ["masa/core", "masa/skills/sample_skill", "masa/evals", "mailboxes"]:
        assert os.path.exists(os.path.join(temp_workspace, d))


def test_skill_script_resolution(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    script_path = fw.skill_script("data_refinement")
    assert os.path.exists(script_path)
    assert script_path.endswith("skill.py")


def test_dynamic_decomposition_scaling(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    pool = ["gemini", "claude", "gpt-4o"]

    # 2 items -> 1 agent
    subtasks = asyncio.run(
        fw.decompose_objective("Test small", pool, {"raw_data": [{"a": 1}, {"a": 2}]})
    )
    assert len(subtasks) == 1
    assert subtasks[0]["task_id"] == "subtask-001"

    # 4 items -> 2 agents
    subtasks = asyncio.run(
        fw.decompose_objective(
            "Test medium", pool, {"raw_data": [{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}]}
        )
    )
    assert len(subtasks) == 2
    assert subtasks[0]["task_id"] == "subtask-001"
    assert subtasks[1]["task_id"] == "subtask-002"

    # Explicit scale
    subtasks = asyncio.run(
        fw.decompose_objective(
            "Test explicit",
            pool,
            {"raw_data": [{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}]},
            num_agents=4,
        )
    )
    assert len(subtasks) == 4


def test_pipeline_execution_e2e(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    res = asyncio.run(
        fw.run_pipeline(
            "Process sensor telemetry",
            super_override="test-super",
            signoff_override="test-signoff",
        )
    )
    assert res["passed"] is True
    assert res["verdict"] == "PASS"
    assert res["master_result"]["total_sub_tasks"] >= 1
    assert res["master_result"]["aggregated_metrics"]["total_rows_processed"] > 0
    assert res["master_result"]["aggregated_metrics"]["total_errors"] == 0


def test_collision_free_mailbox_isolation(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    res1 = asyncio.run(fw.run_pipeline("Run 1", num_agents=2))
    res2 = asyncio.run(fw.run_pipeline("Run 2", num_agents=2))

    assert res1["run_id"] != res2["run_id"]
    dir1 = os.path.join(temp_workspace, "mailboxes", res1["run_id"])
    dir2 = os.path.join(temp_workspace, "mailboxes", res2["run_id"])

    assert os.path.exists(os.path.join(dir1, "master_result.json"))
    assert os.path.exists(os.path.join(dir2, "master_result.json"))
    assert os.path.exists(os.path.join(dir1, "tasks", "subtask-001", "output.json"))
    assert os.path.exists(os.path.join(dir2, "tasks", "subtask-001", "output.json"))


def test_master_result_mixed_success_failure(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    tasks = [
        {
            "task_id": "subtask-001",
            "model": "model-a",
            "skill": "data_refinement",
            "description": "Task 1",
            "result": {
                "status": "SUCCESS",
                "task_id": "subtask-001",
                "data_table": "| col1 |\n| --- |\n| val1 |",
                "metrics": {"rows_processed": 5, "error_count": 0},
                "audit_trail": ["ok"],
                "errors": [],
            },
        },
        {
            "task_id": "subtask-002",
            "model": "model-b",
            "skill": "data_refinement",
            "description": "Task 2",
            "result": {
                "status": "FAILURE",
                "task_id": "subtask-002",
                "data_table": "",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "audit_trail": ["failed"],
                "errors": ["TimeoutExpired"],
            },
        },
    ]

    master = fw.synthesize_master_result("run_mixed", "Test mixed execution", tasks)
    assert master["total_sub_tasks"] == 2
    assert master["aggregated_metrics"]["total_rows_processed"] == 5
    assert master["aggregated_metrics"]["total_errors"] >= 1
    assert "TimeoutExpired" in master["aggregated_metrics"]["unique_errors"]

    # Verify auditor flags the failure
    from masa.evals.eval_template import AuditorAssertionEngine

    engine = AuditorAssertionEngine()
    eval_res = engine.verify_master_result(master)
    assert eval_res["passed"] is False
    assert eval_res["verdict"] == "FAIL"


def test_execute_engage_agents_graceful_recovery(temp_workspace):
    fw = MultiAgentFramework(temp_workspace)
    run_dir = os.path.join(temp_workspace, "mailboxes", "run_recovery_test")
    os.makedirs(run_dir, exist_ok=True)

    attempt_count = 0
    original_dispatch = fw.dispatch_skill

    async def flaking_dispatch(*args, **kwargs):
        nonlocal attempt_count
        attempt_count += 1
        # Flake on first attempt to trigger fallback
        if attempt_count == 1:
            raise RuntimeError("Transient parallel worker glitch")
        return await original_dispatch(*args, **kwargs)

    fw.dispatch_skill = flaking_dispatch

    tasks = [
        {
            "task_id": "subtask-001",
            "skill": "data_refinement",
            "model": "model-test",
            "description": "Transient test",
            "input_data": {"raw_data": [{"id": 1, "sensor": "temp", "val": 22.0}]},
        }
    ]

    results = asyncio.run(fw.execute_engage_agents(tasks, run_dir))
    assert len(results) == 1
    # Check that sequential fallback recovered the task
    assert results[0]["result"]["status"] == "SUCCESS"
    assert results[0]["result"]["metrics"]["rows_processed"] == 1


def test_high_concurrency_mailbox_stress(temp_workspace):
    import json

    fw = MultiAgentFramework(temp_workspace)
    run_dir = os.path.join(temp_workspace, "mailboxes", "run_stress_100")
    os.makedirs(run_dir, exist_ok=True)

    # Generate 100 concurrent tasks
    num_tasks = 100
    tasks = [
        {
            "task_id": f"stress_task_{i:03d}",
            "skill": "data_refinement",
            "model": f"model_{(i % 3)}",
            "description": f"Stress worker {i}",
            "input_data": {"raw_data": [{"id": i, "val": i * 1.5}]},
        }
        for i in range(num_tasks)
    ]

    async def fast_mock_dispatch(
        skill_identifier, input_data, model_name, task_id="default"
    ):
        return {
            "status": "SUCCESS",
            "task_id": task_id,
            "data_table": f"| id | val |\n|---|---|\n| {input_data['raw_data'][0]['id']} | {input_data['raw_data'][0]['val']} |",
            "metrics": {"rows_processed": 1, "error_count": 0},
            "audit_trail": [f"Processed {task_id}"],
            "errors": [],
        }

    fw.dispatch_skill = fast_mock_dispatch
    results = asyncio.run(fw.execute_engage_agents(tasks, run_dir))
    assert len(results) == num_tasks

    # Verify every single task wrote atomic output without collisions
    for i in range(num_tasks):
        task_id = f"stress_task_{i:03d}"
        task_out = os.path.join(run_dir, "tasks", task_id, "output.json")
        assert os.path.exists(task_out), f"Missing output file for {task_id}"
        with open(task_out, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["task_id"] == task_id
            assert data["status"] == "SUCCESS"

    # Synthesize master result
    master = fw.synthesize_master_result(
        "run_stress_100", "Stress test 100 tasks", results
    )
    assert master["aggregated_metrics"]["total_rows_processed"] == num_tasks
    assert master["aggregated_metrics"]["total_errors"] == 0


def test_network_partition_timeout_handling():
    import socket
    import urllib.error
    import urllib.request

    from masa.framework import SubscriptionManager

    def mock_urlopen(*args, **kwargs):
        raise urllib.error.URLError(socket.timeout("Connection timed out"))

    orig_urlopen = urllib.request.urlopen
    urllib.request.urlopen = mock_urlopen
    try:
        models = SubscriptionManager.query_local_models(
            host="192.168.1.99", port=9999, timeout=0.1
        )
        assert models == []
    finally:
        urllib.request.urlopen = orig_urlopen
