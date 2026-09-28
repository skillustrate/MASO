"""
Tests for MASO Phase 2 (Sprint 2: Orchestrator Integration).
Tests end-to-end Super-Engage-Signoff workflow inside rootless Podman containers,
sensitive data pre-scrubbing, auditor validation, and local fallback controls.
"""

import asyncio
import json
import os
import shutil
import tempfile
import pytest

from masa.crypto import SensitiveDataFilter
from masa.orchestrator import MultiAgentFramework
from masa.sandbox import AuditLogger, SandboxConfig


@pytest.fixture
def test_workspace():
    """Create a temporary workspace initialized with MASO structure."""
    d = tempfile.mkdtemp(prefix="maso_orch_test_")
    fw = MultiAgentFramework(root_dir=d)
    fw.initialize_environment()
    yield d, fw
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def podman_available():
    if shutil.which("podman") is None:
        pytest.skip("Podman is not installed on this host")


# ----------------------------------------------------------------------
# 1. End-to-End Super-Engage-Signoff Pipeline inside Podman
# ----------------------------------------------------------------------

def test_orchestrator_pipeline_e2e_podman(podman_available, test_workspace):
    """
    Verify complete pipeline execution:
    Super Agent decomposition -> Podman container execution -> Signoff Auditor verification.
    """
    workspace_dir, fw = test_workspace

    input_payload = {
        "raw_data": [
            {"sensor_id": "SN-01", "voltage": 12.4, "temp": 42.1},
            {"sensor_id": "SN-02", "voltage": 11.9, "temp": 44.5},
            {"sensor_id": "SN-03", "voltage": 12.1, "temp": 39.8},
            {"sensor_id": "SN-04", "voltage": 12.0, "temp": 41.2},
        ]
    }
    input_file = os.path.join(workspace_dir, "test_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_payload, f)

    res = asyncio.run(
        fw.run_pipeline(
            user_objective="Partition and refine sensor telemetry data across pods",
            input_file=input_file,
            num_agents=2,
            sandbox_mode="podman",
            sandbox_memory="256m",
            sandbox_timeout=30,
            purge_ephemeral=False,
        )
    )

    assert res["passed"] is True, f"Pipeline failed: {res.get('audit_report')}"
    assert res["verdict"] == "PASS"
    assert res["master_result"]["total_sub_tasks"] == 2
    assert res["master_result"]["aggregated_metrics"]["total_rows_processed"] == 4
    assert res["master_result"]["aggregated_metrics"]["total_errors"] == 0

    # Verify audit report was generated and passed
    assert res["audit_report"]["passed"] is True
    assert res["audit_report"]["verdict"] == "PASS"

    # Verify execution audit log was populated by the Podman driver
    audit_logger = fw.sandbox_manager.audit_logger
    is_valid, errors = audit_logger.verify_integrity()
    assert is_valid is True, f"Audit log broken: {errors}"
    recent = audit_logger.get_recent_entries(5)
    assert len(recent) >= 2


# ----------------------------------------------------------------------
# 2. Sensitive Data Pre-Scrubbing (Task 2.2)
# ----------------------------------------------------------------------

def test_dispatch_skill_pre_scrubs_secrets(podman_available, test_workspace):
    """
    Verify that dispatch_skill scrubs secrets before writing input.json into the container mailbox.
    """
    workspace_dir, fw = test_workspace

    leaked_aws_key = "AKIAIOSFODNN7EXAMPLE"
    input_data = {
        "raw_data": [
            {"service": "auth", "api_key": leaked_aws_key, "action": "login"}
        ]
    }

    task_dir = os.path.join(workspace_dir, "mailboxes", "test_scrub_task")
    os.makedirs(task_dir, exist_ok=True)

    result = asyncio.run(
        fw.dispatch_skill(
            skill_identifier="data_refinement",
            input_data=input_data,
            model_name="gemini",
            task_id="task-scrub-01",
            task_dir=task_dir,
            run_id="run-scrub",
        )
    )

    input_file = os.path.join(task_dir, "input.json")
    with open(input_file, "r", encoding="utf-8") as f:
        staged_input = json.load(f)

    # AWS key must be redacted in the staged mailbox input.json
    staged_str = json.dumps(staged_input)
    assert leaked_aws_key not in staged_str
    assert "[REDACTED" in staged_str
    assert result.get("status") == "SUCCESS"


# ----------------------------------------------------------------------
# 3. Ephemeral Task Directory Purge (Task 2.4)
# ----------------------------------------------------------------------

def test_orchestrator_purge_ephemeral(podman_available, test_workspace):
    """Verify that purge_ephemeral=True cleans up task directories after signoff."""
    workspace_dir, fw = test_workspace

    input_payload = {"raw_data": [{"val": 1}, {"val": 2}]}
    input_file = os.path.join(workspace_dir, "purge_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_payload, f)

    res = asyncio.run(
        fw.run_pipeline(
            user_objective="Process data with ephemeral cleanup",
            input_file=input_file,
            num_agents=1,
            sandbox_mode="podman",
            purge_ephemeral=True,
        )
    )

    run_dir = os.path.join(workspace_dir, "mailboxes", res["run_id"])
    tasks_dir = os.path.join(run_dir, "tasks")

    # Tasks directory should be purged
    assert not os.path.exists(tasks_dir)
    # Master result and audit report must be preserved
    assert os.path.exists(os.path.join(run_dir, "master_result.json"))
    assert os.path.exists(os.path.join(run_dir, "audit_report.json"))


# ----------------------------------------------------------------------
# 4. Local Fallback Refusal & Risk Acknowledgment (Task 2.5)
# ----------------------------------------------------------------------

def test_local_fallback_requires_acknowledgment(test_workspace):
    """Verify local fallback refuses execution without --i-understand-the-risks."""
    workspace_dir, fw = test_workspace

    with pytest.raises(RuntimeError) as exc_info:
        asyncio.run(
            fw.run_pipeline(
                user_objective="Attempt local run without ack",
                sandbox_mode="local",
                i_understand_the_risks=False,
            )
        )
    assert "DEGRADED LOCAL EXECUTION REFUSED" in str(exc_info.value)


def test_local_fallback_with_acknowledgment(test_workspace):
    """Verify local fallback runs when explicit acknowledgement is provided."""
    workspace_dir, fw = test_workspace

    input_payload = {"raw_data": [{"item": "Alpha"}, {"item": "Beta"}]}
    input_file = os.path.join(workspace_dir, "local_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_payload, f)

    res = asyncio.run(
        fw.run_pipeline(
            user_objective="Run local task with risk acknowledgment",
            input_file=input_file,
            num_agents=1,
            sandbox_mode="local",
            i_understand_the_risks=True,
        )
    )

    assert res["passed"] is True
    assert res["verdict"] == "PASS"

    # Verify audit log records degraded_isolation=True
    recent = fw.sandbox_manager.audit_logger.get_recent_entries(5)
    assert len(recent) >= 1
    assert recent[-1]["degraded_isolation"] is True
    assert recent[-1]["image_digest"] == "local"
