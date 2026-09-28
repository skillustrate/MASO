"""
Comprehensive tests for MASO Sandboxing Phase 1 / Sprint 1 (v1.1.0).
Tests hardened rootless Podman execution, timeout kill, audit hash chains, and containment.
"""

import json
import os
import shutil
import tempfile
import pytest

from masa.sandbox.audit import AuditLogger, GENESIS_HASH
from masa.sandbox.base import SandboxConfig
from masa.sandbox.manager import SandboxManager
from masa.sandbox.podman import PodmanSandboxDriver


@pytest.fixture
def temp_task_dir():
    """Create an ephemeral task directory with 0777 permissions for container mapping."""
    d = tempfile.mkdtemp(prefix="maso_test_task_")
    os.chmod(d, 0o777)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def temp_audit_log():
    """Create an isolated temporary audit log path."""
    d = tempfile.mkdtemp(prefix="maso_test_audit_")
    log_path = os.path.join(d, "test_execution.log")
    yield log_path
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def podman_available():
    """Skip test if Podman is not installed on the system."""
    if shutil.which("podman") is None:
        pytest.skip("Podman is not installed on this host")


# ----------------------------------------------------------------------
# 1. End-to-End Skill Execution in Rootless Podman
# ----------------------------------------------------------------------

def test_podman_e2e_data_refinement(podman_available, temp_task_dir, temp_audit_log):
    """Verify that data_refinement skill runs end-to-end inside Podman container."""
    input_data = {
        "task_id": "task-test-01",
        "run_id": "run-test-e2e",
        "skill_name": "data_refinement",
        "parameters": {
            "raw_data": [
                {"name": "Alice", "role": "Engineer", "score": 95},
                {"name": "Bob", "role": "Architect", "score": 98}
            ]
        }
    }
    input_file = os.path.join(temp_task_dir, "input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_data, f)

    audit_logger = AuditLogger(log_path=temp_audit_log)
    driver = PodmanSandboxDriver(audit_logger=audit_logger)

    config = SandboxConfig(
        runtime="podman",
        memory_limit="256m",
        timeout_seconds=30,
        image_ref="maso-skill-worker:v1.1"
    )

    res = driver.run(temp_task_dir, config)

    assert res.exit_code == 0, f"Skill execution failed: {res.stderr}"
    assert res.timed_out is False
    assert res.output_data is not None
    assert res.output_data.get("status") == "SUCCESS"
    assert "data_table" in res.output_data.get("result", {})
    assert "Alice" in res.output_data["result"]["data_table"]

    # Verify output.json on disk
    output_path = os.path.join(temp_task_dir, "output.json")
    assert os.path.exists(output_path)

    # Verify audit record generated
    valid, errors = audit_logger.verify_integrity()
    assert valid, f"Audit integrity broken: {errors}"
    entries = audit_logger.get_recent_entries(5)
    assert len(entries) == 1
    assert entries[0]["task_id"] == "task-test-01"
    assert entries[0]["skill_name"] == "data_refinement"
    assert entries[0]["exit_code"] == 0


def test_podman_e2e_ast_scanner(podman_available, temp_task_dir, temp_audit_log):
    """Verify that ast_scanner skill runs and identifies dangerous imports."""
    code_sample = (
        "import os\n"
        "import math\n"
        "def compute():\n"
        "    return math.sqrt(16)\n"
    )
    input_data = {
        "task_id": "task-test-ast",
        "run_id": "run-test-e2e",
        "skill_name": "ast_scanner",
        "parameters": {"code": code_sample}
    }
    with open(os.path.join(temp_task_dir, "input.json"), "w", encoding="utf-8") as f:
        json.dump(input_data, f)

    audit_logger = AuditLogger(log_path=temp_audit_log)
    driver = PodmanSandboxDriver(audit_logger=audit_logger)

    config = SandboxConfig(
        runtime="podman",
        memory_limit="256m",
        timeout_seconds=30,
        image_ref="maso-skill-worker:v1.1"
    )

    res = driver.run(temp_task_dir, config)
    assert res.exit_code == 0
    assert res.output_data["result"]["has_dangerous_imports"] is True
    assert "os" in res.output_data["result"]["dangerous_imports"]
    assert "math" in res.output_data["result"]["imports"]


# ----------------------------------------------------------------------
# 2. Wall-Clock Timeout Enforcement
# ----------------------------------------------------------------------

def test_podman_timeout_kill(podman_available, temp_task_dir, temp_audit_log):
    """Verify that an overlong execution is killed by the driver on timeout."""
    input_data = {
        "task_id": "task-test-timeout",
        "run_id": "run-test-timeout",
        "skill_name": "sleep_test",
        "parameters": {"sleep_seconds": 15}
    }
    with open(os.path.join(temp_task_dir, "input.json"), "w", encoding="utf-8") as f:
        json.dump(input_data, f)

    audit_logger = AuditLogger(log_path=temp_audit_log)
    driver = PodmanSandboxDriver(audit_logger=audit_logger)

    # Set hard timeout to 2 seconds
    config = SandboxConfig(
        runtime="podman",
        memory_limit="256m",
        timeout_seconds=2,
        image_ref="maso-skill-worker:v1.1"
    )

    res = driver.run(temp_task_dir, config)

    assert res.timed_out is True
    assert res.exit_code == 124

    # Verify audit log captures timeout event
    entries = audit_logger.get_recent_entries(5)
    assert len(entries) == 1
    assert entries[0]["timed_out"] is True
    assert entries[0]["exit_code"] == 124


# ----------------------------------------------------------------------
# 3. In-Image Unknown Skill Rejection (NEW §5.5)
# ----------------------------------------------------------------------

def test_podman_rejects_unknown_skill(podman_available, temp_task_dir, temp_audit_log):
    """Verify that attempting to execute an unregistered skill fails closed."""
    input_data = {
        "task_id": "task-unknown-skill",
        "skill_name": "malicious_unregistered_skill",
        "parameters": {}
    }
    with open(os.path.join(temp_task_dir, "input.json"), "w", encoding="utf-8") as f:
        json.dump(input_data, f)

    audit_logger = AuditLogger(log_path=temp_audit_log)
    driver = PodmanSandboxDriver(audit_logger=audit_logger)

    config = SandboxConfig(
        runtime="podman",
        timeout_seconds=10,
        image_ref="maso-skill-worker:v1.1"
    )

    res = driver.run(temp_task_dir, config)
    assert res.exit_code != 0
    assert "Unknown skill" in res.stderr
    assert not os.path.exists(os.path.join(temp_task_dir, "output.json"))


# ----------------------------------------------------------------------
# 4. Mandatory Execution Audit Log & Tamper-Evidence (NEW §11)
# ----------------------------------------------------------------------

def test_audit_logger_hash_chaining(temp_audit_log):
    """Verify cryptographic hash chaining across multiple execution records."""
    logger = AuditLogger(log_path=temp_audit_log)

    rec1 = logger.log_execution(
        task_id="t1", skill_name="skill1", exit_code=0, duration_ms=120
    )
    rec2 = logger.log_execution(
        task_id="t2", skill_name="skill2", exit_code=0, duration_ms=150
    )
    rec3 = logger.log_execution(
        task_id="t3", skill_name="skill3", exit_code=1, duration_ms=90
    )

    assert rec1["previous_hash"] == GENESIS_HASH
    assert rec2["previous_hash"] == rec1["record_hash"]
    assert rec3["previous_hash"] == rec2["record_hash"]

    is_valid, errors = logger.verify_integrity()
    assert is_valid is True
    assert len(errors) == 0


def test_audit_logger_tamper_detection(temp_audit_log):
    """Verify that tampering with an audit record breaks the cryptographic chain."""
    logger = AuditLogger(log_path=temp_audit_log)

    logger.log_execution(task_id="t1", skill_name="skill1", exit_code=0, duration_ms=100)
    logger.log_execution(task_id="t2", skill_name="skill2", exit_code=0, duration_ms=200)

    # Tamper with the log file directly
    with open(temp_audit_log, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Alter exit_code in first record
    data = json.loads(lines[0])
    data["exit_code"] = 99
    lines[0] = json.dumps(data) + "\n"

    with open(temp_audit_log, "w", encoding="utf-8") as f:
        f.writelines(lines)

    is_valid, errors = logger.verify_integrity()
    assert is_valid is False
    assert len(errors) > 0
    assert any("Tampered record hash" in err for err in errors)


# ----------------------------------------------------------------------
# 5. Fail-Closed Sandbox Manager (REVISED §7.2)
# ----------------------------------------------------------------------

def test_sandbox_manager_discovery_and_fail_closed():
    """Verify SandboxManager detects Podman and enforces fail-closed policies."""
    mgr = SandboxManager()
    detected = mgr.detect_available_runtime()
    assert detected in ["podman", "docker", "none"]

    # Local mode without risk acknowledgment must raise RuntimeError
    cfg_local_no_ack = SandboxConfig(runtime="local", i_understand_the_risks=False)
    with pytest.raises(RuntimeError) as exc_info:
        mgr.get_driver(cfg_local_no_ack)
    assert "DEGRADED LOCAL EXECUTION REFUSED" in str(exc_info.value)
