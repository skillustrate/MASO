"""
Comprehensive Adversarial Security Test Suite for MASO (Sprint 4, Task 4.2 & 4.5).
Tests real container boundary enforcement against active adversarial vectors:
- Host filesystem escape attempt (cat ~/.ssh/id_rsa)
- Outbound socket connect in offline container
- Syscall attempts (ptrace, mount, bpf) denied by seccomp
- Privilege escalation (setuid) denied by no-new-privileges
- Memory allocation bomb contained by cgroup limits / OOM killer
- Multi-megabyte output attempt aborted by worker output cap
- Cryptographic audit log tampering detection (hash-chain break)
"""

import json
import os
import shutil
import tempfile
import pytest

from masa.sandbox.audit import AuditLogger
from masa.sandbox.base import SandboxConfig
from masa.sandbox.podman import PodmanSandboxDriver


@pytest.fixture
def podman_driver():
    if shutil.which("podman") is None:
        pytest.skip("Podman not available on host")
    return PodmanSandboxDriver()


def run_adversarial_task(driver, attack_type: str, memory_limit: str = "512m", timeout_seconds: int = 30, td_path: str = None):
    """Helper to dispatch an adversarial attack task into a rootless Podman worker container."""
    td = td_path or tempfile.mkdtemp(prefix="adv_test_")
    log_path = os.path.join(td, "audit.log")
    logger = AuditLogger(log_path=log_path)
    driver.audit_logger = logger

    input_payload = {
        "task_id": f"adv-{attack_type}",
        "run_id": "run-adv",
        "skill_name": "adversarial_test",
        "parameters": {"attack_type": attack_type}
    }
    with open(os.path.join(td, "input.json"), "w", encoding="utf-8") as f:
        json.dump(input_payload, f)

    cfg = SandboxConfig(
        runtime="podman",
        image_ref="maso-skill-worker:v1.1",
        memory_limit=memory_limit,
        timeout_seconds=timeout_seconds,
        allow_network=False
    )

    res = driver.run(td, cfg)
    return res, logger, td


def test_adversarial_ssh_read_attempt(podman_driver):
    """Adversarial 4.2: Verify host ~/.ssh/id_rsa and /etc/shadow cannot be read."""
    res, logger, td = run_adversarial_task(podman_driver, "ssh_read")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
        assert "Host filesystem inaccessible" in result.get("message", "")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_socket_connect_offline(podman_driver):
    """Adversarial 4.2: Verify raw socket connection is blocked in default offline container."""
    res, logger, td = run_adversarial_task(podman_driver, "socket_connect")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_ptrace_syscall_blocked(podman_driver):
    """Adversarial 4.2: Verify ptrace syscall is blocked by custom seccomp allowlist profile."""
    res, logger, td = run_adversarial_task(podman_driver, "ptrace_syscall")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_mount_syscall_blocked(podman_driver):
    """Adversarial 4.2: Verify mount syscall is blocked by seccomp and dropped capabilities."""
    res, logger, td = run_adversarial_task(podman_driver, "mount_syscall")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_bpf_syscall_blocked(podman_driver):
    """Adversarial 4.2: Verify bpf syscall is blocked by seccomp."""
    res, logger, td = run_adversarial_task(podman_driver, "bpf_syscall")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_setuid_escalation_blocked(podman_driver):
    """Adversarial 4.2: Verify privilege escalation via setuid is blocked by no-new-privileges."""
    res, logger, td = run_adversarial_task(podman_driver, "setuid_escalation")
    try:
        assert res.exit_code == 0
        assert res.output_data is not None
        result = res.output_data.get("result", {})
        assert result.get("status") == "CONTAINED"
        assert "Operation not permitted" in result.get("error", "")
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_memory_bomb_contained(podman_driver):
    """Adversarial 4.2: Verify allocation bomb (700MB in 256MB container) triggers OOM kill, host stable."""
    res, logger, td = run_adversarial_task(podman_driver, "memory_bomb", memory_limit="256m")
    try:
        # Kernel OOM killer terminates process (exit code 137 or non-zero)
        assert res.exit_code != 0
        assert res.exit_code in (137, 1)

        # Audit record must record non-zero exit
        entries = logger.get_recent_entries(limit=1)
        assert len(entries) == 1
        assert entries[0]["exit_code"] != 0
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_adversarial_oversized_output_aborts(podman_driver):
    """Adversarial 4.2: Verify multi-MB output exceeding cap aborts worker without writing output.json."""
    res, logger, td = run_adversarial_task(podman_driver, "oversized_output")
    try:
        # Worker exits with exit_code 15 when output size cap is exceeded
        assert res.exit_code == 15
        assert "exceeds configured max_output_bytes" in res.stderr
        assert res.output_data is None
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_audit_log_tamper_detection_breaks_hash_chain():
    """Task 4.5: Verify tampering with any record in the audit log causes hash-chain verification to fail."""
    with tempfile.TemporaryDirectory() as td:
        log_path = os.path.join(td, "audit.log")
        logger = AuditLogger(log_path=log_path)

        # Log 3 legitimate records
        logger.log_execution(task_id="t1", skill_name="s1", exit_code=0, duration_ms=10)
        logger.log_execution(task_id="t2", skill_name="s2", exit_code=0, duration_ms=20)
        logger.log_execution(task_id="t3", skill_name="s3", exit_code=0, duration_ms=30)

        # Confirm valid before tampering
        is_valid, errors = logger.verify_integrity()
        assert is_valid is True
        assert len(errors) == 0

        # Tamper with the 2nd record: modify duration_ms
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        lines[1]["duration_ms"] = 999999  # Tamper!

        with open(log_path, "w", encoding="utf-8") as f:
            for rec in lines:
                f.write(json.dumps(rec) + "\n")

        # Now verification MUST fail
        is_valid_after, errors_after = logger.verify_integrity()
        assert is_valid_after is False
        assert len(errors_after) > 0
        assert any("Tampered record hash" in err or "Broken hash link" in err for err in errors_after)
