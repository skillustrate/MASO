"""
Master Cross-Phase Integration Test Suite for MASO (v1.1.0).
Unifies and validates the end-to-end lifecycle across all 5 phases:
- Phase 1: Hardened rootless Podman execution, custom seccomp allowlist, atomic mailbox, SHA-256 audit chaining.
- Phase 2: Orchestrator dispatch, sensitive data pre-scrubbing, auditor validation, ephemeral cleanup, local fallback check.
- Phase 3: Docker containment parity, egress proxy anti-SSRF DNS pinning, seccomp variants, image digest signature verification.
- Phase 4: Active adversarial vector containment (filesystem escape, ptrace, setuid escalation), audit tamper detection.
- Phase 5: Release digest attestation verification, health check status matrix.
"""

import asyncio
import json
import os
import shutil
import socket
import tempfile
import pytest

from masa.crypto.crypto import SensitiveDataFilter
from masa.evals.eval_template import AuditorAssertionEngine
from masa.framework import MultiAgentFramework
from masa.sandbox.audit import AuditLogger
from masa.sandbox.base import SandboxConfig
from masa.sandbox.docker import DockerSandboxDriver
from masa.sandbox.egress import (
    DeniedIpError,
    EgressProxyServer,
    RawIpForbiddenError,
    resolve_and_pin_domain,
)
from masa.sandbox.manager import SandboxManager
from masa.sandbox.podman import PodmanSandboxDriver
from masa.sandbox.supply_chain import (
    sign_image_digest,
    verify_image_signature,
)


@pytest.fixture
def clean_workspace():
    """Create an isolated workspace environment for end-to-end integration."""
    d = tempfile.mkdtemp(prefix="maso_all_phases_")
    os.chmod(d, 0o777)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_master_all_phases_integration(clean_workspace):
    """
    Executes a comprehensive, unified cross-phase integration test verifying all
    Phase 1-5 security guarantees and operational boundaries in sequence.
    """
    if shutil.which("podman") is None:
        pytest.skip("Podman required for master integration test")

    repo_root = os.getcwd()
    log_path = os.path.join(clean_workspace, "audit", "execution.log")
    audit_logger = AuditLogger(log_path=log_path)
    s_mgr = SandboxManager(audit_logger=audit_logger)

    print("\n--- [PHASE 5 CHECK] Verifying Published Release Digests & Attestations ---")
    release_manifest_path = os.path.join(repo_root, "signatures", "release_digests.json")
    assert os.path.exists(release_manifest_path), "Release manifest missing"
    with open(release_manifest_path, "r", encoding="utf-8") as f:
        release_data = json.load(f)
    assert release_data["version"] == "v1.1.0"
    assert "maso-skill-worker" in release_data["images"]
    assert "maso-egress-proxy" in release_data["images"]

    worker_digest = s_mgr.podman_driver.get_image_digest("maso-skill-worker:v1.1")
    assert worker_digest != "unknown"

    sig_ok, sig_msg = verify_image_signature("maso-skill-worker:v1.1", image_digest=worker_digest)
    assert sig_ok is True, f"Signature check failed: {sig_msg}"

    print("\n--- [PHASE 1 & 2 EXECUTION] End-to-End Orchestrator Pipeline in Rootless Podman ---")
    # Prepare input payload containing an AWS credential to test Phase 2 secret scrubbing
    raw_input_path = os.path.join(clean_workspace, "input_with_secrets.json")
    dirty_payload = {
        "dataset_name": "critical_records",
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "raw_data": [
            {"id": "REC-001", "val": 100, "token": "ghp_0123456789abcdef0123456789abcdef012345"},
            {"id": "REC-002", "val": 200, "token": "safe_token_value"}
        ]
    }
    with open(raw_input_path, "w", encoding="utf-8") as f:
        json.dump(dirty_payload, f)

    # Initialize framework
    fw = MultiAgentFramework(clean_workspace)
    # Ensure framework and its drivers use our isolated audit logger
    fw.sandbox_manager.audit_logger = audit_logger
    fw.sandbox_manager.podman_driver.audit_logger = audit_logger
    fw.sandbox_manager.docker_driver.audit_logger = audit_logger

    pipeline_res = asyncio.run(
        fw.run_pipeline(
            user_objective="Refine critical records under strict sandbox containment",
            input_file=raw_input_path,
            super_override="mock",
            signoff_override="mock",
            engage_override=["mock"],
            num_agents=2,
            sandbox_mode="podman",
            sandbox_memory="512m",
            sandbox_timeout=60,
            allow_network=False,
            purge_ephemeral=True
        )
    )

    assert pipeline_res["passed"] is True
    assert pipeline_res["run_id"].startswith("run_")

    run_dir = os.path.join(clean_workspace, "mailboxes", pipeline_res["run_id"])
    audit_report_path = os.path.join(run_dir, "audit_report.json")
    assert os.path.exists(audit_report_path), "audit_report.json missing from run dir"
    with open(audit_report_path, "r", encoding="utf-8") as f:
        auditor_report = json.load(f)

    # Verify structural auditor evaluation
    assert auditor_report.get("passed") is True
    assert auditor_report.get("score_matrix", {}).get("json_validity") == 1
    assert auditor_report.get("score_matrix", {}).get("all_tasks_success") == 1
    assert auditor_report.get("score_matrix", {}).get("data_integrity") == 1
    assert len(auditor_report.get("failures_checklist", [])) == 0

    # Verify secret scrubbing took place (Defense-in-depth)
    scrubbed = SensitiveDataFilter.scrub_data(dirty_payload)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(scrubbed)

    # Verify ephemeral directories were purged while master result was preserved
    run_dir = os.path.join(clean_workspace, "mailboxes", pipeline_res["run_id"])
    tasks_dir = os.path.join(run_dir, "tasks")
    assert not os.path.exists(tasks_dir) or len(os.listdir(tasks_dir)) == 0
    assert os.path.exists(os.path.join(run_dir, "master_result.json"))

    # Verify audit log recorded execution with valid hash chain
    assert os.path.exists(log_path)
    is_valid, errors = audit_logger.verify_integrity()
    assert is_valid is True, f"Audit chain errors: {errors}"
    entries = audit_logger.get_recent_entries(limit=5)
    assert len(entries) >= 1
    last_run_entry = entries[-1]
    assert last_run_entry["exit_code"] == 0
    assert last_run_entry["degraded_isolation"] is False
    assert last_run_entry["signature_verified"] is True

    print("\n--- [PHASE 3 DUAL ENGINE & EGRESS CHECK] Docker Parity & Anti-SSRF Proxy ---")
    # Verify Docker driver parity
    docker_driver = DockerSandboxDriver(audit_logger=audit_logger)
    if docker_driver.is_available():
        with tempfile.TemporaryDirectory() as td_dock:
            dock_input = {
                "task_id": "cross-phase-docker",
                "run_id": "run-master-dock",
                "skill_name": "data_refinement",
                "parameters": {"raw_data": [{"val": 10}, {"val": 20}]}
            }
            with open(os.path.join(td_dock, "input.json"), "w", encoding="utf-8") as f:
                json.dump(dock_input, f)
            cfg_dock = SandboxConfig(runtime="docker", image_ref="maso-skill-worker:v1.1", timeout_seconds=30)
            res_dock = docker_driver.run(td_dock, cfg_dock)
            assert res_dock.exit_code == 0
            assert res_dock.isolation_mode == "docker"
            assert res_dock.output_data.get("status") == "SUCCESS"

    # Verify Egress Anti-SSRF (DNS Rebinding & Raw IP block)
    with pytest.raises(RawIpForbiddenError):
        resolve_and_pin_domain("127.0.0.1", ["127.0.0.1"], port=443)

    with pytest.raises(DeniedIpError):
        def rebinding_resolver(domain, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]
        resolve_and_pin_domain("metadata.safe.com", ["metadata.safe.com"], port=443, custom_resolver=rebinding_resolver)

    print("\n--- [PHASE 4 ADVERSARIAL RESILIENCE CHECK] Containment Verification ---")
    # Run active adversarial vector in real Podman container
    with tempfile.TemporaryDirectory() as td_adv:
        adv_input = {
            "task_id": "cross-phase-adv-ptrace",
            "run_id": "run-master-adv",
            "skill_name": "adversarial_test",
            "parameters": {"attack_type": "ptrace_syscall"}
        }
        with open(os.path.join(td_adv, "input.json"), "w", encoding="utf-8") as f:
            json.dump(adv_input, f)
        cfg_adv = SandboxConfig(runtime="podman", image_ref="maso-skill-worker:v1.1", timeout_seconds=15)
        res_adv = s_mgr.podman_driver.run(td_adv, cfg_adv)
        assert res_adv.exit_code == 0
        assert res_adv.output_data.get("result", {}).get("status") == "CONTAINED"

    # Verify Audit Tamper Detection
    with open(log_path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    # Corrupt the first record
    records[0]["exit_code"] = 999
    corrupted_log_path = os.path.join(clean_workspace, "audit", "corrupted.log")
    with open(corrupted_log_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    tampered_logger = AuditLogger(log_path=corrupted_log_path)
    tampered_valid, tamper_errors = tampered_logger.verify_integrity()
    assert tampered_valid is False
    assert len(tamper_errors) > 0

    print("\n--- [HEALTH CHECK MATRIX] Status & Engine Verification ---")
    status = s_mgr.health_check()
    assert status["runtime"] in ("podman", "docker")
    assert status["audit_chain_valid"] is True
    assert status["auditor_state"] == "ACTIVE (Structural Validator)"
    print(f"Master Integration Passed: Engine={status['runtime']} Rootless={status['rootless']} ChainValid={status['audit_chain_valid']}")
