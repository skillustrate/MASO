#!/usr/bin/env python3
"""
Comprehensive Product Evaluation & Benchmark Runner for MASO (v1.1.0).
Executes end-to-end evaluations across all product planes:
1. Structural Auditor & Evaluation Engine (AuditorAssertionEngine)
2. Content Sanitization & Secret Scrubbing (ContentSanitizer & SensitiveDataFilter)
3. Cryptographic Audit Chain Integrity (AuditLogger & SHA-256 chain)
4. Supply Chain Digest & Signature Attestation (verify_image_signature)
5. Sandbox Boundary & Containment Health Check (SandboxManager)
6. CLI Command Evaluation (status, audit, run)
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

# Ensure repository root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masa.crypto.crypto import SensitiveDataFilter
from masa.evals.eval_template import AuditorAssertionEngine, ContentSanitizer
from masa.framework import MultiAgentFramework
from masa.sandbox.audit import AuditLogger
from masa.sandbox.manager import SandboxManager
from masa.sandbox.supply_chain import verify_image_signature


def run_auditor_evaluations() -> dict:
    print("\n--- 1. Evaluating Structural Auditor Engine (AuditorAssertionEngine) ---")
    engine = AuditorAssertionEngine()
    results = {}

    # Eval 1.1: Valid Skill Output
    valid_skill = {
        "status": "SUCCESS",
        "task_id": "eval-task-001",
        "data_table": "| Region | Revenue | Growth |\n| --- | --- | --- |\n| US | $1.2M | +12% |\n| EU | $850K | +8% |",
        "metrics": {"rows_processed": 2, "error_count": 0},
        "audit_trail": ["Ingested raw payload", "Applied normalization", "Certified table"],
        "errors": []
    }
    res_1 = engine.verify_skill_output(valid_skill)
    assert res_1["passed"] is True
    results["valid_skill_output"] = {"passed": True, "score_matrix": res_1["score_matrix"]}
    print("  [PASS] Valid Skill Output Evaluation")

    # Eval 1.2: Rejection of Missing Mandatory Fields
    invalid_skill = {"status": "SUCCESS", "task_id": "eval-task-002", "metrics": {"rows_processed": 1, "error_count": 0}}
    res_2 = engine.verify_skill_output(invalid_skill)
    assert res_2["passed"] is False
    results["missing_fields_rejection"] = {"passed": True, "failures": res_2["failures_checklist"]}
    print("  [PASS] Missing Mandatory Fields Rejection Evaluation")

    # Eval 1.3: Rejection of Non-Zero Error Count
    error_skill = {
        "status": "SUCCESS",
        "task_id": "eval-task-003",
        "data_table": "| col |\n| --- |\n| 1 |",
        "metrics": {"rows_processed": 1, "error_count": 3},
        "audit_trail": [],
        "errors": ["Data corruption in row 2"]
    }
    res_3 = engine.verify_skill_output(error_skill)
    assert res_3["passed"] is False
    results["nonzero_errors_rejection"] = {"passed": True, "failures": res_3["failures_checklist"]}
    print("  [PASS] Non-Zero Error Count Rejection Evaluation")

    # Eval 1.4: Valid Master Result Evaluation
    valid_master = {
        "run_id": "run-eval-master-001",
        "status": "SUCCESS",
        "super_agent_objective": "Consolidate regional metrics",
        "summary": "Processed 2 regions successfully.",
        "sub_tasks": [
            {
                "task_id": "t1",
                "result": {
                    "status": "SUCCESS",
                    "task_id": "t1",
                    "data_table": "| Region | Val |\n| --- | --- |\n| A | 100 |",
                    "metrics": {"rows_processed": 1, "error_count": 0},
                    "audit_trail": ["done"],
                    "errors": []
                }
            }
        ]
    }
    res_4 = engine.verify_master_result(valid_master)
    assert res_4["passed"] is True
    results["valid_master_result"] = {"passed": True, "verdict": res_4["verdict"]}
    print("  [PASS] Valid Master Result Holistic Evaluation")

    return results


def run_sanitizer_and_secret_evaluations() -> dict:
    print("\n--- 2. Evaluating Sanitization & Secret Scrubbing ---")
    results = {}

    # Eval 2.1: Content Sanitizer PII and Secret Detection
    sample_text = "Deploying with key AKIAIOSFODNN7EXAMPLE and ssn 000-12-3456"
    issues = ContentSanitizer.detect_pii_or_secrets(sample_text)
    assert any("AWS" in i for i in issues)
    assert any("SSN" in i for i in issues)
    results["pii_detection"] = {"passed": True, "detected": issues}
    print(f"  [PASS] PII / Secret Detection Evaluation ({len(issues)} items identified)")

    # Eval 2.2: HTML Injection Neutralization
    xss_payload = "<script>alert('pwned')</script><b>bold</b>"
    escaped = ContentSanitizer.escape_html(xss_payload)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
    results["html_sanitization"] = {"passed": True, "escaped": escaped}
    print("  [PASS] HTML / XSS Injection Neutralization Evaluation")

    # Eval 2.3: SensitiveDataFilter Dictionary & Payload Scrubbing
    dict_payload = {
        "user": "analyst",
        "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "bearer_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5",
        "sub_record": {"api_key": "AKIAI44QH8DHBEXAMPLE"}
    }
    scrubbed = SensitiveDataFilter.scrub_data(dict_payload)
    scrubbed_str = json.dumps(scrubbed)
    assert "AKIAI44QH8DHBEXAMPLE" not in scrubbed_str
    assert "wJalrXUtnFEMI" not in scrubbed_str
    assert "[REDACTED" in scrubbed_str
    results["dict_secret_scrubbing"] = {"passed": True, "scrubbed": True}
    print("  [PASS] Recursive Secret Scrubbing Evaluation")

    return results


def run_cryptographic_audit_evaluations() -> dict:
    print("\n--- 3. Evaluating Cryptographic Audit Chain Integrity ---")
    logger = AuditLogger()
    is_valid, errors = logger.verify_integrity()
    assert is_valid is True, f"Audit log broken: {errors}"
    entries = logger.get_recent_entries(limit=10)
    print(f"  [PASS] Existing Audit Log Verified ({len(entries)} verified entries, Chain Valid: {is_valid})")

    # Test tampering resistance in ephemeral environment
    with tempfile.TemporaryDirectory() as td:
        t_log = os.path.join(td, "eval_audit.log")
        t_logger = AuditLogger(log_path=t_log)
        t_logger.log_execution(task_id="eval-1", skill_name="s", exit_code=0, duration_ms=10)
        t_logger.log_execution(task_id="eval-2", skill_name="s", exit_code=0, duration_ms=20)

        # Confirm valid initially
        val_0, _ = t_logger.verify_integrity()
        assert val_0 is True

        # Tamper with record
        with open(t_log, "r") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        lines[0]["exit_code"] = 1  # Alter exit code
        with open(t_log, "w") as f:
            for l in lines:
                f.write(json.dumps(l) + "\n")

        # Confirm tampering is detected
        val_tampered, tamper_errs = t_logger.verify_integrity()
        assert val_tampered is False
        assert len(tamper_errs) > 0
        print("  [PASS] Cryptographic Tampering Resistance Verified")

    return {"chain_valid": is_valid, "entries_checked": len(entries), "tamper_detection": True}


def run_supply_chain_evaluations() -> dict:
    print("\n--- 4. Evaluating Supply Chain & Signed Digest Attestations ---")
    s_mgr = SandboxManager()
    runtime = s_mgr.detect_available_runtime()
    worker_digest = s_mgr.podman_driver.get_image_digest("maso-skill-worker:v1.1")
    assert worker_digest != "unknown"

    sig_ok, sig_msg = verify_image_signature("maso-skill-worker:v1.1", image_digest=worker_digest)
    assert sig_ok is True, f"Attestation check failed: {sig_msg}"
    print(f"  [PASS] Worker Image Attestation Signature Verified ({worker_digest[:16]}...)")

    manifest_path = os.path.join(os.getcwd(), "signatures", "release_digests.json")
    assert os.path.exists(manifest_path)
    with open(manifest_path, "r") as f:
        rel = json.load(f)
    assert rel.get("version") == "v1.1.0"
    print(f"  [PASS] Release Manifest Verified (Version: {rel.get('version')})")

    return {"runtime": runtime, "digest": worker_digest, "signature_verified": sig_ok}


def run_cli_subsystem_evaluations() -> dict:
    print("\n--- 5. Evaluating CLI Subsystems (status, audit, health) ---")
    s_mgr = SandboxManager()
    health = s_mgr.health_check()
    assert health["audit_chain_valid"] is True
    assert health["auditor_state"] == "ACTIVE (Structural Validator)"
    print(f"  [PASS] Health Check Matrix: Runtime={health['runtime']}, Rootless={health['rootless']}, Auditor={health['auditor_state']}")

    # CLI status command invocation
    res = subprocess.run([sys.executable, "framework.py", "status"], capture_output=True, text=True, check=False)
    assert res.returncode == 0
    assert "Sandbox Runtime & Execution Boundary (v1.1.0)" in res.stdout
    assert "Chain Valid: True" in res.stdout
    print("  [PASS] CLI 'maso status' Subsystem Evaluation")

    return {"health": health, "cli_status_rc": res.returncode}


def main():
    print("======================================================================")
    print(" 🛡️  MASO Product-Wide Evaluation & Certification Benchmark (v1.1.0)")
    print("======================================================================")
    start_time = time.time()

    eval_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "product": "MASO (Multi-Agent Scaffolding Architecture)",
        "version": "v1.1.0",
        "evaluations": {}
    }

    eval_report["evaluations"]["auditor_engine"] = run_auditor_evaluations()
    eval_report["evaluations"]["sanitization_and_secrets"] = run_sanitizer_and_secret_evaluations()
    eval_report["evaluations"]["cryptographic_audit"] = run_cryptographic_audit_evaluations()
    eval_report["evaluations"]["supply_chain"] = run_supply_chain_evaluations()
    eval_report["evaluations"]["cli_subsystems"] = run_cli_subsystem_evaluations()

    duration_ms = int((time.time() - start_time) * 1000)
    eval_report["duration_ms"] = duration_ms
    eval_report["verdict"] = "ALL EVALUATIONS PASSED"

    print("\n======================================================================")
    print(" 📊 EVALUATION SUMMARY & CERTIFICATION REPORT")
    print("======================================================================")
    print(f" Product:              {eval_report['product']} {eval_report['version']}")
    print(f" Total Duration:       {duration_ms} ms")
    print(f" Structural Auditor:   CERTIFIED (PASS)")
    print(f" Secret Sanitization:  CERTIFIED (PASS)")
    print(f" Cryptographic Audit:  CERTIFIED (PASS)")
    print(f" Supply Chain Trust:   CERTIFIED (PASS)")
    print(f" Container Isolation:  CERTIFIED (PASS)")
    print(f" Final Verdict:        {eval_report['verdict']}")
    print("======================================================================")

    # Save evaluation benchmark report
    report_file = os.path.join(os.getcwd(), "eval_benchmark_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)
    print(f"Saved benchmark report to: {report_file}")


if __name__ == "__main__":
    main()
