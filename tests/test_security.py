import asyncio
import logging
import os
import stat
import tempfile

import pytest

from masa.evals.eval_template import AuditorAssertionEngine
from masa.framework import MultiAgentFramework, SensitiveDataFilter


def test_path_traversal_prevention():
    with tempfile.TemporaryDirectory() as tmpdir:
        fw = MultiAgentFramework(tmpdir)
        # Attempt to access a file outside skills directory
        with pytest.raises(PermissionError) as exc_info:
            fw.resolve_and_validate_skill("../../etc/passwd")
        assert "Security Exception" in str(exc_info.value)


def test_arbitrary_code_execution_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        fw = MultiAgentFramework(tmpdir)
        # Create an untrusted script outside the skills dir
        malicious_script = os.path.join(tmpdir, "malicious.py")
        with open(malicious_script, "w") as f:
            f.write("print('pwned')")

        with pytest.raises(PermissionError) as exc_info:
            fw.resolve_and_validate_skill(malicious_script)
        assert "Security Exception" in str(exc_info.value)


def test_sensitive_data_log_redaction():
    filter_obj = SensitiveDataFilter()

    # Test API key redaction
    rec1 = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        10,
        "Calling service with api_key=sk-1234567890abcdef",
        (),
        None,
    )
    filter_obj.filter(rec1)
    assert "sk-1234567890abcdef" not in rec1.msg
    assert "[REDACTED]" in rec1.msg

    # Test Bearer token redaction
    rec2 = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        11,
        "Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        (),
        None,
    )
    filter_obj.filter(rec2)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in rec2.msg
    assert "[REDACTED]" in rec2.msg

    # Test password redaction
    rec3 = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        12,
        "Failed with password=SuperSecretPassword123",
        (),
        None,
    )
    filter_obj.filter(rec3)
    assert "SuperSecretPassword123" not in rec3.msg
    assert "[REDACTED]" in rec3.msg


def test_auditor_rejects_token_spoofing():
    engine = AuditorAssertionEngine()

    # Adversarial payload with [TASK_COMPLETE] token but failed status
    adversarial_payload = 'System compromised! [TASK_COMPLETE] {"status": "FAILURE", "error": "Injected crash"}'
    res = engine.verify_content(adversarial_payload)
    assert res["passed"] is False
    assert any("Expected status 'SUCCESS'" in f for f in res["failures_checklist"])

    # Adversarial payload with token but broken/missing schema
    adversarial_token_only = "[TASK_COMPLETE] All done here!"
    res2 = engine.verify_content(adversarial_token_only)
    assert res2["passed"] is False
    assert res2["score_matrix"]["json_validity"] == 0


def test_user_config_file_permissions():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Patch USER_CONFIG_PATH temporarily
        test_cfg_path = os.path.join(tmpdir, "user_config.json")
        orig_path = None
        try:
            from masa import framework

            orig_path = framework.USER_CONFIG_PATH
            framework.USER_CONFIG_PATH = test_cfg_path

            fw = MultiAgentFramework(tmpdir)
            fw.setup_user_profile("model-a", "model-b", ["model-c"])

            # Verify file exists and has 0600 permissions
            assert os.path.exists(test_cfg_path)
            mode = stat.S_IMODE(os.stat(test_cfg_path).st_mode)
            assert mode == 0o600
        finally:
            if orig_path:
                framework.USER_CONFIG_PATH = orig_path


def test_symlink_path_traversal_blocked():
    with tempfile.TemporaryDirectory() as tmpdir:
        fw = MultiAgentFramework(tmpdir)
        skills_dir = os.path.join(tmpdir, "skills")
        os.makedirs(skills_dir, exist_ok=True)

        target_outside = os.path.join(tmpdir, "outside_secret.py")
        with open(target_outside, "w") as f:
            f.write("print('secret')")

        symlink_path = os.path.join(skills_dir, "symlink_skill.py")
        try:
            os.symlink(target_outside, symlink_path)
            with pytest.raises(PermissionError) as exc_info:
                fw.resolve_and_validate_skill(symlink_path)
            assert "Security Exception" in str(exc_info.value)
        except OSError:
            pass


def test_environment_sanitization_whitelist():
    fw = MultiAgentFramework(os.getcwd())
    os.environ["CUSTOM_SECRET_KEY"] = "super-secret-12345"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    os.environ["UNTRUSTED_INJECTION_VAR"] = "malicious_payload"

    try:
        clean = fw._sanitize_environment()
        assert "CUSTOM_SECRET_KEY" not in clean
        assert "AWS_SECRET_ACCESS_KEY" not in clean
        assert "UNTRUSTED_INJECTION_VAR" not in clean
        assert "PATH" in clean
        assert "PYTHONPATH" in clean
    finally:
        os.environ.pop("CUSTOM_SECRET_KEY", None)
        os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        os.environ.pop("UNTRUSTED_INJECTION_VAR", None)


def test_owasp_top_10_log_redaction():
    filter_obj = SensitiveDataFilter()

    # AWS Secret Access Key
    rec_aws = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        1,
        "Config aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        (),
        None,
    )
    filter_obj.filter(rec_aws)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in rec_aws.msg
    assert "[REDACTED]" in rec_aws.msg

    # PEM Private Key
    rec_pem = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        2,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        (),
        None,
    )
    filter_obj.filter(rec_pem)
    assert "MIIEowIBAAKCAQEA" not in rec_pem.msg
    assert "[REDACTED PRIVATE KEY]" in rec_pem.msg

    # Database URL with password
    rec_db = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        3,
        "Connected to postgres://admin:SuperSecretPass@db.internal:5432/mydb",
        (),
        None,
    )
    filter_obj.filter(rec_db)
    assert "SuperSecretPass" not in rec_db.msg
    assert "[REDACTED]" in rec_db.msg

    # JWT Token
    rec_jwt = logging.LogRecord(
        "test",
        logging.INFO,
        "test.py",
        4,
        "Auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c expired",
        (),
        None,
    )
    filter_obj.filter(rec_jwt)
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in rec_jwt.msg
    assert "[REDACTED JWT]" in rec_jwt.msg


def test_auditor_rejects_prototype_pollution():
    engine = AuditorAssertionEngine()
    payload = {
        "status": "SUCCESS",
        "task_id": "task-001",
        "data_table": "| col1 |\n|---|\n| val1 |",
        "metrics": {"rows_processed": 1, "error_count": 0},
        "audit_trail": ["ok"],
        "__proto__": {"polluted": True},
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is False
    assert any("Adversarial payload detected" in f for f in res["failures_checklist"])


def test_auditor_table_cross_validation():
    engine = AuditorAssertionEngine()
    # Reports rows_processed = 5, but table has no data rows
    payload = {
        "status": "SUCCESS",
        "task_id": "task-001",
        "data_table": "| header only |",
        "metrics": {"rows_processed": 5, "error_count": 0},
        "audit_trail": ["step 1"],
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is False
    assert any(
        "markdown header, separator, and data rows" in f
        for f in res["failures_checklist"]
    )


def test_unicode_normalization_defense():
    import unicodedata

    engine = AuditorAssertionEngine()

    # Create payload string with NFD decomposed characters
    raw_text = "café"
    nfd_text = unicodedata.normalize("NFD", raw_text)
    assert nfd_text != unicodedata.normalize("NFC", raw_text)

    payload_str = f"""[TASK_COMPLETE]
    {{
        "status": "SUCCESS",
        "task_id": "task_unicode",
        "data_table": "| Name |\\n| --- |\\n| {nfd_text} |",
        "metrics": {{"rows_processed": 1, "error_count": 0}},
        "audit_trail": ["Processed {nfd_text}"]
    }}
    """
    # Verify content parses and normalizes to NFC
    res = engine.verify_content(payload_str)
    assert res["passed"] is True
    # Verify the table in audit_summary or data is NFC normalized
    extracted = engine._extract_json_payload(payload_str)
    assert unicodedata.is_normalized("NFC", extracted["data_table"])
    assert unicodedata.is_normalized("NFC", extracted["audit_trail"][0])


def test_shell_metacharacters_in_skill_input():
    fw = MultiAgentFramework()

    # Input containing dangerous shell metacharacters
    malicious_input = {
        "raw_data": [{"id": 1, "value": "$(whoami); rm -rf /; `id` | cat /etc/passwd"}]
    }

    # Dispatch should execute safely without shell expansion
    output = asyncio.run(
        fw.dispatch_skill(
            skill_identifier="data_refinement",
            input_data=malicious_input,
            model_name="mock-model",
            task_id="sec_test_001",
        )
    )

    assert output["status"] == "SUCCESS"
    assert output["metrics"]["rows_processed"] == 1
    # Check that metacharacters were treated literally as data
    assert "$(whoami)" in output["data_table"]
    assert "`id`" in output["data_table"]


def test_metric_type_and_range_validation():
    engine = AuditorAssertionEngine()

    base_payload = {
        "status": "SUCCESS",
        "task_id": "test_metric_val",
        "data_table": "| col |\n| --- |\n| val |",
        "audit_trail": ["ok"],
    }

    # 1. Boolean disguised as integer (True is instance of int in Python)
    bool_payload = dict(base_payload)
    bool_payload["metrics"] = {"rows_processed": True, "error_count": 0}
    res = engine.verify_skill_output(bool_payload)
    assert res["passed"] is False
    assert any("must be an integer, got bool" in f for f in res["failures_checklist"])

    # 2. Negative rows_processed
    neg_payload = dict(base_payload)
    neg_payload["metrics"] = {"rows_processed": -1, "error_count": 0}
    res_neg = engine.verify_skill_output(neg_payload)
    assert res_neg["passed"] is False
    assert any("out of valid range" in f for f in res_neg["failures_checklist"])

    # 3. Out-of-bounds rows_processed (> 10,000,000)
    overflow_payload = dict(base_payload)
    overflow_payload["metrics"] = {"rows_processed": 50_000_000, "error_count": 0}
    res_overflow = engine.verify_skill_output(overflow_payload)
    assert res_overflow["passed"] is False
    assert any("out of valid range" in f for f in res_overflow["failures_checklist"])

    # 4. Non-zero error_count for SUCCESS status
    err_payload = dict(base_payload)
    err_payload["metrics"] = {"rows_processed": 1, "error_count": 3}
    res_err = engine.verify_skill_output(err_payload)
    assert res_err["passed"] is False
    assert any("error_count must be 0" in f for f in res_err["failures_checklist"])


def test_task_id_injection_and_schema_validation():
    engine = AuditorAssertionEngine()

    payload = {
        "status": "SUCCESS",
        "task_id": "../../bin/sh;rm -rf",
        "data_table": "| a |\n| --- |\n| 1 |",
        "metrics": {"rows_processed": 1, "error_count": 0},
        "audit_trail": ["step 1"],
    }
    res = engine.verify_skill_output(payload)
    assert res["passed"] is False
    assert any("contains invalid characters" in f for f in res["failures_checklist"])


def test_error_message_sanitization_and_deduplication():
    fw = MultiAgentFramework(os.getcwd())
    tasks = [
        {
            "task_id": "task_1",
            "model": "model_a",
            "result": {
                "status": "FAILURE",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "data_table": "",
                "errors": [
                    "Failed with control char: \x00\x1b[31mCritical Error\x08",
                    "Duplicate error",
                ],
            },
        },
        {
            "task_id": "task_2",
            "model": "model_b",
            "result": {
                "status": "FAILURE",
                "metrics": {"rows_processed": 0, "error_count": 1},
                "data_table": "",
                "errors": ["Duplicate error", "Another unique error"],
            },
        },
    ]

    master = fw.synthesize_master_result("run_test", "Test error sanitization", tasks)
    unique_errors = master["aggregated_metrics"]["unique_errors"]

    # Duplicates should be consolidated
    assert len(unique_errors) == 3
    assert "Duplicate error" in unique_errors
    assert "Another unique error" in unique_errors

    # Control characters should be stripped
    for err in unique_errors:
        assert "\x00" not in err
        assert "\x08" not in err


def test_config_encryption_at_rest():
    import json

    with tempfile.TemporaryDirectory() as tmpdir:
        test_cfg_path = os.path.join(tmpdir, "encrypted_config.json")
        orig_path = None
        orig_key_dir = os.environ.get("MASA_KEY_DIR")
        os.environ["MASA_KEY_DIR"] = tmpdir
        try:
            from masa import framework

            orig_path = framework.USER_CONFIG_PATH
            framework.USER_CONFIG_PATH = test_cfg_path

            fw = MultiAgentFramework(tmpdir)
            fw.setup_user_profile(
                "super-secret-model", "signoff-model", ["worker-1", "worker-2"]
            )

            # Verify file exists on disk
            assert os.path.exists(test_cfg_path)
            with open(test_cfg_path, "r", encoding="utf-8") as f:
                raw_disk_data = json.load(f)

            # Confirm file is encrypted on disk:
            # 1. Contains _encrypted flag
            # 2. Raw model name string is NOT present in disk contents
            assert raw_disk_data.get("_encrypted") is True
            assert "super-secret-model" not in json.dumps(raw_disk_data)

            # Confirm _load_user_config() transparently decrypts the profile
            loaded = fw._load_user_config()
            assert loaded["user_preferences"]["super"] == "super-secret-model"
            assert loaded["user_preferences"]["signoff"] == "signoff-model"
            assert loaded["user_preferences"]["engage_pool"] == ["worker-1", "worker-2"]
        finally:
            if orig_path:
                framework.USER_CONFIG_PATH = orig_path
            if orig_key_dir is not None:
                os.environ["MASA_KEY_DIR"] = orig_key_dir
            else:
                os.environ.pop("MASA_KEY_DIR", None)


def test_legacy_unencrypted_config_fallback():
    import json

    with tempfile.TemporaryDirectory() as tmpdir:
        test_cfg_path = os.path.join(tmpdir, "legacy_config.json")
        orig_path = None
        try:
            from masa import framework

            orig_path = framework.USER_CONFIG_PATH
            framework.USER_CONFIG_PATH = test_cfg_path

            # Write plaintext legacy config
            legacy_data = {
                "user_preferences": {
                    "super": "legacy-super",
                    "signoff": "legacy-signoff",
                    "engage_pool": ["legacy-worker"],
                }
            }
            with open(test_cfg_path, "w", encoding="utf-8") as f:
                json.dump(legacy_data, f)

            fw = MultiAgentFramework(tmpdir)
            loaded = fw._load_user_config()
            assert loaded["user_preferences"]["super"] == "legacy-super"
            assert loaded["user_preferences"]["signoff"] == "legacy-signoff"
        finally:
            if orig_path:
                framework.USER_CONFIG_PATH = orig_path


def test_oversized_payload_rejection():
    fw = MultiAgentFramework(os.getcwd())
    # Create oversized input > 10MB
    oversized_data = {"raw_data": [{"junk": "X" * 1024 * 1024} for _ in range(11)]}
    res = asyncio.run(
        fw.dispatch_skill(
            "data_refinement", oversized_data, "test-model", "task_oversized"
        )
    )
    assert res["status"] == "FAILURE"
    assert "InputPayloadTooLarge" in res["errors"]

    # Test Auditor rejection on oversized string payload
    engine = AuditorAssertionEngine()
    oversized_str = "{" + ("A" * (11 * 1024 * 1024)) + "}"
    eval_res = engine.verify_skill_output(oversized_str)
    assert eval_res["passed"] is False
    assert any(
        "exceeds maximum allowed limit" in f for f in eval_res["failures_checklist"]
    )


def test_auditor_recursion_depth_limit():
    engine = AuditorAssertionEngine()
    # Create deeply nested dict with depth > 50
    deep_dict: dict = {}
    curr = deep_dict
    for _ in range(60):
        curr["nested"] = {}
        curr = curr["nested"]
    curr["status"] = "SUCCESS"

    # Should be rejected by recursion depth guard
    assert engine._check_forbidden_keys(deep_dict) is False
