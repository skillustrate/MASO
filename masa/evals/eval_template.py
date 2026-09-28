import json
import logging
import os
import re
import sys
import unicodedata
from typing import Any, Dict, List, Optional, Union

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("AuditorAssertionEngine")


import html


class ContentSanitizer:
    @staticmethod
    def escape_html(text: str) -> str:
        if not isinstance(text, str):
            return text
        return html.escape(text)

    @staticmethod
    def detect_pii_or_secrets(text: str) -> List[str]:
        if not isinstance(text, str):
            return []
        issues = []
        # Basic regex for AWS keys, private keys, or social security numbers
        if re.search(r"AKIA[0-9A-Z]{16}", text):
            issues.append("Detected potential AWS Access Key")
        if re.search(r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----", text):
            issues.append("Detected potential Private Key")
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
            issues.append("Detected potential SSN")
        return issues


class AuditorAssertionEngine:
    """
    Programmatic test validation and holistic verification engine for the Signoff / Auditor Agent.
    Enforces strict structural integrity, schema compliance, and semantic verification,
    eliminating bypasses from completion-token spoofing or schema bypass.
    """

    MANDATORY_SKILL_FIELDS = [
        "status",
        "task_id",
        "data_table",
        "metrics",
        "audit_trail",
    ]
    MANDATORY_METRIC_FIELDS = ["rows_processed", "error_count"]
    FORBIDDEN_KEYS = {"__proto__", "constructor", "prototype"}
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB limit

    def __init__(
        self, completion_tokens: Optional[List[str]] = None, require_token: bool = False
    ):
        self.completion_tokens = completion_tokens or ["[TASK_COMPLETE]"]
        self.require_token = require_token

    def _check_forbidden_keys(
        self, obj: Any, depth: int = 0, max_depth: int = 50
    ) -> bool:
        """Recursively checks if dictionary or list contains forbidden prototype pollution keys or exceeds recursion limit."""
        if depth > max_depth:
            return False
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in self.FORBIDDEN_KEYS:
                    return False
                if not self._check_forbidden_keys(v, depth + 1, max_depth):
                    return False
        elif isinstance(obj, list):
            for item in obj:
                if not self._check_forbidden_keys(item, depth + 1, max_depth):
                    return False
        return True

    @staticmethod
    def sanitize_error_message(err: Any) -> str:
        """Sanitizes an error message by stripping control characters and enforcing max length."""
        text = str(err)
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)
        return text[:500]

    def validate_schema(self, data: Dict[str, Any]) -> List[str]:
        """
        Performs formal schema, type, and range validation on the telemetry dictionary.
        Returns a list of validation failure messages (empty if valid).
        """
        errors: List[str] = []
        if not isinstance(data, dict):
            return ["Payload root must be a JSON object."]

        # Check prototype pollution keys
        if not self._check_forbidden_keys(data):
            return ["Adversarial payload detected: forbidden prototype pollution keys."]

        # Mandatory fields
        missing = [f for f in self.MANDATORY_SKILL_FIELDS if f not in data]
        if missing:
            errors.append(f"Missing mandatory schema fields: {missing}")

        # Field: status (exact string check)
        status = data.get("status")
        if not isinstance(status, str) or status not in ["SUCCESS", "FAILURE"]:
            errors.append(
                f"'status' must be 'SUCCESS' or 'FAILURE', got {repr(status)}."
            )

        # Field: task_id (alphanumeric string with hyphens/underscores, 1-128 chars)
        task_id = data.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            errors.append("'task_id' must be a non-empty string.")
        elif not re.match(r"^[a-zA-Z0-9_\-\.:]{1,128}$", task_id):
            errors.append(
                f"'task_id' contains invalid characters or exceeds 128 chars: {repr(task_id)}"
            )

        # Field: data_table
        data_table = data.get("data_table")
        if not isinstance(data_table, str):
            errors.append("'data_table' must be a string.")

        # Field: metrics (type and range validation)
        metrics = data.get("metrics")
        if not isinstance(metrics, dict):
            errors.append("'metrics' must be a dictionary.")
        else:
            for mf in self.MANDATORY_METRIC_FIELDS:
                if mf not in metrics:
                    errors.append(f"Missing mandatory metrics field: '{mf}'")
                else:
                    val = metrics[mf]
                    if type(val) is not int:
                        errors.append(
                            f"Metric '{mf}' must be an integer, got {type(val).__name__}."
                        )
                    elif val < 0 or val > 10_000_000:
                        errors.append(
                            f"Metric '{mf}' value {val} out of valid range [0, 10000000]."
                        )

        # Field: audit_trail
        audit_trail = data.get("audit_trail")
        if not isinstance(audit_trail, list):
            errors.append("'audit_trail' must be a list of strings.")
        elif len(audit_trail) > 1000:
            errors.append("Length of 'audit_trail' exceeds maximum limit (1000).")
        elif not all(
            isinstance(item, str) and len(item) <= 2000 for item in audit_trail
        ):
            errors.append(
                "All entries in 'audit_trail' must be strings with max length 2000."
            )

        # Optional field: errors
        reported_errors = data.get("errors")
        if reported_errors is not None:
            if not isinstance(reported_errors, list):
                errors.append("'errors' must be a list.")
            elif not all(isinstance(e, str) for e in reported_errors):
                errors.append("All items in 'errors' list must be strings.")

        return errors

    def _extract_json_payload(self, content: str) -> Optional[Dict[str, Any]]:
        """Safely parses JSON payload from string content with Unicode NFC normalization, size bounds, and security guards."""
        if not isinstance(content, str):
            return None
        if len(content.encode("utf-8", errors="ignore")) > self.MAX_PAYLOAD_SIZE:
            logger.warning(
                f"Payload size ({len(content)} bytes) exceeds maximum limit ({self.MAX_PAYLOAD_SIZE} bytes)."
            )
            return None
        # Unicode normalization (NFC) prevents visual spoofing and character-level normalization attacks
        content = unicodedata.normalize("NFC", content).strip()
        parsed = None
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            start_idx = content.find("{")
            end_idx = content.rfind("}")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                candidate = content[start_idx : end_idx + 1]
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    pass

        if parsed and isinstance(parsed, dict) and self._check_forbidden_keys(parsed):
            return parsed
        return None

    def verify_skill_output(
        self, payload: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validates individual Engage Agent skill telemetry against schema & integrity rules.
        """
        failures: List[str] = []
        score_matrix = {
            "json_validity": 0,
            "status_success": 0,
            "schema_conformity": 0,
            "data_integrity": 0,
            "no_errors": 0,
        }

        if (
            isinstance(payload, str)
            and len(payload.encode("utf-8", errors="ignore")) > self.MAX_PAYLOAD_SIZE
        ):
            return {
                "passed": False,
                "score_matrix": score_matrix,
                "failures_checklist": [
                    f"Payload size exceeds maximum allowed limit ({self.MAX_PAYLOAD_SIZE} bytes)."
                ],
                "audit_summary": {"error": "Payload size exceeded limit"},
            }

        data: Optional[Dict[str, Any]] = None
        if isinstance(payload, dict):
            if self._check_forbidden_keys(payload):
                data = payload
                score_matrix["json_validity"] = 1
            else:
                failures.append(
                    "Adversarial payload detected: forbidden prototype pollution keys."
                )
        elif isinstance(payload, str):
            data = self._extract_json_payload(payload)
            if data is not None:
                score_matrix["json_validity"] = 1
            else:
                failures.append(
                    "No valid or safe JSON payload could be extracted from the content."
                )
        else:
            failures.append(f"Invalid payload type: {type(payload)}")

        if not data:
            return {
                "passed": False,
                "score_matrix": score_matrix,
                "failures_checklist": failures,
                "audit_summary": {"error": "Missing or invalid payload"},
            }

        # 1. Status verification
        status = data.get("status")
        if status == "SUCCESS":
            score_matrix["status_success"] = 1
        else:
            failures.append(f"Expected status 'SUCCESS', but got '{status}'.")

        # 2. Schema conformity check (formal validation: types, ranges & structure)
        schema_errors = self.validate_schema(data)
        if not schema_errors:
            score_matrix["schema_conformity"] = 1
        else:
            failures.extend(schema_errors)

        # 3. Error list check
        errors = data.get("errors", [])
        if isinstance(errors, list) and len(errors) == 0:
            score_matrix["no_errors"] = 1
        else:
            failures.append(f"Agent reported execution errors: {errors}")

        # Phase 2: Semantic Content Sanitization (PII/Secrets Detection & HTML Escaping)
        data_table = data.get("data_table", "")
        if isinstance(data_table, str):
            secrets = ContentSanitizer.detect_pii_or_secrets(data_table)
            if secrets:
                failures.extend(secrets)

            # Sanitize output by escaping HTML to prevent XSS
            data["data_table"] = ContentSanitizer.escape_html(data_table)

        # 4. Data integrity verification (cross-validation)
        metrics = data.get("metrics", {})
        if isinstance(metrics, dict):
            metric_missing = [
                f for f in self.MANDATORY_METRIC_FIELDS if f not in metrics
            ]
            if metric_missing:
                failures.append(f"Missing metrics fields: {metric_missing}")
            else:
                rows_processed = metrics.get("rows_processed", 0)
                error_count = metrics.get("error_count", 0)
                if type(rows_processed) is not int or rows_processed < 0:
                    failures.append(f"Invalid rows_processed: {rows_processed}")
                elif type(error_count) is not int or error_count != 0:
                    failures.append(
                        f"error_count must be 0 for SUCCESS status, found {error_count}"
                    )
                else:
                    data_table = data.get("data_table", "")
                    if rows_processed > 0:
                        if not isinstance(data_table, str) or not data_table.strip():
                            failures.append(
                                "data_table must not be empty when rows_processed > 0"
                            )
                        else:
                            table_rows = [
                                line.strip()
                                for line in data_table.strip().split("\n")
                                if line.strip() and "|" in line
                            ]
                            if len(table_rows) < 3:
                                failures.append(
                                    f"data_table must contain markdown header, separator, and data rows when rows_processed > 0 (found {len(table_rows)} rows)"
                                )
                            else:
                                score_matrix["data_integrity"] = 1
                    else:
                        score_matrix["data_integrity"] = 1
        else:
            failures.append("'metrics' must be a dictionary.")

        passed = len(failures) == 0

        return {
            "passed": passed,
            "score_matrix": score_matrix,
            "failures_checklist": failures,
            "audit_summary": {
                "task_id": data.get("task_id"),
                "rows_processed": (
                    data.get("metrics", {}).get("rows_processed", 0)
                    if isinstance(data.get("metrics"), dict)
                    else 0
                ),
                "audit_trail_length": (
                    len(data.get("audit_trail", []))
                    if isinstance(data.get("audit_trail"), list)
                    else 0
                ),
            },
        }

    def verify_master_result(
        self, master_result: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Holistic Signoff Agent verification across all aggregated Engage agent sub-tasks.
        Verifies:
        - Did all n agents finish with SUCCESS?
        - Is combined data consistent and error-free?
        - Does aggregate work fulfill high-level objective requirements?
        """
        failures: List[str] = []
        score_matrix = {
            "json_validity": 0,
            "all_tasks_success": 0,
            "decomposition_coverage": 0,
            "data_integrity": 0,
        }

        data: Optional[Dict[str, Any]] = None
        if isinstance(master_result, dict):
            data = master_result
            score_matrix["json_validity"] = 1
        elif isinstance(master_result, str):
            data = self._extract_json_payload(master_result)
            if data is not None:
                score_matrix["json_validity"] = 1
            else:
                failures.append("Failed to decode Master Result JSON.")
        else:
            failures.append("Invalid master_result data type.")

        if not data:
            return {
                "passed": False,
                "verdict": "FAIL",
                "score_matrix": score_matrix,
                "failures_checklist": failures,
                "summary": {},
            }

        sub_tasks = data.get("sub_tasks", [])
        if not isinstance(sub_tasks, list) or len(sub_tasks) == 0:
            failures.append("Master Result contains no executed sub-tasks.")
        else:
            score_matrix["decomposition_coverage"] = 1

            all_ok = True
            total_rows = 0
            for idx, task in enumerate(sub_tasks):
                task_res = self.verify_skill_output(task.get("result", {}))
                if not task_res["passed"]:
                    all_ok = False
                    failures.append(
                        f"Sub-task [{task.get('task_id', idx)}] verification failed: {task_res['failures_checklist']}"
                    )
                total_rows += task_res.get("audit_summary", {}).get("rows_processed", 0)

            if all_ok:
                score_matrix["all_tasks_success"] = 1
                score_matrix["data_integrity"] = 1

        passed = len(failures) == 0 and score_matrix["all_tasks_success"] == 1
        verdict = "PASS" if passed else "FAIL"

        return {
            "passed": passed,
            "verdict": verdict,
            "score_matrix": score_matrix,
            "failures_checklist": failures,
            "summary": {
                "run_id": data.get("run_id"),
                "total_sub_tasks": len(sub_tasks) if isinstance(sub_tasks, list) else 0,
                "objective": data.get("objective"),
            },
        }

    def verify_content(self, content: str) -> Dict[str, Any]:
        """
        Backwards-compatible API. Verifies content against strict schema and integrity.
        Supports both single skill output and master result structures.
        """
        parsed = self._extract_json_payload(content)
        if parsed and "sub_tasks" in parsed:
            return self.verify_master_result(parsed)
        return self.verify_skill_output(content)


def main():
    """
    CLI entry point for the Auditor assertion engine.
    Usage: python eval_template.py <file_path> [--master]
    """
    if len(sys.argv) < 2:
        print(
            json.dumps(
                {
                    "error": "No file path provided. Usage: python eval_template.py <file_path>"
                },
                indent=2,
            )
        )
        sys.exit(1)

    file_path = sys.argv[1]
    is_master = "--master" in sys.argv

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        engine = AuditorAssertionEngine()
        if is_master:
            result = engine.verify_master_result(content)
        else:
            result = engine.verify_content(content)

        print(json.dumps(result, indent=2))

        if not result["passed"]:
            sys.exit(1)

    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {file_path}"}, indent=2))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"An error occurred: {str(e)}"}, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
