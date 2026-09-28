"""
Mandatory, tamper-evident execution audit log module for MASO (v1.1.0).
Implements append-only hash-chained execution records with 0600 permissions.
"""

import fcntl
import getpass
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file if it exists, otherwise return empty hash."""
    if not os.path.exists(filepath):
        return ""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: Dict[str, Any]) -> str:
    """Return deterministic canonical JSON string with sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class AuditLogger:
    """Manages append-only, tamper-evident execution audit logging with hash chains."""

    def __init__(self, log_path: Optional[str] = None):
        if log_path is None:
            # Default to audit/execution.log relative to MASO root or current workspace
            base_dir = os.environ.get("MASO_HOME", os.getcwd())
            log_dir = os.path.join(base_dir, "audit")
            os.makedirs(log_dir, exist_ok=True)
            self.log_path = os.path.join(log_dir, "execution.log")
        else:
            self.log_path = log_path
            os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)

    def _get_last_hash(self) -> str:
        """Read the last record's hash from the log, or return GENESIS_HASH."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return GENESIS_HASH

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    return GENESIS_HASH
                last_record = json.loads(lines[-1])
                return last_record.get("record_hash", GENESIS_HASH)
        except Exception:
            return GENESIS_HASH

    def log_execution(
        self,
        task_id: str,
        skill_name: str,
        exit_code: int,
        duration_ms: int,
        timed_out: bool = False,
        run_id: str = "run-0",
        skill_version: str = "1.0.0",
        image_digest: str = "unknown",
        input_sha256: str = "",
        output_sha256: str = "",
        peak_memory_mb: float = 0.0,
        degraded_isolation: bool = False,
        egress_allowed: bool = False,
        seccomp_profile: str = "maso-seccomp-profile.json",
        operator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Append an execution record to the audit log under an exclusive lock.
        Computes SHA-256 hash chaining to detect tampering.
        """
        if operator is None:
            try:
                operator = getpass.getuser()
            except Exception:
                operator = "unknown"

        timestamp = datetime.now(timezone.utc).isoformat()

        # Open file with 0600 permissions
        flags = os.O_CREAT | os.O_RDWR | os.O_APPEND
        fd = os.open(self.log_path, flags, 0o600)

        with open(fd, "a+", encoding="utf-8") as f:
            # Acquire exclusive lock to prevent concurrent write collisions
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                # Seek to start to find the real last hash
                f.seek(0)
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    try:
                        last_record = json.loads(lines[-1])
                        previous_hash = last_record.get("record_hash", GENESIS_HASH)
                    except Exception:
                        previous_hash = GENESIS_HASH
                else:
                    previous_hash = GENESIS_HASH

                record_data = {
                    "timestamp": timestamp,
                    "run_id": run_id,
                    "task_id": task_id,
                    "skill_name": skill_name,
                    "skill_version": skill_version,
                    "image_digest": image_digest,
                    "input_sha256": input_sha256,
                    "output_sha256": output_sha256,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "duration_ms": duration_ms,
                    "peak_memory_mb": peak_memory_mb,
                    "degraded_isolation": degraded_isolation,
                    "egress_allowed": egress_allowed,
                    "seccomp_profile": seccomp_profile,
                    "operator": operator,
                    "previous_hash": previous_hash,
                }

                # Compute current record hash: SHA256(previous_hash + canonical_json)
                payload_str = previous_hash + canonical_json(record_data)
                record_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
                record_data["record_hash"] = record_hash

                f.write(json.dumps(record_data) + "\n")
                f.flush()
                return record_data
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify the complete cryptographic hash chain of the audit log.
        Returns: (is_valid, error_list)
        """
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return True, []

        errors = []
        expected_prev_hash = GENESIS_HASH

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception as e:
                    errors.append(f"Line {line_no}: Malformed JSON ({str(e)})")
                    continue

                actual_hash = record.get("record_hash")
                reported_prev = record.get("previous_hash")

                if reported_prev != expected_prev_hash:
                    errors.append(
                        f"Line {line_no}: Broken hash link! Expected previous '{expected_prev_hash}', got '{reported_prev}'"
                    )

                # Recompute hash
                check_data = {k: v for k, v in record.items() if k != "record_hash"}
                payload = reported_prev + canonical_json(check_data)
                recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()

                if recomputed != actual_hash:
                    errors.append(
                        f"Line {line_no}: Tampered record hash! Expected '{recomputed}', got '{actual_hash}'"
                    )

                expected_prev_hash = actual_hash

        return len(errors) == 0, errors

    def get_recent_entries(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Fetch the last N audit log records."""
        if not os.path.exists(self.log_path):
            return []

        entries = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                for line in lines[-limit:]:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        except Exception:
            return []
        return entries
