"""
Rootless Podman sandbox driver for MASO (v1.1.0).
Implements hardened, daemonless container containment per REVISED §5.4.
"""

import json
import os
import shutil
import subprocess
import time
import uuid
from typing import Any, Dict, Optional

from masa.sandbox.audit import AuditLogger, compute_file_sha256
from masa.sandbox.base import ExecutionResult, SandboxConfig, SandboxDriver


class PodmanSandboxDriver(SandboxDriver):
    """Executes specialist skills within a rootless Podman container boundary."""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger or AuditLogger()

    def is_available(self) -> bool:
        """Check if podman binary is present on the host PATH."""
        return shutil.which("podman") is not None

    def get_image_digest(self, image_ref: str) -> str:
        """Retrieve the immutable inspect digest or image ID."""
        try:
            res = subprocess.run(
                ["podman", "image", "inspect", image_ref, "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
        return "unknown"

    def run(self, task_dir: str, config: SandboxConfig) -> ExecutionResult:
        """
        Execute skill inside a hardened rootless Podman container.
        """
        abs_task_dir = os.path.abspath(task_dir)
        input_path = os.path.join(abs_task_dir, "input.json")
        output_path = os.path.join(abs_task_dir, "output.json")

        # Read task metadata from input.json for audit and dispatch
        task_id = "task-unknown"
        skill_name = "unknown"
        run_id = "run-0"
        if os.path.exists(input_path):
            try:
                with open(input_path, "r", encoding="utf-8") as f:
                    in_data = json.load(f)
                    task_id = in_data.get("task_id", task_id)
                    skill_name = in_data.get("skill_name", skill_name)
                    run_id = in_data.get("run_id", run_id)
            except Exception:
                pass

        # Compute input hash for tamper-evident audit record
        input_sha256 = compute_file_sha256(input_path)

        # Ensure container user UID 10001 has RW permissions to task_dir
        try:
            os.chmod(abs_task_dir, 0o777)
        except Exception:
            pass

        container_name = f"maso-worker-{task_id}-{uuid.uuid4().hex[:8]}"

        # Construct reconciled command (REVISED §5.4)
        cmd = [
            "podman", "run",
            "--rm",
            "--name", container_name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            f"--memory={config.memory_limit}",
            f"--memory-swap={config.memory_limit}",
            f"--cpus={config.cpus}",
            f"--pids-limit={config.pids_limit}",
            "--user=10001:10001",
            "--volume", f"{abs_task_dir}:/workspace:rw",
        ]

        if not config.allow_network:
            cmd.append("--network=none")

        # Apply custom seccomp profile if configured
        seccomp_file = config.seccomp_profile
        if not seccomp_file:
            # Default lookup in repo root
            candidate = os.path.join(os.getcwd(), "maso-seccomp-profile.json")
            if os.path.exists(candidate):
                seccomp_file = candidate

        if seccomp_file and os.path.exists(seccomp_file):
            cmd.append(f"--security-opt=seccomp={os.path.abspath(seccomp_file)}")

        cmd.append(config.image_ref)

        start_time = time.time()
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = -1

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(timeout=config.timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            # Forcibly terminate the container
            subprocess.run(["podman", "kill", container_name], capture_output=True, check=False)
            subprocess.run(["podman", "rm", "-f", container_name], capture_output=True, check=False)
            stderr = f"Execution timed out after {config.timeout_seconds} seconds"
        except Exception as e:
            exit_code = 127
            stderr = f"Driver invocation error: {str(e)}"

        duration_ms = int((time.time() - start_time) * 1000)

        # Inspect output if produced
        output_data = None
        output_sha256 = ""
        if os.path.exists(output_path):
            output_sha256 = compute_file_sha256(output_path)
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    output_data = json.load(f)
            except Exception:
                pass

        image_digest = self.get_image_digest(config.image_ref)

        # Mandatory execution audit record (NEW §11)
        self.audit_logger.log_execution(
            run_id=run_id,
            task_id=task_id,
            skill_name=skill_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            image_digest=image_digest,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            degraded_isolation=False,
            egress_allowed=config.allow_network,
            seccomp_profile=os.path.basename(seccomp_file) if seccomp_file else "default"
        )

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            isolation_mode="podman",
            image_digest=image_digest,
            output_data=output_data,
            error_message=stderr if exit_code != 0 else None
        )
