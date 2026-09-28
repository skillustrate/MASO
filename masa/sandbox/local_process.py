"""
Local process sandbox driver for MASO (v1.1.0).
Provides best-effort resource bounding with POSIX resource.setrlimit per REVISED §7.2.
Requires explicit '--i-understand-the-risks' flag.
"""

import json
import os
import resource
import signal
import subprocess
import sys
import time
from typing import Optional

from masa.sandbox.audit import AuditLogger, compute_file_sha256
from masa.sandbox.base import ExecutionResult, SandboxConfig, SandboxDriver


class LocalProcessSandboxDriver(SandboxDriver):
    """
    Best-effort local process isolation with resource limits.
    Provides NO filesystem, network, or capability isolation.
    """

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger or AuditLogger()

    def is_available(self) -> bool:
        """Local process driver is always available on POSIX systems."""
        return True

    def _parse_memory_bytes(self, mem_str: str) -> int:
        """Parse memory limit string (e.g. '512m', '1g') to integer bytes."""
        mem_str = mem_str.strip().lower()
        if mem_str.endswith("g"):
            return int(float(mem_str[:-1]) * 1024 * 1024 * 1024)
        if mem_str.endswith("m"):
            return int(float(mem_str[:-1]) * 1024 * 1024)
        if mem_str.endswith("k"):
            return int(float(mem_str[:-1]) * 1024)
        try:
            return int(mem_str)
        except ValueError:
            return 512 * 1024 * 1024

    def _make_preexec(self, config: SandboxConfig):
        """Construct preexec_fn setting POSIX rlimits and process group."""
        mem_bytes = self._parse_memory_bytes(config.memory_limit)
        fsize_bytes = config.max_output_bytes
        cpu_seconds = max(1, int(config.timeout_seconds))

        def _preexec():
            # Create detached process group so timeouts kill entire child tree
            os.setpgrp()

            # Apply address space limit
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass

            # Apply CPU time limit
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds + 5, cpu_seconds + 10))
            except Exception:
                pass

            # Apply process creation limit
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (config.pids_limit, config.pids_limit))
            except Exception:
                pass

            # Apply file size cap (bounds output disk fill)
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes * 2, fsize_bytes * 2))
            except Exception:
                pass

            # Apply file descriptor limit
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            except Exception:
                pass

        return _preexec

    def run(self, task_dir: str, config: SandboxConfig) -> ExecutionResult:
        if not config.i_understand_the_risks:
            raise RuntimeError(
                "DEGRADED LOCAL EXECUTION REFUSED (REVISED §7.2):\n"
                "Local process execution provides NO filesystem, network, or capability isolation.\n"
                "To acknowledge this risk, specify '--i-understand-the-risks'."
            )

        # Print prominent, non-suppressible warning to stderr per REVISED §7.2
        sys.stderr.write(
            "\n"
            "======================================================================\n"
            " [WARNING: LOCAL DEGRADED EXECUTION - NO CONTAINER ISOLATION]\n"
            " Running skill as an unconfined local host process.\n"
            " The skill CAN access host files (~/.ssh, ~/.aws, .env) and network.\n"
            "======================================================================\n\n"
        )
        sys.stderr.flush()

        abs_task_dir = os.path.abspath(task_dir)
        input_path = os.path.join(abs_task_dir, "input.json")
        output_path = os.path.join(abs_task_dir, "output.json")

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

        input_sha256 = compute_file_sha256(input_path)

        # Locate runner.py and repo root
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        runner_path = os.path.join(base_dir, "runner.py")
        if not os.path.exists(runner_path):
            runner_path = os.path.abspath("runner.py")

        cmd = [sys.executable, runner_path]

        # In local mode, runner reads from WORKSPACE_DIR; override WORKSPACE env
        local_env = dict(os.environ)
        local_env["WORKSPACE"] = abs_task_dir
        local_env["PYTHONUNBUFFERED"] = "1"

        start_time = time.time()
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = -1
        proc = None

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=abs_task_dir,
                env=local_env,
                preexec_fn=self._make_preexec(config),
            )
            stdout, stderr = proc.communicate(timeout=config.timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            if proc:
                try:
                    # Kill entire process group
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    proc.kill()
            stderr = f"Local execution timed out after {config.timeout_seconds} seconds"
        except Exception as e:
            exit_code = 127
            stderr = f"Local process launch error: {str(e)}"

        duration_ms = int((time.time() - start_time) * 1000)

        output_data = None
        output_sha256 = ""
        if os.path.exists(output_path):
            output_sha256 = compute_file_sha256(output_path)
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    output_data = json.load(f)
            except Exception:
                pass

        # Record into audit log with degraded_isolation=True
        self.audit_logger.log_execution(
            run_id=run_id,
            task_id=task_id,
            skill_name=skill_name,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            image_digest="local",
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            degraded_isolation=True,
            egress_allowed=config.allow_network,
            seccomp_profile="none"
        )

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            isolation_mode="local",
            image_digest="local",
            output_data=output_data,
            error_message=stderr if exit_code != 0 else None
        )
