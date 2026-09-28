"""
Sandbox Manager and engine discovery for MASO (v1.1.0).
Implements fail-closed graceful degradation per REVISED §7.2.
"""

import shutil
import subprocess
from typing import Any, Dict, Optional

from masa.sandbox.audit import AuditLogger
from masa.sandbox.base import ExecutionResult, SandboxConfig, SandboxDriver
from masa.sandbox.docker import DockerSandboxDriver
from masa.sandbox.local_process import LocalProcessSandboxDriver
from masa.sandbox.podman import PodmanSandboxDriver


class SandboxManager:
    """Dispatches execution across container drivers with fail-closed governance."""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger or AuditLogger()
        self.podman_driver = PodmanSandboxDriver(self.audit_logger)
        self.docker_driver = DockerSandboxDriver(self.audit_logger)
        self.local_driver = LocalProcessSandboxDriver(self.audit_logger)

    def detect_available_runtime(self) -> str:
        """Probe host for installed container runtimes in priority order."""
        if shutil.which("podman") is not None:
            return "podman"
        if shutil.which("docker") is not None:
            return "docker"
        return "none"

    def is_podman_rootless(self) -> bool:
        """Check if Podman is running in rootless mode."""
        try:
            res = subprocess.run(
                ["podman", "info", "--format", "{{.Host.Security.Rootless}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            return res.stdout.strip().lower() == "true"
        except Exception:
            return False

    def get_driver(self, config: SandboxConfig) -> SandboxDriver:
        """
        Resolve the appropriate SandboxDriver based on user config and host capabilities.
        Enforces fail-closed policy (REVISED §7.2).
        """
        target_runtime = config.runtime

        if target_runtime == "auto":
            detected = self.detect_available_runtime()
            if detected == "none":
                raise RuntimeError(
                    "FAIL-CLOSED SECURITY ENFORCEMENT (REVISED §7.2):\n"
                    "No container runtime (Podman or Docker) was detected on the host.\n"
                    "MASO refuses to execute untrusted specialist skills unconfined.\n\n"
                    "Remediation:\n"
                    "  1. Install Podman: sudo apt install podman (recommended rootless daemonless)\n"
                    "  2. Install Docker: sudo apt install docker.io\n"
                    "  3. Explicit Override: pass '--sandbox local --i-understand-the-risks' to run locally with best-effort bounds."
                )
            target_runtime = detected

        if target_runtime == "podman":
            if not self.podman_driver.is_available():
                raise RuntimeError("Podman runtime requested but 'podman' binary was not found on PATH.")
            return self.podman_driver

        if target_runtime == "docker":
            if not self.docker_driver.is_available():
                raise RuntimeError("Docker runtime requested but 'docker' binary was not found or daemon is not responding.")
            return self.docker_driver

        if target_runtime == "local":
            if not config.i_understand_the_risks:
                raise RuntimeError(
                    "DEGRADED LOCAL EXECUTION REFUSED:\n"
                    "Local process fallback provides NO filesystem, network, or capability isolation.\n"
                    "To proceed, you must pass '--i-understand-the-risks'."
                )
            return self.local_driver

        raise ValueError(f"Unknown sandbox runtime mode: '{target_runtime}'")

    def run(self, task_dir: str, config: SandboxConfig) -> ExecutionResult:
        """Resolve driver and run task inside the sandbox."""
        driver = self.get_driver(config)
        return driver.run(task_dir, config)

    def health_check(self) -> Dict[str, Any]:
        """Audit status of sandbox runtime, worker image, and audit log."""
        runtime = self.detect_available_runtime()
        rootless = False
        image_digest = "unknown"
        if runtime == "podman":
            rootless = self.is_podman_rootless()
            image_digest = self.podman_driver.get_image_digest("maso-skill-worker:v1.1")
        elif runtime == "docker":
            rootless = self.docker_driver.is_rootless()
            image_digest = self.docker_driver.get_image_digest("maso-skill-worker:v1.1")

        is_valid_chain, errors = self.audit_logger.verify_integrity()
        recent_entries = self.audit_logger.get_recent_entries(limit=5)

        return {
            "runtime": runtime,
            "rootless": rootless,
            "worker_image": "maso-skill-worker:v1.1",
            "image_digest": image_digest,
            "seccomp_profile": "maso-seccomp-profile.json",
            "audit_log_path": self.audit_logger.log_path,
            "audit_log_entries": len(recent_entries),
            "audit_chain_valid": is_valid_chain,
            "audit_errors": errors
        }
