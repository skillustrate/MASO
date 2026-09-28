"""
Base interfaces and data structures for the MASO Sandbox subsystem (v1.1.0).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SandboxConfig:
    """Configuration parameters for sandbox execution."""
    runtime: str = "auto"
    memory_limit: str = "512m"
    cpus: float = 1.0
    pids_limit: int = 50
    timeout_seconds: int = 120
    allow_network: bool = False
    max_output_bytes: int = 10485760  # 10 MiB default cap
    image_ref: str = "maso-skill-worker:v1.1"
    seccomp_profile: Optional[str] = None
    i_understand_the_risks: bool = False
    extra_env: Dict[str, str] = field(default_factory=dict)
    require_signature: bool = False
    signature_file: Optional[str] = None
    public_key_path: Optional[str] = None


@dataclass
class ExecutionResult:
    """Normalized execution telemetry and output from a sandbox driver."""
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    peak_memory_mb: float = 0.0
    isolation_mode: str = "podman"
    image_digest: Optional[str] = None
    error_message: Optional[str] = None
    output_data: Optional[Dict[str, Any]] = None


class SandboxDriver(ABC):
    """Abstract Base Class for sandbox isolation drivers."""

    @abstractmethod
    def run(self, task_dir: str, config: SandboxConfig) -> ExecutionResult:
        """
        Execute a specialist skill task inside the sandbox isolation boundary.

        Args:
            task_dir: Directory containing input.json and receiving output.json
            config: Sandbox resource limits and security constraints

        Returns:
            ExecutionResult containing execution metrics and exit status
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the driver runtime is installed and operational."""
        pass
