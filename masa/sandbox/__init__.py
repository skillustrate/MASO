"""
MASO Sandboxing subsystem (v1.1.0).
Provides multi-engine OCI containment, mailbox staging, and execution audit logging.
"""

from masa.sandbox.audit import AuditLogger
from masa.sandbox.base import ExecutionResult, SandboxConfig, SandboxDriver
from masa.sandbox.docker import DockerSandboxDriver
from masa.sandbox.egress import (
    DeniedIpError,
    DomainNotAllowlistedError,
    EgressProxyServer,
    PortForbiddenError,
    RawIpForbiddenError,
    SSRFSecurityViolation,
    is_domain_allowlisted,
    is_ip_denied,
    is_raw_ip,
    resolve_and_pin_domain,
)
from masa.sandbox.local_process import LocalProcessSandboxDriver
from masa.sandbox.manager import SandboxManager
from masa.sandbox.podman import PodmanSandboxDriver
from masa.sandbox.supply_chain import (
    SupplyChainVerificationError,
    UnsignedImageError,
    VulnerabilityScanError,
    scan_image_vulnerabilities,
    sign_image_digest,
    verify_image_signature,
)
from masa.sandbox.setup_podman import (
    build_sandbox_images,
    detect_os_info,
    get_install_plan,
    run_guided_podman_setup,
)

__all__ = [
    "SandboxConfig",
    "ExecutionResult",
    "SandboxDriver",
    "PodmanSandboxDriver",
    "DockerSandboxDriver",
    "LocalProcessSandboxDriver",
    "SandboxManager",
    "AuditLogger",
    "EgressProxyServer",
    "resolve_and_pin_domain",
    "is_ip_denied",
    "is_raw_ip",
    "is_domain_allowlisted",
    "SSRFSecurityViolation",
    "DeniedIpError",
    "RawIpForbiddenError",
    "DomainNotAllowlistedError",
    "PortForbiddenError",
    "verify_image_signature",
    "sign_image_digest",
    "scan_image_vulnerabilities",
    "SupplyChainVerificationError",
    "UnsignedImageError",
    "VulnerabilityScanError",
    "run_guided_podman_setup",
    "detect_os_info",
    "get_install_plan",
    "build_sandbox_images",
]
