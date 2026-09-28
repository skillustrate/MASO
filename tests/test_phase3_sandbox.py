"""
Phase 3 (Sprint 3) Verification Test Suite: Docker Parity, Egress Control, and Supply Chain Security.
Implements test coverage for:
- Docker sandbox driver parity with Podman (Task 3.1)
- Egress allowlist proxy, anti-DNS-rebinding, IP pinning, port 443 restriction (Tasks 3.2 - 3.6)
- Seccomp profile variants (offline vs egress) (Task 3.5)
- Supply chain security: pinned digest, Cosign/attestation verification, vulnerability scan gate (Tasks 3.7 - 3.10)
- Audit log tracking of image digest and signature verification status (Task 3.10)
"""

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import tempfile
import pytest

from masa.sandbox.audit import AuditLogger
from masa.sandbox.base import SandboxConfig
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
from masa.sandbox.manager import SandboxManager
from masa.sandbox.podman import PodmanSandboxDriver
from masa.sandbox.supply_chain import (
    UnsignedImageError,
    get_default_sig_path,
    scan_image_vulnerabilities,
    sign_image_digest,
    verify_image_signature,
)


# ==============================================================================
# 1. Docker Driver Containment Parity Tests (WS-B, Task 3.1)
# ==============================================================================

def test_docker_driver_availability_and_health():
    """Verify Docker sandbox driver detects daemon and reports status."""
    driver = DockerSandboxDriver()
    if not driver.is_available():
        pytest.skip("Docker daemon not available on host")

    assert driver.is_available() is True
    digest = driver.get_image_digest("maso-skill-worker:v1.1")
    assert digest != "unknown" and len(digest) > 0


def test_docker_driver_skill_execution_and_audit():
    """Verify Docker driver executes specialist skill inside container with full containment."""
    driver = DockerSandboxDriver()
    if not driver.is_available():
        pytest.skip("Docker daemon not available on host")

    with tempfile.TemporaryDirectory() as td:
        log_path = os.path.join(td, "audit.log")
        logger = AuditLogger(log_path=log_path)
        driver.audit_logger = logger

        # Prepare mailbox input
        input_payload = {
            "task_id": "docker-test-01",
            "run_id": "run-dock-01",
            "skill_name": "data_refinement",
            "parameters": {
                "raw_data": [{"name": "Alpha", "score": 95}, {"name": "Beta", "score": 88}]
            }
        }
        with open(os.path.join(td, "input.json"), "w", encoding="utf-8") as f:
            json.dump(input_payload, f)

        cfg = SandboxConfig(
            runtime="docker",
            image_ref="maso-skill-worker:v1.1",
            timeout_seconds=30
        )
        res = driver.run(td, cfg)

        assert res.exit_code == 0
        assert res.isolation_mode == "docker"
        assert res.timed_out is False
        assert res.output_data is not None
        assert res.output_data.get("status") == "SUCCESS"

        # Verify audit record
        assert os.path.exists(log_path)
        is_valid, errors = logger.verify_integrity()
        assert is_valid is True, f"Audit chain errors: {errors}"

        entries = logger.get_recent_entries(limit=1)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["task_id"] == "docker-test-01"
        assert entry["exit_code"] == 0
        assert entry["degraded_isolation"] is False
        assert entry["image_digest"] != "unknown"


def test_docker_driver_timeout_enforcement():
    """Verify Docker driver forcibly kills container on timeout (Task 3.1 & 4.1)."""
    driver = DockerSandboxDriver()
    if not driver.is_available():
        pytest.skip("Docker daemon not available on host")

    with tempfile.TemporaryDirectory() as td:
        log_path = os.path.join(td, "audit.log")
        logger = AuditLogger(log_path=log_path)
        driver.audit_logger = logger

        input_payload = {
            "task_id": "docker-timeout-01",
            "run_id": "run-dock-timeout",
            "skill_name": "sleep_test",
            "parameters": {"sleep_seconds": 10}
        }
        with open(os.path.join(td, "input.json"), "w", encoding="utf-8") as f:
            json.dump(input_payload, f)

        cfg = SandboxConfig(
            runtime="docker",
            image_ref="maso-skill-worker:v1.1",
            timeout_seconds=2
        )
        res = driver.run(td, cfg)

        assert res.timed_out is True
        assert res.exit_code == 124
        assert "timed out" in res.stderr.lower()

        # Audit record must record timeout
        entries = logger.get_recent_entries(limit=1)
        assert entries[0]["timed_out"] is True
        assert entries[0]["exit_code"] == 124


def test_sandbox_manager_docker_routing():
    """Verify SandboxManager resolves Docker driver when runtime is docker."""
    mgr = SandboxManager()
    cfg = SandboxConfig(runtime="docker")
    driver = mgr.get_driver(cfg)
    assert isinstance(driver, DockerSandboxDriver)


# ==============================================================================
# 2. Egress Allowlist & Anti-SSRF Test Matrix (WS-D, Tasks 3.2 - 3.6)
# ==============================================================================

def test_egress_raw_ip_rejection():
    """Task 3.6: Verify raw IP addresses in decimal, octal, hex, or standard format are rejected."""
    # Standard IPv4 and IPv6
    assert is_raw_ip("127.0.0.1") is True
    assert is_raw_ip("169.254.169.254") is True
    assert is_raw_ip("::1") is True
    assert is_raw_ip("[::1]") is True

    # Decimal integer IP literals (e.g. 2130706433 for 127.0.0.1, 2852039166 for 169.254.169.254)
    assert is_raw_ip("2130706433") is True
    assert is_raw_ip("2852039166") is True

    # Hexadecimal IP literal
    assert is_raw_ip("0x7f000001") is True

    # Legitimate domains are NOT raw IPs
    assert is_raw_ip("api.example.com") is False
    assert is_raw_ip("registry.hub.docker.com") is False


def test_egress_denied_ip_ranges():
    """Task 3.6: Verify private, loopback, link-local, and cloud metadata IPs are identified as denied."""
    # Loopback
    denied, reason = is_ip_denied("127.0.0.1")
    assert denied is True and "loopback" in reason.lower()

    # IPv6 Loopback
    denied, reason = is_ip_denied("::1")
    assert denied is True and "loopback" in reason.lower()

    # Cloud metadata (169.254.169.254)
    denied, reason = is_ip_denied("169.254.169.254")
    assert denied is True and ("metadata" in reason.lower() or "link-local" in reason.lower())

    # RFC 1918 Private ranges
    assert is_ip_denied("10.0.0.1")[0] is True
    assert is_ip_denied("172.16.5.2")[0] is True
    assert is_ip_denied("192.168.1.1")[0] is True

    # IPv6 ULA and link-local
    assert is_ip_denied("fc00::1")[0] is True
    assert is_ip_denied("fe80::1")[0] is True

    # Public IP must pass
    denied, _ = is_ip_denied("8.8.8.8")
    assert denied is False
    denied, _ = is_ip_denied("93.184.216.34")
    assert denied is False


def test_egress_port_restriction_matrix():
    """Task 3.6: Only port 443 is permitted. Non-443 ports (80, 8080, 22) must be blocked."""
    allowlist = ["api.example.com"]
    
    # Port 80 -> blocked
    with pytest.raises(PortForbiddenError) as exc_info:
        resolve_and_pin_domain("api.example.com", allowlist, port=80)
    assert "port 80 is forbidden" in str(exc_info.value).lower()

    # Port 8080 -> blocked
    with pytest.raises(PortForbiddenError):
        resolve_and_pin_domain("api.example.com", allowlist, port=8080)

    # Port 22 -> blocked
    with pytest.raises(PortForbiddenError):
        resolve_and_pin_domain("api.example.com", allowlist, port=22)


def test_egress_domain_allowlist_enforcement():
    """Task 3.6: Reject domains not listed in the egress allowlist."""
    allowlist = ["api.example.com", "*.trusted.org"]

    assert is_domain_allowlisted("api.example.com", allowlist) is True
    assert is_domain_allowlisted("sub.trusted.org", allowlist) is True
    assert is_domain_allowlisted("malicious-site.com", allowlist) is False

    with pytest.raises(DomainNotAllowlistedError):
        resolve_and_pin_domain("evil.com", allowlist, port=443)


def test_egress_anti_dns_rebinding_simulation():
    """Task 3.6: Reject allowlisted domain that rebinds to loopback or cloud metadata."""
    allowlist = ["rebinding.example.com"]

    # Mock resolver returning loopback 127.0.0.1
    def mock_rebinding_loopback(domain, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    with pytest.raises(DeniedIpError) as exc_info:
        resolve_and_pin_domain(
            "rebinding.example.com",
            allowlist,
            port=443,
            custom_resolver=mock_rebinding_loopback
        )
    assert "dns rebinding / ssrf attempt detected" in str(exc_info.value).lower()
    assert "127.0.0.1" in str(exc_info.value)

    # Mock resolver returning cloud metadata 169.254.169.254
    def mock_rebinding_metadata(domain, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    with pytest.raises(DeniedIpError) as exc_info:
        resolve_and_pin_domain(
            "rebinding.example.com",
            allowlist,
            port=443,
            custom_resolver=mock_rebinding_metadata
        )
    assert "169.254.169.254" in str(exc_info.value)


def test_egress_successful_pinning():
    """Task 3.6: Valid public domain pins the resolved public IP."""
    allowlist = ["public.example.com"]

    def mock_public_resolver(domain, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    pinned_ip = resolve_and_pin_domain(
        "public.example.com",
        allowlist,
        port=443,
        custom_resolver=mock_public_resolver
    )
    assert pinned_ip == "93.184.216.34"


def test_egress_proxy_server_connect_rejections():
    """Task 3.6: Test EgressProxyServer async client interactions."""
    async def run_proxy_checks():
        server = EgressProxyServer(host="127.0.0.1", port=0, allowlist=["api.allowed.com"])
        await server.start()
        port = server.listening_port

        try:
            # 1. Plain HTTP request -> Rejected 403
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await writer.drain()
            resp = await reader.read(1024)
            assert b"403 Forbidden" in resp
            assert b"Plain HTTP" in resp
            writer.close()
            await writer.wait_closed()

            # 2. CONNECT with raw IP -> Rejected 403
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
            await writer.drain()
            resp = await reader.read(1024)
            assert b"403 Forbidden" in resp
            assert b"RawIpForbiddenError" in resp
            writer.close()
            await writer.wait_closed()

            # 3. CONNECT with forbidden port 80 -> Rejected 403
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT api.allowed.com:80 HTTP/1.1\r\nHost: api.allowed.com:80\r\n\r\n")
            await writer.drain()
            resp = await reader.read(1024)
            assert b"403 Forbidden" in resp
            assert b"PortForbiddenError" in resp
            writer.close()
            await writer.wait_closed()

            # 4. CONNECT with non-allowlisted domain -> Rejected 403
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"CONNECT untrusted.org:443 HTTP/1.1\r\nHost: untrusted.org:443\r\n\r\n")
            await writer.drain()
            resp = await reader.read(1024)
            assert b"403 Forbidden" in resp
            assert b"DomainNotAllowlistedError" in resp
            writer.close()
            await writer.wait_closed()

        finally:
            await server.stop()

    asyncio.run(run_proxy_checks())


def test_seccomp_profile_variants():
    """Task 3.5: Verify offline seccomp profile denies socket syscalls, and egress variant allows them."""
    with open("maso-seccomp-offline.json", "r", encoding="utf-8") as f:
        offline_data = json.load(f)
    with open("maso-seccomp-egress.json", "r", encoding="utf-8") as f:
        egress_data = json.load(f)

    offline_allowed = set(offline_data["syscalls"][0]["names"])
    egress_allowed = set(egress_data["syscalls"][0]["names"])

    # Offline profile MUST NOT allow socket and connect
    assert "socket" not in offline_allowed
    assert "connect" not in offline_allowed

    # Egress profile MUST allow socket and connect
    assert "socket" in egress_allowed
    assert "connect" in egress_allowed


# ==============================================================================
# 3. Supply Chain Security Tests (WS-F, Tasks 3.7 - 3.10)
# ==============================================================================

def test_containerfile_pinned_digest():
    """Task 3.7: Verify Containerfile.worker uses an immutable base image pinned by sha256 digest."""
    with open("Containerfile.worker", "r", encoding="utf-8") as f:
        content = f.read()

    assert "FROM python:3.13-slim-bookworm@sha256:" in content


def test_supply_chain_signature_verification():
    """Task 3.8: Verify valid cryptographic signature passes and unsigned/tampered image fails."""
    # Test valid signing & verification
    test_digest = "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    with tempfile.TemporaryDirectory() as td:
        sig_file = os.path.join(td, "test.sig")
        sign_image_digest(test_digest, output_file=sig_file)

        # 1. Valid signature check
        valid, msg = verify_image_signature("my-image:v1", image_digest=test_digest, sig_path=sig_file)
        assert valid is True
        assert "verified" in msg.lower()

        # 2. Tampered / mismatched digest
        tampered_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
        valid, msg = verify_image_signature("my-image:v1", image_digest=tampered_digest, sig_path=sig_file)
        assert valid is False
        assert "mismatch" in msg.lower()

        # 3. Non-existent signature file (unsigned)
        valid, msg = verify_image_signature("my-image:v1", image_digest=test_digest, sig_path=os.path.join(td, "missing.sig"))
        assert valid is False
        assert "unsigned" in msg.lower()


def test_driver_refuses_unsigned_image_when_signature_required():
    """Task 3.8: Driver must refuse execution when require_signature=True on unsigned image."""
    driver = PodmanSandboxDriver()
    if not driver.is_available():
        pytest.skip("Podman not available")

    with tempfile.TemporaryDirectory() as td:
        log_path = os.path.join(td, "audit.log")
        logger = AuditLogger(log_path=log_path)
        driver.audit_logger = logger

        input_payload = {
            "task_id": "unsigned-test",
            "run_id": "run-unsigned",
            "skill_name": "data_refinement",
            "parameters": {"raw_data": []}
        }
        with open(os.path.join(td, "input.json"), "w", encoding="utf-8") as f:
            json.dump(input_payload, f)

        # Point to an invalid/non-existent signature file
        cfg = SandboxConfig(
            runtime="podman",
            image_ref="maso-skill-worker:v1.1",
            require_signature=True,
            signature_file=os.path.join(td, "non_existent.sig")
        )

        res = driver.run(td, cfg)

        # Must be rejected with exit code 126
        assert res.exit_code == 126
        assert "SUPPLY CHAIN REFUSAL" in res.error_message

        # Audit record must record signature_verified=False
        entries = logger.get_recent_entries(limit=1)
        assert entries[0]["signature_verified"] is False
        assert entries[0]["exit_code"] == 126


def test_vulnerability_scan_gate():
    """Task 3.9: Test Trivy/Grype vulnerability scan gate."""
    # Pinned image passes baseline check
    passed, vulns, msg = scan_image_vulnerabilities("maso-skill-worker:v1.1")
    assert passed is True
