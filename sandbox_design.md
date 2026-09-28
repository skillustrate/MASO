# MASA / MASO Sandbox Architecture Design
**Document Version:** 1.1.0 Final  
**Framework:** MASO / MASA  
**Status:** Approved Architectural Specification & Verified Implementation  
**Release Date:** 2026-09-28  

---

## 1. Executive Summary & Problem Statement

### 1.1 The Threat Model of Host-Resident Autonomous Agents
Modern agentic architectures execute complex tasks by delegating sub-problems to specialist models ("Engage Agents"), generating dynamic code, shell invocations, or data transformations. Running these operations directly on the host operating system creates critical security vulnerabilities:
1. **Arbitrary Code Execution & System Mutation:** LLM-generated scripts or unvetted skill implementations can delete files, overwrite system libraries, or spawn background daemons.
2. **Credential & Secret Exfiltration:** An injected or compromised specialist agent can scan the host filesystem (`~/.ssh`, `~/.aws`, `.env`, OS Keyring) and exfiltrate credentials over outbound HTTP/DNS sockets.
3. **Resource Starvation (DoS):** Infinite recursion, unmetered loops, or memory leaks can exhaust host CPU, RAM, and file descriptors.
4. **Prompt Injection Escape:** Malicious user inputs or scraped web content can trigger tool executions that breach workspace boundaries.

### 1.2 The Dilemma: Host Tooling vs. Sandboxed Execution
A naive sandbox running the *entire* agent inside an isolated VM or container breaks client subscription workflows:
- Local subscription CLIs (`claude`, `agy`, `gh copilot`) rely on host-authenticated sessions, local OAuth tokens, and system keyrings.
- Local AI backends (e.g., LM Studio, Ollama) bind to `localhost` or host sockets.
- The user expects the agent to orchestrate their host development workflow without requiring them to mount raw credentials into an untrusted container.

### 1.3 The Solution: The "Split Sandbox" Architecture
The **Split Sandbox** architecture decouples the **Control Plane** (Super Agent / Orchestrator) from the **Execution Plane** (Engage Agents / Specialist Workers):
- **Host Control Plane:** The Orchestrator runs locally with access to user subscription tools, LM Studio, and the secure OS Keyring.
- **Isolated Execution Plane:** Skill execution and dynamic agent computations occur inside disposable, non-root, strictly constrained Podman/Docker containers.
- **Host Verification Plane:** The Signoff Agent (`AuditorAssertionEngine`) deterministically inspects and sanitizes all generated outputs before admitting them back to the host filesystem.

---

## 2. Architectural Overview

```mermaid
flowchart TD
    subgraph Host ["HOST MACHINE (Trusted Control Plane)"]
        User["Client / Terminal Invocation"] --> FrameworkCLI["masa / maso CLI (`masa/framework.py`)"]
        FrameworkCLI --> Orchestrator["Super Agent (`MultiAgentFramework`)"]
        
        subgraph SubMgr ["Subscription & Secret Layer"]
            SubManager["SubscriptionManager"]
            Keyring["OS Keyring (Fernet / AES-256)"]
            LocalCLIs["Local CLIs (claude, agy, copilot, LM Studio)"]
            SubManager --- Keyring
            SubManager --- LocalCLIs
        end
        Orchestrator <--> SubMgr
        
        subgraph MailboxHost ["Host File System (Isolated Mailbox)"]
            HostTaskDir["`mailboxes/<run_id>/tasks/<task_id>/`"]
            InputFile["`input.json` (Sanitized Input)"]
            OutputFile["`output.json` (Untrusted Output)"]
            HostTaskDir --- InputFile
            HostTaskDir --- OutputFile
        end
        Orchestrator -->|"1. Prepare Task & Clean Secrets (Defense-in-Depth)"| InputFile
        
        subgraph Auditor ["Signoff & Verification Plane"]
            AssertionEngine["AuditorAssertionEngine (Structural Validator)"]
            Sanitizer["ContentSanitizer"]
            AuditLog["Tamper-Evident Audit Log (`audit/execution.log`)"]
        end
        OutputFile -->|"3. Read Output (Post-exit 0 only)"| AssertionEngine
        AssertionEngine --> Sanitizer
        Sanitizer -->|"4. Commit Master Result"| MasterResult["`mailboxes/<run_id>/master_result.json`"]
    end

    subgraph ContainerSpace ["CONTAINER BOUNDARY (Isolated Execution Plane)"]
        subgraph WorkerContainer ["Hardened Worker (`maso-skill-worker:v1.1.0`)"]
            Runner["In-Image Dispatcher (`runner.py`)"]
            Registry["In-Image Registry (`/opt/skills/<skill>/`)"]
            WorkerWorkspace["Mounted Workspace (`/workspace`)"]
            Runner --> Registry
            WorkerWorkspace --- InContainerInput["`/workspace/input.json`"]
            WorkerWorkspace --- InContainerOutput["`/workspace/output.json`"]
            Runner -->|"Read Parameters"| InContainerInput
            Runner -->|"Atomic Write (Bounded Cap)"| InContainerOutput
        end
    end

    HostTaskDir ===|"Single Read-Write Bind Mount"| WorkerWorkspace
    Orchestrator -->|"2. Spawn Container (Podman/Docker)"| WorkerContainer
    WorkerContainer -.->|"5. Mandatory Telemetry & Hash Chain"| AuditLog
```

---

## 3. Sandboxing Technology Stack & Engine Support

The MASO architecture supports both daemonless rootless **Podman** and **Docker Engine**, unified under the abstract `SandboxDriver` interface:

| Runtime Driver | Execution Mechanism | Rootless Mode | Daemon Requirement |
| :--- | :--- | :--- | :--- |
| **Podman** (`PodmanSandboxDriver`) | Fork/exec via `conmon` / `crun` | Yes (UID 10001 in user namespace) | Daemonless (No background service) |
| **Docker** (`DockerSandboxDriver`) | `containerd` via `dockerd` | Yes / Rootful (UID 10001) | System daemon (`dockerd`) |
| **Local Fallback** (`LocalProcessDriver`) | Subprocess with POSIX `setrlimit` | Unisolated host process | None (Explicit `--i-understand-the-risks`) |

---

## 4. Mailbox Protocol & File Isolation Boundary

The file-based mailbox is the **sole interface** between host and container.

### 4.1 Atomicity & Concurrency Controls
- **Write Atomicity:** `input.json` is created using `os.O_CREAT | os.O_EXCL | os.O_WRONLY` to prevent TOCTOU race conditions.
- **Locking:** The task directory is locked using POSIX `fcntl.flock(LOCK_EX)` during staging and execution.
- **Output Atomicity:** The worker writes `output.json.tmp`, syncs to disk (`os.fsync`), and renames atomically via `os.replace()`.
- **Auditor Staging:** The Auditor inspects `output.json` **only after** container exit code 0 and verifies that file size does not exceed `max_output_bytes`.

---

## 5. Container Hardening Specification

### 5.1 Reconciled Container Invocation Command (REVISED §5.4)

```bash
podman run \
    --rm \
    --name maso-worker-<task_id> \
    --read-only \
    --network=none \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --security-opt seccomp=/path/to/maso-seccomp-profile.json \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --memory=512m \
    --memory-swap=512m \
    --cpus=1.0 \
    --pids-limit=50 \
    --user=10001:10001 \
    --volume /path/to/mailboxes/<run_id>/tasks/<task_id>:/workspace:rw \
    maso-skill-worker@sha256:<pinned-digest>
```

### 5.2 Hardening Control Summary
- **Read-Only Root (`--read-only`):** System directories cannot be modified.
- **Non-executable Tempfs (`noexec /tmp`):** Prevents executing dropped binaries or JIT-compiled native code.
- **Zero Capabilities (`--cap-drop=ALL`):** Drops all Linux capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`).
- **No Privilege Escalation (`no-new-privileges:true`):** Prevents setuid binary abuse.
- **Custom Seccomp Profile:** Deny-by-default (`SCMP_ACT_ERRNO`); explicitly denies `ptrace`, `mount`, `bpf`, `kexec`, `reboot`, and `io_uring`.

---

## 6. Skill Delivery Contract (NEW §5.5)

Skills are **trusted, versioned code artifacts shipped inside the worker image** — not arbitrary code strings passed in `input.json`.

```
/opt/skills/<skill_name>/
├── manifest.json       # Metadata, limits, entrypoint
└── main.py             # Implementation callable
```

- `input.json` carries **data parameters only**.
- In-container `runner.py` dispatches only from `/opt/skills/`. Unknown skills trigger immediate non-zero exit without generating output.

---

## 7. Network Policy & Egress Control (REVISED §6)

1. **Default Mode:** `--network=none`. No network interfaces other than `lo`.
2. **Opt-in Egress:** Active only when skill manifest specifies `"network_required": true` and user supplies `--allow-network`.
3. **Dedicated Egress Proxy (`maso-egress-proxy:v1.1.0`):**
   - Separate, non-root (`UID 10002`), read-only container holding no credentials.
   - **Self-Resolving IP Pinning:** The proxy performs DNS resolution itself, validates the IP, and connects directly to the pinned IP to block DNS rebinding.
   - **Denied Subnets:** Rejects loopback (`127.0.0.0/8`, `::1`), RFC 1918 private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and link-local / cloud metadata (`169.254.0.0/16`).
   - **Port 443 Only:** Rejects plain HTTP and all non-443 ports.

---

## 8. Graceful Degradation & Fail-Closed Governance (REVISED §7.2)

| Sandbox Setting | Podman Found | Docker Found | None Found |
| :--- | :--- | :--- | :--- |
| `--sandbox auto` *(Default)* | Uses Podman (rootless) | Uses Docker (rootless) | **FAIL CLOSED** (Exit non-zero with remediation guidance) |
| `--sandbox podman` | Uses Podman | Error (Exit 1) | Error (Exit 1) |
| `--sandbox docker` | Error (Exit 1) | Uses Docker | Error (Exit 1) |
| `--sandbox local` | Local fallback (Explicit) | Local fallback (Explicit) | Local fallback (Explicit) |

### Local Fallback Contract
Local execution requires explicit user consent:
```bash
maso run --task "..." --sandbox local --i-understand-the-risks
```
- Emits prominent, non-suppressible warning to `sys.stderr`.
- Enforces POSIX bounds via `resource.setrlimit` (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`).
- Records `degraded_isolation=True` in the tamper-evident audit log.
- `maso status` displays: `Runtime Engine: LOCAL (DEGRADED — no isolation)`.

---

## 9. Structural Auditor & Defense-in-Depth (REVISED §10.1)

- **`SensitiveDataFilter`:** Regex and heuristic scrubbing of `input.json` is treated strictly as **defense-in-depth**, not the primary security boundary. The real boundary is the container filesystem and network isolation.
- **`AuditorAssertionEngine`:** Categorized as a **structural validator** (validating types, ranges, schema, and output size caps), not a semantic security boundary against prompt injection.

---

## 10. Mandatory Execution Audit Log (NEW §11)

Every execution appends an immutable, cryptographic record to `audit/execution.log`:
- Restrictive permissions: `0600`
- Concurrency protection: `fcntl.flock(LOCK_EX)`
- Cryptographic chaining: `record_hash = SHA256(previous_hash + canonical_json(record))`
- Record fields: `timestamp`, `run_id`, `task_id`, `skill_name`, `skill_version`, `image_digest`, `signature_verified`, `input_sha256`, `output_sha256`, `exit_code`, `timed_out`, `duration_ms`, `degraded_isolation`, `egress_allowed`, `seccomp_profile`, `operator`.

---

## 11. Supply Chain Security (NEW §12)

- **Base Image Digest Pinning:** `python:3.13-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26`
- **Cryptographic Signature Verification:** Images are verified before invocation via Cosign CLI or signed digest attestations (`signatures/`). Unsigned images are refused when `--require-signature` is set.
- **Vulnerability Scanning:** Automated build gate supporting Trivy and Grype; fails builds on High or Critical findings.

---

## 12. Threat Model Review & Verification Matrix (REVISED §10.3)

| Threat Vector | Severity | Mitigation in MASO v1.1.0 | Verification Test Case |
| :--- | :--- | :--- | :--- |
| **Container escape via kernel exploit** | Critical | Custom seccomp allowlist profile (`SCMP_ACT_ERRNO`); all dangerous syscalls denied | `tests/test_adversarial_suite.py::test_adversarial_ptrace_syscall_blocked`, `test_adversarial_mount_syscall_blocked`, `test_adversarial_bpf_syscall_blocked` |
| **Privilege escalation via setuid** | High | `no-new-privileges:true`, UID 10001, `cap-drop=ALL` | `tests/test_adversarial_suite.py::test_adversarial_setuid_escalation_blocked` |
| **SSRF to host services & cloud metadata** | High | Default `--network=none`; Egress proxy pins resolved IP and rejects private/loopback/metadata subnets | `tests/test_phase3_sandbox.py::test_egress_denied_ip_ranges`, `test_egress_anti_dns_rebinding_simulation`, `test_adversarial_suite.py::test_adversarial_socket_connect_offline` |
| **Resource exhaustion (CPU / RAM / PIDs)** | Medium | cgroup limits (`512m`, `1.0 CPU`, `pids-limit=50`) + driver timeout kill | `tests/test_adversarial_suite.py::test_adversarial_memory_bomb_contained`, `tests/test_phase3_sandbox.py::test_docker_driver_timeout_enforcement`, `tests/test_sandbox_v11.py::test_podman_timeout_kill` |
| **Host disk-fill DoS via oversized output** | High | Worker-side `max_output_bytes` cap + Auditor verification | `tests/test_adversarial_suite.py::test_adversarial_oversized_output_aborts` |
| **Prompt injection causing rogue skill execution** | Medium | Skills are trusted in-image code; Auditor asserts structural output contracts | `tests/test_orchestrator_sandbox.py::test_auditor_asserts_sandbox_outputs` |
| **Silent fail-open to unconfined host** | Critical | Fail-closed `auto`; local mode requires `--i-understand-the-risks` + audit log | `tests/test_sandbox_v11.py::test_sandbox_manager_fail_closed_auto`, `tests/test_orchestrator_sandbox.py::test_local_process_driver_acknowledgment_and_degraded_audit` |
| **DNS rebinding / IP-encoding SSRF** | High | Proxy resolves DNS itself, pins resolved IP, rejects decimal/hex IP encodings | `tests/test_phase3_sandbox.py::test_egress_raw_ip_rejection`, `test_egress_anti_dns_rebinding_simulation` |
| **Tampered base image or skill code** | Critical | Immutable digest pinning + Cosign signature verification | `tests/test_phase3_sandbox.py::test_containerfile_pinned_digest`, `test_supply_chain_signature_verification`, `test_driver_refuses_unsigned_image_when_signature_required` |
| **SensitiveDataFilter false negatives** | Medium | Re-framed as defense-in-depth; primary boundary is zero host mounts + offline networking | `tests/test_orchestrator_sandbox.py::test_dispatch_skill_secret_scrubbing`, `tests/test_adversarial_suite.py::test_adversarial_ssh_read_attempt` |

---

## 13. Threat-Model Delta Closeout Table

| # | Gap in v1.0.0 | Severity | Resolution in v1.1.0 | Status | Verified By |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `auto` default silently falls back to unconfined host process | **Critical** | Fail-closed `auto` implemented; local fallback requires explicit `--i-understand-the-risks` | **CLOSED** | `test_sandbox_manager_fail_closed_auto` |
| 2 | Egress uses private IP blocklist (vulnerable to DNS rebinding) | **High** | Allowlist domains + proxy resolves DNS and pins public IP; port 443 HTTPS only | **CLOSED** | `test_egress_anti_dns_rebinding_simulation` |
| 3 | Skill delivery undefined | **High** | In-image skill delivery contract implemented (`/opt/skills/`); data-only `input.json` | **CLOSED** | `test_podman_e2e_data_refinement` |
| 4 | No output size bound (host disk fill DoS) | **High** | Worker-side 10 MiB cap + Auditor size assertion | **CLOSED** | `test_adversarial_oversized_output_aborts` |
| 5 | `:Z` SELinux relabeling presented as primary control | **Medium** | De-scoped `:Z`; single read-write bind mount established as boundary | **CLOSED** | Reconciled §5.4 |
| 6 | Inconsistent seccomp profile recommendations | **High** | Custom seccomp allowlist profile (`maso-seccomp-profile.json`) made mandatory | **CLOSED** | `test_adversarial_ptrace_syscall_blocked` |
| 7 | `SensitiveDataFilter` oversold as security boundary | **Medium** | Re-framed as defense-in-depth; primary control is container isolation | **CLOSED** | Reconciled §10.1 |
| 8 | Inappropriate `setrecursionlimit(100)` and `__builtins__` tricks | **Medium** | Dropped in-process Python tricks; rely on cgroups, limits, and wall-clock timeout | **CLOSED** | `runner.py` v1.1.0 |
| 9 | Inconsistent `--userns=keep-id` vs `--user=10001:10001` | **Low** | Standardized on rootless `--user=10001:10001` matching container image UID | **CLOSED** | Reconciled §5.4 |
| 10 | 30s default timeout too aggressive | **Low** | Default timeout raised to 120s with per-task override capability | **CLOSED** | Reconciled §10.2 |
| 11 | Mutable base image (`:latest`) | **High** | Base image pinned by SHA-256 digest in `Containerfile.worker` and `Containerfile.proxy` | **CLOSED** | `test_containerfile_pinned_digest` |
| 12 | Telemetry optional | **Medium** | Mandatory, append-only, SHA-256 hash-chained audit log implemented (`0600`) | **CLOSED** | `test_audit_log_tamper_detection_breaks_hash_chain` |
| 13 | `AuditorAssertionEngine` "zero-trust" overstated | **Low** | Formally labeled as a structural validator (schema/types/ranges), not semantic filter | **CLOSED** | Reconciled §10.1 |
| 14 | `noexec /tmp` + read-only root limits compiled extensions | **Low** | Skill authoring constraints documented in `docs/skill_author_guide.md` | **CLOSED** | Published Guide |
| 15 | Test baseline unverified | **Low** | Full test suite verified and expanded to 88 tests (0 regressions) | **CLOSED** | Full pytest suite green |

---

## 14. Evaluation of gVisor (`runsc`) Micro-Isolation (Task 5.3)

### Architectural Evaluation
gVisor (`runsc`) provides user-space kernel virtualization (intercepting application syscalls via `ptrace` or KVM). This architecture offers higher isolation against hypothetical zero-day Linux kernel vulnerabilities.

### Decision Record
- **Decision:** Out of scope for MASO v1.1.0 release.
- **Rationale:** The combination of rootless Podman/Docker, custom seccomp allowlist profile (`SCMP_ACT_ERRNO`), zero capabilities (`--cap-drop=ALL`), and `no-new-privileges:true` provides an exceptional defense posture for untrusted skills without introducing `runsc` virtualization overhead (3-5x syscall latency) or requiring KVM kernel module support on user hosts.
- **Future Integration:** Because the MASO sandboxing subsystem is decoupled via the [`SandboxDriver`](masa/sandbox/base.py) abstract interface, a `GVisorSandboxDriver` can be added seamlessly in a future release if multi-tenant untrusted code hosting is required.

---

## 15. Release Sign-Off (Task 5.4)

### Published Image Artifacts (v1.1.0 Final)

| Component | Image Tag | Image Digest | Signature Attestation |
| :--- | :--- | :--- | :--- |
| **Worker Image** | `maso-skill-worker:v1.1.0` | `3e2c44f3c99bb594349b8469083278deace487b6b822fbd79c0d9e581b1a822c` | `signatures/maso-skill-worker_v1.1.sig` |
| **Egress Proxy** | `maso-egress-proxy:v1.1.0` | `8821948d91df6cba14af6438ac4472ad7255348a62c273ca1b56037420a3e389` | `signatures/release_digests.json` |

- **Security Gate:** Trivy/Grype baseline scan passed.
- **Test Matrix:** 88 automated tests passing in CI / local environment (100% pass rate).
- **Audit Logging:** Verified tamper-evident SHA-256 hash chaining active.
- **Status:** **APPROVED & SHIPPED (v1.1.0)**.
