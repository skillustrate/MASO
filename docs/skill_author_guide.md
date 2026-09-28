# MASO Specialist Skill Authoring Guide (v1.1.0)

This guide documents the security, architectural, and operational constraints for developing specialist skills within the **MASO (Multi-Agent Scaffolding Architecture)** framework.

All specialist skills execute inside hardened, unprivileged OCI container sandboxes (via rootless Podman or Docker). Understanding these containment constraints is essential for authoring stable and compliant skills.

---

## 1. Skill Delivery Contract

Per **REVISED §5.5**, skills are **trusted, versioned code artifacts shipped inside the worker image** (`maso-skill-worker:v1.1`).

- Skills are located at `/opt/skills/<skill_name>/`.
- The mailbox `input.json` carries **data and parameters only** — never arbitrary executable code strings.
- The in-container dispatcher (`/opt/runner.py`) looks up the skill in the in-image registry by `skill_name`, validates input parameters against the skill manifest, and invokes the defined entrypoint.

### Skill Directory Layout

```
/opt/skills/<skill_name>/
├── manifest.json       # Metadata, limits, and entrypoint definition
├── main.py             # Skill entrypoint implementation
└── schemas/            # (Optional) Input and output JSON schemas
    ├── input.json
    └── output.json
```

### Manifest Schema (`manifest.json`)

```json
{
  "name": "data_refinement",
  "version": "1.0.0",
  "entrypoint": "main.py:execute_skill",
  "description": "Cleanses, normalizes, and filters tabular datasets",
  "network_required": false,
  "egress_allowlist": [],
  "max_output_bytes": 10485760
}
```

- `entrypoint`: Module and callable formatted as `filename.py:function_name`.
- `network_required`: Set to `true` only if the skill requires outbound HTTPS access.
- `egress_allowlist`: List of domain names permitted for outbound HTTPS connections (e.g., `["registry.example.com"]`).
- `max_output_bytes`: Maximum allowable serialized output size in bytes (default: 10 MiB).

---

## 2. Containment Boundaries & Execution Constraints

Skills execute within a hardened container environment with the following isolation properties:

### A. Read-Only Root Filesystem (`--read-only`)
- The container root filesystem (`/`, `/opt`, `/usr`, `/lib`) is strictly read-only.
- Skills cannot install packages, mutate libraries, or modify system files.

### B. Non-Executable Ephemeral Tempfs (`/tmp:rw,noexec,nosuid,nodev`)
- `/tmp` is provided as an in-memory `tmpfs` bounded at 64 MiB.
- It is mounted with the `noexec` flag.
- **Any attempt to compile, download, or execute binary executables or shared libraries from `/tmp` will fail with `EACCES` (Permission denied).**

### C. No Subprocess Binaries or Runtime C Extensions
- Python C-extensions cannot be compiled or loaded from `/tmp` at runtime.
- Any external compiled dependencies or binary packages must be pre-installed into the worker image via `Containerfile.worker`.

### D. Unprivileged User (`UID 10001:10001`)
- Containers execute under unprivileged user `masouser` (`UID 10001`, `GID 10001`) with a `nologin` shell.
- Capabilities are completely dropped (`--cap-drop=ALL`).
- Privilege escalation is disabled (`--security-opt=no-new-privileges:true`).

### E. Output Size Cap (Host Disk-Fill Protection)
- `runner.py` enforces a hard output size cap before writing `output.json`.
- The default limit is **10 MiB** (`10485760` bytes).
- If the serialized result exceeds `max_output_bytes`, execution aborts with exit code `15`, no `output.json` is generated, and the host auditor marks the task as failed.

### F. Resource Limits & Timeouts
- **Memory limit**: 512 MiB (default); exceeding causes OOM termination (exit code 137).
- **CPUs**: 1.0 core maximum.
- **PIDs limit**: 50 processes/threads maximum; fork bombs are contained.
- **Wall-clock timeout**: 120 seconds default; exceeded tasks are killed (exit code 124).

---

## 3. Network Policy & Egress Control

1. **Default: Offline (`--network=none`)**
   - By default, skills have zero network access. Syscalls such as `socket()`, `connect()`, `sendto()`, and `recvfrom()` are blocked at the kernel level by the custom seccomp profile (`maso-seccomp-offline.json`).

2. **Opt-in Egress**:
   - Outbound network access is enabled **only** if:
     1. The skill manifest declares `"network_required": true`.
     2. The user explicitly supplies the `--allow-network` flag.
   - When active, the container uses the egress seccomp profile (`maso-seccomp-egress.json`) and routes traffic exclusively through the isolated egress proxy (`maso-egress-proxy:v1.1`).

3. **Egress Rules**:
   - Only **port 443 (HTTPS)** is permitted.
   - Only **allowlisted domains** listed in `egress_allowlist` may be accessed.
   - **No Raw IP Literals**: Direct IP connections (IPv4 or IPv6) are rejected.
   - **Anti-DNS Rebinding**: The proxy resolves DNS independently and validates that resolved IPs do not belong to private networks, loopback (`127.0.0.1`, `::1`), or cloud metadata endpoints (`169.254.169.254`).

---

## 4. Entrypoint Implementation Contract

The skill entrypoint callable must accept two parameters: `context` and `parameters`.

```python
from typing import Any, Dict


def execute_skill(context: Dict[str, Any], parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Specialist skill execution entrypoint.

    Args:
        context: Execution metadata including task_id, skill_name, and manifest.
        parameters: Input parameters passed from orchestrator.

    Returns:
        JSON-serializable dictionary with execution results.
    """
    raw_data = parameters.get("raw_data")
    if not raw_data:
        return {
            "status": "FAILURE",
            "errors": ["Missing required parameter 'raw_data'"]
        }

    # Process data within memory and execution bounds
    processed_count = len(raw_data)

    return {
        "status": "SUCCESS",
        "processed_count": processed_count,
        "summary": "Data successfully processed"
    }
```
