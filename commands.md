# MASO / MASA Command Reference

**Document:** `commands.md`  
**Framework:** MASO / MASA  
**Companion Documents:** `environment.md`, `revised_plan.md`, `revised_recom.md`  
**Status:** Approved Reference Documentation  
**Date:** 2026-09-28  

---

## 1. Overview & Binary Entry Points

In the MASA / MASO framework, both **`maso`** and **`masa`** are configured as identical entry-point aliases pointing to `masa.framework:main` (`masa/framework.py`).

```bash
# Both commands are identical:
maso status
masa status
```

All commands operate through a subparser architecture handling orchestration, inspection, auditing, role configuration, local LLM bridging, and credential vault management.

---

## 2. Orchestration & Execution

### `maso run`
Executes the full end-to-end multi-agent orchestration pipeline:
1. **Super Agent** decomposes the high-level objective into subtasks.
2. **Engage Agents** execute specialist skills within an isolated sandbox.
3. **Mailbox mounts** stage inputs (`input.json`) and untrusted outputs (`output.json`).
4. **Signoff Agent** audits and validates results using `AuditorAssertionEngine`.

#### Syntax
```bash
maso run "<objective>" [options]
```

#### Positional Arguments
* `objective` *(required)*: The high-level objective string (e.g. `"Refine sensor data across all pods"`).

#### General Orchestration Flags
* `--workspace`, `-w <path>`: Target working directory for task execution (defaults to current directory).
* `--num-agents <int>`: Number of parallel Engage worker agents to spawn.
* `--input-file <path>`: Path to structured JSON data file to pass as initial input.
* `--super <model>`: Override model for the Super Agent (e.g., `gemini-1.5-pro`, `claude-3-5-sonnet`).
* `--signoff <model>`: Override model for the Signoff Auditor Agent.
* `--engage <models>`: Comma-separated list of model overrides for Engage Agents.

#### Sandbox & Isolation Flags
* `--sandbox {auto,podman,docker,local}`: Container execution engine (default: `auto`).
  * `auto`: Probes Podman $\rightarrow$ Docker $\rightarrow$ **Fails Closed** if neither is found.
  * `podman`: Forces rootless Podman execution (daemonless, no root).
  * `docker`: Forces Docker container execution.
  * `local`: Unconfined local process execution (requires explicit risk acknowledgment).
* `--sandbox-memory <limit>`: Container RAM limit (default: `512m`).
* `--sandbox-timeout <seconds>`: Wall-clock execution timeout (default: `30`, raised to `120` in v1.1.0).
* `--allow-network`: Enables opt-in egress proxy for skills declaring network dependencies (default: disabled / `--network=none`).
* `--i-understand-the-risks`: *(v1.1.0 mandatory flag)* Required whenever `--sandbox local` is specified to acknowledge unconfined host execution.

#### Examples
```bash
# Basic run with auto-detected sandbox
maso run "Process telemetry data"

# Multi-agent run with custom workspace and memory bound
maso run "Batch analyze source code" -w ~/projects/codebase --num-agents 4 --sandbox-memory 1024m

# Run with explicit Podman engine and network access
maso run "Fetch and validate remote schema" --sandbox podman --allow-network

# Explicit local fallback with risk acknowledgement
maso run "Local AST parse" --sandbox local --i-understand-the-risks
```

---

## 3. Inspection & Auditing

### `maso status` (Alias: `maso whoami`)
Inspects active CLI sessions, provider authentication, and container runtime health.

#### Syntax
```bash
maso status
# or
maso whoami
```

#### Output Information
* Authentication status for all supported providers (`agy`, `claude`, `codex`, `bionic`, `local`).
* Active model assignments for Super, Engage, and Signoff agents.
* Container runtime health check (Podman / Docker availability and rootless state).
* *(v1.1.0)* Pinned worker image digest, active seccomp profile, and execution audit log path.

---

### `maso audit`
Runs the `AuditorAssertionEngine` to deterministically validate skill outputs against schemas and bounds without running an agent pipeline.

#### Syntax
```bash
maso audit <file_path> [--master]
```

#### Arguments
* `file_path` *(required)*: Path to the JSON output file to audit (e.g., `output.json`).
* `--master`: Audits the file as an aggregated Master Execution Result across multiple agents.

#### Examples
```bash
# Audit a single task output file
maso audit mailboxes/run_101/tasks/task_01/output.json

# Audit a combined multi-agent result
maso audit workspace/master_result.json --master
```

---

### `maso list-skills`
Lists all specialist skills registered in the framework and available for dispatch.

#### Syntax
```bash
maso list-skills
```

#### Output
Formatted JSON listing registered skill names, entrypoints, schemas, required parameters, and resource manifests.

---

## 4. Setup & Provider Configuration

### `maso setup`
Configures default persistent model routing for the multi-agent roles.

#### Syntax
```bash
maso setup [--super <model>] [--signoff <model>] [--engage <models>]
```

#### Flags
* `--super <model>`: Default model for the Super Agent.
* `--signoff <model>`: Default model for the Signoff Agent.
* `--engage <model1,model2...>`: Comma-separated list of default models for Engage Agents.

#### Example
```bash
maso setup --super gemini-1.5-pro --signoff claude-3-5-sonnet --engage gpt-4o,claude-3-5-haiku
```

---

### `maso setup-local`
Connects, tests, and configures a local LLM server (LM Studio, Ollama, Local AI Rig).

#### Syntax
```bash
maso setup-local [--host <host>] [--port <port>] [--name <name>]
```

#### Flags
* `--host <host>`: Local server address (default: `localhost`).
* `--port <port>`: Port number (default: `1234`).
* `--name <name>`: Display identifier (default: `"Local AI"`).

#### Behavior
Probes the local endpoint, automatically queries available models, and saves the connection settings.

#### Example
```bash
maso setup-local --host localhost --port 11434 --name "Ollama Local"
```

---

### `maso setup-podman`
Guided, cross-platform installer and verifier for rootless Podman containment. Detects the host operating system and distribution, generates the native package manager commands, guides installation, initializes user namespaces, and builds the MASO sandbox container images.

#### Syntax
```bash
maso setup-podman [--yes] [--skip-images]
# or
maso setup --podman [--yes] [--skip-images]
```

#### Flags
* `--yes`, `-y`: Auto-confirms installation and build prompts without requiring interactive inputs.
* `--skip-images`: Skips automated building of `maso-skill-worker:v1.1` and `maso-egress-proxy:v1.1` container images.

#### Supported Platforms
* **Debian / Ubuntu / Mint / Pop!_OS**: `sudo apt-get update && sudo apt-get install -y podman`
* **Fedora / RHEL / CentOS / Rocky**: `sudo dnf install -y podman`
* **Arch Linux / Manjaro**: `sudo pacman -S --noconfirm podman`
* **openSUSE (Leap / Tumbleweed)**: `sudo zypper install -y podman`
* **Alpine Linux**: `sudo apk add podman`
* **macOS**: `brew install podman` followed by `podman machine init && podman machine start`
* **Windows**: Native guidance via WSL2 (recommended) or `winget install RedHat.Podman`

#### Example
```bash
# Interactive guided setup
maso setup-podman

# Non-interactive automated setup (e.g., CI/CD)
maso setup-podman -y
```

---

## 5. Authentication & Workspace Trust

### `maso login`
Authenticates with an AI subscription provider and securely stores tokens into the host OS Keyring.

#### Syntax
```bash
maso login <provider>
```

#### Positional Argument
* `provider` *(required)*: One of `agy`, `claude`, `codex`, `bionic`, or `local`.

#### Behavior
Securely captures API keys / OAuth tokens without saving them in plain text or mounting them into untrusted containers.

#### Examples
```bash
maso login agy
maso login claude
maso login codex
```

---

### `maso trust`
Pre-approves a workspace directory to bypass interactive permission confirmation prompts.

#### Syntax
```bash
maso trust [path]
```

#### Arguments
* `path` *(optional)*: Directory path to mark as trusted (defaults to current working directory `.`).

#### Examples
```bash
# Trust current directory
maso trust

# Trust specific project folder
maso trust ~/projects/my-target-folder
```

---

## 6. Quick Reference Table

| Command | Primary Function | Typical Use Case |
| :--- | :--- | :--- |
| `maso run` | Pipeline Orchestrator | `maso run "Analyze telemetry data" --num-agents 2` |
| `maso status` / `whoami` | System & Sandbox Inspection | `maso status` |
| `maso audit` | Deterministic Output Validator | `maso audit /path/to/output.json` |
| `maso list-skills` | Skill Registry Viewer | `maso list-skills` |
| `maso login` | Keyring Credential Vault | `maso login claude` |
| `maso trust` | Directory Whitelisting | `maso trust ~/projects/analytics` |
| `maso setup` | Model Preference Configuration | `maso setup --super gemini-1.5-pro` |
| `maso setup-local` | Local LLM Integration | `maso setup-local --port 1234` |
