"""
Multi-Agent Scaffolding Architecture (MASA / MASO) CLI & Entry Point.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from masa.broker import TaskBroker
from masa.crypto import ConfigCrypto, SensitiveDataFilter
from masa.evals import AuditorAssertionEngine, ContentSanitizer
from masa.orchestrator import (
    MASA_HOME_DIR,
    USER_CONFIG_PATH,
    MetaAuditor,
    MultiAgentFramework,
    RetryPolicy,
    SubscriptionManager,
    TelemetryEventBus,
)

__all__ = [
    "main",
    "MultiAgentFramework",
    "SubscriptionManager",
    "SensitiveDataFilter",
    "ConfigCrypto",
    "TaskBroker",
    "ContentSanitizer",
    "AuditorAssertionEngine",
    "MetaAuditor",
    "RetryPolicy",
    "TelemetryEventBus",
    "USER_CONFIG_PATH",
    "MASA_HOME_DIR",
]


def print_status(workspace: Optional[str] = None):
    root = workspace or os.getcwd()
    mgr = SubscriptionManager(root)
    statuses = mgr.get_all_statuses()

    print("======================================================================")
    print(" MASA / MASO Subscription Status & Session Verification")
    print("======================================================================")
    print(f"{'PROVIDER':<12} {'STATUS':<15} {'DETAILS':<35}")
    print("----------------------------------------------------------------------")
    for prov, info in statuses.items():
        prov_name = info.get("name", prov.upper())
        status_val = info.get("status", "UNKNOWN")
        details_val = str(info.get("details", ""))
        print(f"{prov_name:<12} {status_val:<15} {details_val:<35}")
    print("======================================================================")


def handle_login(provider: str, workspace: Optional[str] = None):
    root = workspace or os.getcwd()
    scripts_dir = os.path.join(root, "scripts")
    script_candidates = [
        os.path.join(scripts_dir, f"login_{provider}.sh"),
        os.path.join(root, "masa", "scripts", f"login_{provider}.sh"),
    ]
    script_to_run = None
    for cand in script_candidates:
        if os.path.isfile(cand):
            script_to_run = cand
            break

    if script_to_run:
        import subprocess

        subprocess.run(["bash", script_to_run])
    else:
        print(f"ℹ️ Login guidance for {provider}:")
        if provider == "agy":
            print("Run: agy auth login")
        elif provider == "claude":
            print("Run: claude login")
        elif provider == "codex":
            print("Run: codex auth or gh auth login")
        elif provider in ["bionic", "local"]:
            print("Run: masa setup-local")
        else:
            print(
                f"Unknown provider '{provider}'. Supported: agy, claude, codex, bionic, local"
            )


def handle_trust(directory: Optional[str] = None):
    target = os.path.abspath(directory or ".")
    mgr = SubscriptionManager(target)
    res = mgr.trust_directory(target)
    print(f"✅ Pre-approved workspace trust for '{target}':")
    print(f"   Claude Code: {'Trusted' if res.get('claude') else 'Not updated'}")
    print(f"   Antigravity AGY: {'Trusted' if res.get('agy') else 'Not updated'}")


def handle_setup(
    super_m: Optional[str],
    signoff_m: Optional[str],
    engage_m: Optional[str],
    workspace: Optional[str] = None,
):
    fw = MultiAgentFramework(workspace or os.getcwd())
    super_val = super_m or "gemini"
    signoff_val = signoff_m or "claude"
    if engage_m:
        engage_val = [m.strip() for m in engage_m.split(",") if m.strip()]
    else:
        engage_val = ["gemini", "claude", "gpt-4o"]
    fw.setup_user_profile(super_val, signoff_val, engage_val)
    print("✅ User model preferences securely updated and encrypted at rest.")


def handle_setup_local(
    host: str = "localhost", port: int = 1234, name: str = "Local AI"
):
    os.makedirs(MASA_HOME_DIR, exist_ok=True)
    models = SubscriptionManager.query_local_models(host=host, port=port)
    selected_model = models[0] if models else "default-local-model"
    cfg = {
        "provider": "local",
        "name": name,
        "host": host,
        "port": port,
        "selected_model": selected_model,
        "available_models": models,
        "status": "ACTIVE" if models else "CONFIGURED",
    }
    cfg_file = os.path.join(MASA_HOME_DIR, "local_model.json")
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"✅ Configured Local AI ({name}) at http://{host}:{port}/v1")
    if models:
        print(f"   Found {len(models)} model(s): {', '.join(models[:3])}")
        print(f"   Selected model: {selected_model}")
    else:
        print(
            "   ⚠️ Server currently unreachable or no models loaded; saved configuration."
        )


def handle_run(
    objective: str,
    workspace: Optional[str] = None,
    num_agents: Optional[int] = None,
    input_file: Optional[str] = None,
    super_override: Optional[str] = None,
    signoff_override: Optional[str] = None,
    engage_override: Optional[str] = None,
):
    fw = MultiAgentFramework(workspace or os.getcwd())
    engage_list = (
        [m.strip() for m in engage_override.split(",") if m.strip()]
        if engage_override
        else None
    )
    res = asyncio.run(
        fw.run_pipeline(
            user_objective=objective,
            super_override=super_override,
            signoff_override=signoff_override,
            engage_override=engage_list,
            input_file=input_file,
            num_agents=num_agents,
        )
    )
    print(json.dumps(res, indent=2))
    if not res.get("passed"):
        sys.exit(1)


def handle_audit(file_path: str, master: bool = False, workspace: Optional[str] = None):
    fw = MultiAgentFramework(workspace or os.getcwd())
    report = fw.run_evaluator(file_path, master=master)
    print(json.dumps(report, indent=2))
    if not report.get("passed"):
        sys.exit(1)


def handle_list_skills(workspace: Optional[str] = None):
    fw = MultiAgentFramework(workspace or os.getcwd())
    print(json.dumps(fw.get_registered_skills(), indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent Scaffolding Architecture (MASA / MASO) CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # status / whoami
    subparsers.add_parser(
        "status", help="Inspect subscription statuses and active CLI sessions"
    )
    subparsers.add_parser("whoami", help="Alias for status")

    # login
    login_p = subparsers.add_parser(
        "login", help="Authenticate a subscription provider"
    )
    login_p.add_argument(
        "provider", choices=["agy", "claude", "codex", "bionic", "local"]
    )

    # trust
    trust_p = subparsers.add_parser(
        "trust", help="Pre-approve folder trust to skip prompts"
    )
    trust_p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to trust (default: current directory)",
    )

    # setup
    setup_p = subparsers.add_parser("setup", help="Configure user model preferences")
    setup_p.add_argument("--super", help="Super Agent model")
    setup_p.add_argument("--signoff", help="Signoff Agent model")
    setup_p.add_argument("--engage", help="Comma-separated list of Engage models")

    # setup-local
    setup_local_p = subparsers.add_parser(
        "setup-local", help="Configure local LLM server (LM Studio / Ollama / AI Rig)"
    )
    setup_local_p.add_argument(
        "--host", default="localhost", help="Host address (default: localhost)"
    )
    setup_local_p.add_argument(
        "--port", type=int, default=1234, help="Port (default: 1234)"
    )
    setup_local_p.add_argument("--name", default="Local AI", help="Display name")

    # run
    run_p = subparsers.add_parser(
        "run", help="Execute multi-agent orchestration pipeline"
    )
    run_p.add_argument("objective", help="High-level objective")
    run_p.add_argument("--workspace", "-w", help="Target working directory")
    run_p.add_argument(
        "--num-agents", type=int, help="Number of parallel Engage agents"
    )
    run_p.add_argument("--input-file", help="Path to JSON input data file")
    run_p.add_argument("--super", help="Super Agent model override")
    run_p.add_argument("--signoff", help="Signoff Agent model override")
    run_p.add_argument(
        "--engage", help="Engage Agent models override (comma-separated)"
    )

    # audit
    audit_p = subparsers.add_parser(
        "audit", help="Run auditor evaluation on an output or master result JSON file"
    )
    audit_p.add_argument("file_path", help="Path to JSON file to audit")
    audit_p.add_argument("--master", action="store_true", help="Audit as Master Result")

    # list-skills
    subparsers.add_parser("list-skills", help="List registered skills")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command in ["status", "whoami"]:
        print_status()
    elif args.command == "login":
        handle_login(args.provider)
    elif args.command == "trust":
        handle_trust(args.path)
    elif args.command == "setup":
        handle_setup(args.super, args.signoff, args.engage)
    elif args.command == "setup-local":
        handle_setup_local(args.host, args.port, args.name)
    elif args.command == "run":
        handle_run(
            objective=args.objective,
            workspace=args.workspace,
            num_agents=args.num_agents,
            input_file=args.input_file,
            super_override=args.super,
            signoff_override=args.signoff,
            engage_override=args.engage,
        )
    elif args.command == "audit":
        handle_audit(args.file_path, master=args.master)
    elif args.command == "list-skills":
        handle_list_skills()


if __name__ == "__main__":
    main()
