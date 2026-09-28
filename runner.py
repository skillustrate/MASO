#!/usr/bin/env python3
"""
MASO Container Worker Runner (v1.1.0).
Bakes into the worker image at /opt/runner.py.
Dispatches specialist skills from the in-image registry /opt/skills.
"""

import importlib.util
import json
import os
import sys
import time
from typing import Any, Dict

WORKSPACE_DIR = os.environ.get("WORKSPACE", "/workspace")
_default_skills = "/opt/skills" if os.path.exists("/opt/skills") else os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")
SKILLS_DIR = os.environ.get("SKILLS_DIR", _default_skills)
DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MiB


def fail(message: str, exit_code: int = 1):
    """Log error message to stderr and exit non-zero without writing output.json."""
    sys.stderr.write(f"[MASO WORKER ERROR] {message}\n")
    sys.stderr.flush()
    sys.exit(exit_code)


def load_skill_entrypoint(skill_name: str):
    """
    Look up skill in in-image registry /opt/skills/<skill_name>/manifest.json.
    Dynamically load the entrypoint module.
    """
    skill_dir = os.path.join(SKILLS_DIR, skill_name)
    manifest_path = os.path.join(skill_dir, "manifest.json")

    if not os.path.exists(manifest_path):
        fail(f"Unknown skill '{skill_name}' - not found in in-image registry ({manifest_path})", exit_code=2)

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        fail(f"Malformed skill manifest for '{skill_name}': {str(e)}", exit_code=3)

    entrypoint_str = manifest.get("entrypoint", "main.py:execute_skill")
    if ":" not in entrypoint_str:
        fail(f"Invalid entrypoint format '{entrypoint_str}' in manifest for '{skill_name}'", exit_code=4)

    file_part, func_part = entrypoint_str.split(":", 1)
    module_path = os.path.join(skill_dir, file_part)

    if not os.path.exists(module_path):
        fail(f"Skill entrypoint file not found: {module_path}", exit_code=5)

    spec = importlib.util.spec_from_file_location(f"skills.{skill_name}", module_path)
    if spec is None or spec.loader is None:
        fail(f"Failed to load spec for skill '{skill_name}' from {module_path}", exit_code=6)

    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        fail(f"Failed to execute skill module '{skill_name}': {str(e)}", exit_code=7)

    if not hasattr(module, func_part):
        fail(f"Function '{func_part}' not found in skill module {module_path}", exit_code=8)

    return getattr(module, func_part), manifest


def main():
    input_path = os.path.join(WORKSPACE_DIR, "input.json")
    output_tmp_path = os.path.join(WORKSPACE_DIR, "output.json.tmp")
    output_path = os.path.join(WORKSPACE_DIR, "output.json")

    if not os.path.exists(input_path):
        fail(f"Missing required mailbox input file: {input_path}", exit_code=10)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            input_data = json.load(f)
    except Exception as e:
        fail(f"Malformed input.json: {str(e)}", exit_code=11)

    task_id = input_data.get("task_id", "task-unknown")
    skill_name = input_data.get("skill_name")
    parameters = input_data.get("parameters", {})
    limits = input_data.get("limits", {})

    if not skill_name:
        fail("Missing 'skill_name' in input.json", exit_code=12)

    # In-image skill resolution (REVISED §5.5)
    skill_func, manifest = load_skill_entrypoint(skill_name)

    max_output_bytes = limits.get("max_output_bytes") or manifest.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES)

    task_context = {
        "task_id": task_id,
        "skill_name": skill_name,
        "manifest": manifest
    }

    start_time = time.time()
    try:
        result = skill_func(task_context, parameters)
    except Exception as e:
        fail(f"Unhandled exception in skill '{skill_name}': {str(e)}", exit_code=13)

    duration_ms = int((time.time() - start_time) * 1000)

    envelope = {
        "task_id": task_id,
        "skill_name": skill_name,
        "skill_version": manifest.get("version", "1.0.0"),
        "status": result.get("status", "SUCCESS") if isinstance(result, dict) else "SUCCESS",
        "duration_ms": duration_ms,
        "result": result
    }

    # Bounded serialization check (REVISED §10.2-C)
    try:
        serialized = json.dumps(envelope, indent=2)
    except Exception as e:
        fail(f"Failed to serialize skill result to JSON: {str(e)}", exit_code=14)

    output_bytes = len(serialized.encode("utf-8"))
    if output_bytes > max_output_bytes:
        fail(
            f"Output size ({output_bytes} bytes) exceeds configured max_output_bytes ({max_output_bytes} bytes)",
            exit_code=15
        )

    # Atomic write to temporary file, then os.replace() (REVISED §10.2-A)
    try:
        with open(output_tmp_path, "w", encoding="utf-8") as f:
            f.write(serialized)
            f.flush()
            os.fsync(f.fileno())
        os.replace(output_tmp_path, output_path)
    except Exception as e:
        fail(f"Failed to write output.json atomically: {str(e)}", exit_code=16)

    sys.exit(0)


if __name__ == "__main__":
    main()
