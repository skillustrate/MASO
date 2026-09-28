#!/usr/bin/env python3
"""
MASO End-to-End Sandboxed Execution Demo (v1.1.0).
Demonstrates Super -> Engage -> Signoff offline container execution,
Auditor assertion validation, ephemeral purge, and tamper-evident audit log chaining.
"""

import asyncio
import json
import os
import sys

# Ensure repository root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masa.framework import MultiAgentFramework


async def run_demo():
    print("======================================================================")
    print(" 🚀 MASO Hardened Sandbox End-to-End Demo (v1.1.0)")
    print(" Boundary: Rootless Podman / Docker Container (Offline, Seccomp allowlist)")
    print("======================================================================")

    framework = MultiAgentFramework(os.getcwd())

    sample_payload = {
        "dataset_name": "quarterly_performance",
        "raw_data": [
            {"region": "EMEA", "sales": 12000, "status": "APPROVED"},
            {"region": "APAC", "sales": 18500, "status": "APPROVED"},
            {"region": "AMER", "sales": 24000, "status": "PENDING"}
        ]
    }

    # Write temporary demo input
    demo_input_file = os.path.join(os.getcwd(), "demo_input.json")
    with open(demo_input_file, "w", encoding="utf-8") as f:
        json.dump(sample_payload, f, indent=2)

    print("\n1. Initiating Sandboxed Pipeline Run...")
    try:
        pipeline_result = await framework.run_pipeline(
            user_objective="Refine quarterly regional sales figures and generate certified summary table",
            input_file=demo_input_file,
            super_override="mock",
            signoff_override="mock",
            engage_override=["mock"],
            num_agents=2,
            sandbox_mode="auto",
            sandbox_memory="512m",
            sandbox_timeout=60,
            allow_network=False,
            purge_ephemeral=True
        )

        print("\n2. Pipeline Execution Finished:")
        print(f"   - Passed:        {pipeline_result.get('passed')}")
        print(f"   - Run ID:        {pipeline_result.get('run_id')}")
        print(f"   - Signoff Model: {pipeline_result.get('signoff_agent')}")
        print(f"   - Master Result: {pipeline_result.get('master_result_path')}")

        print("\n3. Auditor Evaluation:")
        auditor_report = pipeline_result.get("auditor_report", {})
        print(f"   - Structural Audit Passed: {auditor_report.get('passed')}")
        print(f"   - Assertions Validated:    {len(auditor_report.get('assertions_validated', []))}")

        print("\n4. Tamper-Evident Audit Chain Status:")
        from masa.sandbox.manager import SandboxManager
        s_mgr = SandboxManager()
        health = s_mgr.health_check()
        print(f"   - Container Engine: {health.get('runtime')} (Rootless: {health.get('rootless')})")
        print(f"   - Image Digest:     {health.get('image_digest')}")
        print(f"   - Audit Chain Valid:{health.get('audit_chain_valid')}")
        print(f"   - Log Entries:      {health.get('audit_log_entries')}")

        print("\n======================================================================")
        print(" ✅ End-to-End Demo Completed Successfully!")
        print("======================================================================")

    finally:
        if os.path.exists(demo_input_file):
            os.remove(demo_input_file)


if __name__ == "__main__":
    asyncio.run(run_demo())
