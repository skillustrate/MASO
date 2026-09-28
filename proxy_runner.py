"""
Standalone runner for the MASO Egress Proxy container (v1.1.0).
Reads allowlist configuration from environment and runs EgressProxyServer.
"""

import asyncio
import json
import os
import sys

from masa.sandbox.egress import EgressProxyServer


def parse_allowlist() -> list:
    raw = os.environ.get("MASO_EGRESS_ALLOWLIST", "")
    if not raw.strip():
        return []
    try:
        # Check if valid JSON array
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(item).strip() for item in data if item]
    except Exception:
        pass
    # Fallback comma-separated
    return [item.strip() for item in raw.split(",") if item.strip()]


async def main():
    host = os.environ.get("MASO_PROXY_HOST", "0.0.0.0")
    port = int(os.environ.get("MASO_PROXY_PORT", "8080"))
    allowlist = parse_allowlist()

    print(f"[MASO EGRESS PROXY] Starting on {host}:{port} with allowlist: {allowlist}", flush=True)
    server = EgressProxyServer(host=host, port=port, allowlist=allowlist)
    await server.start()
    print(f"[MASO EGRESS PROXY] Listening on port {server.listening_port}", flush=True)

    try:
        # Keep running
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        print("[MASO EGRESS PROXY] Shutting down...", flush=True)
        await server.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
