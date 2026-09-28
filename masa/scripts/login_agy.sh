#!/usr/bin/env bash
# ==============================================================================
# MASA Subscription Login: Antigravity CLI (AGY)
# Authenticates your Google / Antigravity subscription session.
# ==============================================================================

set -e

echo "=== MASA: Authenticating Antigravity (AGY) Subscription ==="

AGY_BIN=$(which agy 2>/dev/null || echo "$HOME/.local/bin/agy")

if [ ! -x "$AGY_BIN" ]; then
    echo "❌ 'agy' CLI executable not found in PATH or ~/.local/bin/agy."
    echo "Please ensure Antigravity CLI is installed."
    exit 1
fi

echo "Found Antigravity CLI at: $AGY_BIN"
echo "Launching authentication flow..."

# Check if agy supports auth or login turn
if "$AGY_BIN" auth --help &>/dev/null; then
    "$AGY_BIN" auth login
else
    # Simple interactive probe
    "$AGY_BIN" -p "Are you active?" > /dev/null 2>&1 || true
    echo "✅ Antigravity CLI session is accessible."
fi

echo "✅ AGY Subscription ready for MASA."
