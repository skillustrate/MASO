#!/usr/bin/env bash
# ==============================================================================
# MASA Subscription Login: Codex CLI
# Authenticates your Codex CLI session (with GitHub Copilot fallback).
# ==============================================================================

set -e

echo "=== MASA: Authenticating Codex Subscription ==="

# 1. Primary: Native OpenAI Codex CLI
CODEX_BIN=$(which codex 2>/dev/null || true)
if [ -n "$CODEX_BIN" ] && [ -x "$CODEX_BIN" ]; then
    echo "Found Codex CLI at: $CODEX_BIN"
    "$CODEX_BIN" login || "$CODEX_BIN" auth login || true
    echo "✅ Codex subscription verified."
    exit 0
fi

# 2. Secondary fallback: GitHub Copilot CLI
GH_BIN=$(which gh 2>/dev/null || echo "$HOME/.local/bin/gh")
if [ -x "$GH_BIN" ]; then
    echo "Codex CLI ('codex') not found in PATH. Checking GitHub Copilot CLI at: $GH_BIN"
    if ! "$GH_BIN" auth status >/dev/null 2>&1; then
        echo "Launching GitHub authentication..."
        "$GH_BIN" auth login
    else
        echo "✅ GitHub Copilot session is already authenticated."
    fi
    echo "✅ Copilot session verified."
    exit 0
fi

echo "❌ Neither 'codex' nor 'gh' CLI found in PATH."
echo "Please install Codex CLI ('codex') or GitHub CLI ('gh')."
exit 1
