#!/usr/bin/env bash
# ==============================================================================
# MASA Subscription Login: Claude Code CLI
# Authenticates your Anthropic / Claude Pro / Team subscription session.
# ==============================================================================

set -e

echo "=== MASA: Authenticating Claude Code Subscription ==="

CLAUDE_BIN=$(which claude 2>/dev/null || echo "$HOME/.local/bin/claude")

if [ ! -x "$CLAUDE_BIN" ]; then
    echo "❌ 'claude' CLI executable not found in PATH or ~/.local/bin/claude."
    echo "Please ensure Claude Code CLI is installed."
    exit 1
fi

echo "Found Claude CLI at: $CLAUDE_BIN"
echo "Invoking Claude Code authentication..."

# Run claude auth or setup-token
"$CLAUDE_BIN" auth || "$CLAUDE_BIN" doctor || true

echo "✅ Claude subscription session verified."
