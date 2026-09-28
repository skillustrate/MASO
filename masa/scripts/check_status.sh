#!/usr/bin/env bash
# ==============================================================================
# MASA: Check Subscription CLI Statuses
# ==============================================================================

echo "======================================================================"
echo " MASA Subscription Status & Session Verification"
echo "======================================================================"
printf "%-12s %-12s %-15s %-30s\n" "PROVIDER" "CLI BINARY" "STATUS" "DETAILS"
echo "----------------------------------------------------------------------"

# 1. AGY
AGY_BIN=$(which agy 2>/dev/null || echo "$HOME/.local/bin/agy")
if [ -x "$AGY_BIN" ]; then
    printf "%-12s %-12s %-15s %-30s\n" "AGY" "agy" "INSTALLED" "$($AGY_BIN --version 2>/dev/null || echo 'Antigravity CLI')"
else
    printf "%-12s %-12s %-15s %-30s\n" "AGY" "agy" "NOT FOUND" "Install via agy setup"
fi

# 2. Claude
CLAUDE_BIN=$(which claude 2>/dev/null || echo "$HOME/.local/bin/claude")
if [ -x "$CLAUDE_BIN" ]; then
    printf "%-12s %-12s %-15s %-30s\n" "Claude" "claude" "INSTALLED" "$($CLAUDE_BIN --version 2>/dev/null | head -n1 || echo 'Claude Code')"
else
    printf "%-12s %-12s %-15s %-30s\n" "Claude" "claude" "NOT FOUND" "npm install -g @anthropic-ai/claude-code"
fi

# 3. Codex CLI (with GitHub Copilot fallback)
CODEX_BIN=$(which codex 2>/dev/null || true)
GH_BIN=$(which gh 2>/dev/null || echo "$HOME/.local/bin/gh")

if [ -n "$CODEX_BIN" ] && [ -x "$CODEX_BIN" ]; then
    printf "%-12s %-12s %-15s %-30s\n" "Codex" "codex" "ACTIVE" "$($CODEX_BIN --version 2>/dev/null || echo 'Codex CLI')"
elif [ -x "$GH_BIN" ]; then
    GH_STATUS="INSTALLED"
    if "$GH_BIN" auth status >/dev/null 2>&1; then
        GH_STATUS="LOGGED IN"
    fi
    printf "%-12s %-12s %-15s %-30s\n" "Codex" "gh copilot" "$GH_STATUS" "GitHub Copilot Session"
else
    printf "%-12s %-12s %-15s %-30s\n" "Codex" "codex" "NOT FOUND" "Install Codex CLI ('codex')"
fi

# 4. Local AI Models (LM Studio, Ollama, AI Rig, BIONIC)
LOCAL_CFG="$HOME/.masa/local_model.json"
BIONIC_CFG="$HOME/.masa/bionic_session.json"
LOCAL_NAME="LOCAL AI"
if [ -f "$LOCAL_CFG" ]; then
    LOCAL_NAME=$(python3 -c "import json; d=json.load(open('$LOCAL_CFG')); print(d.get('name', 'LOCAL AI'))" 2>/dev/null || echo "LOCAL AI")
    MODEL=$(python3 -c "import json; d=json.load(open('$LOCAL_CFG')); print(d.get('selected_model', 'active'))" 2>/dev/null || echo "active")
    printf "%-12s %-12s %-15s %-30s\n" "$LOCAL_NAME" "local" "ACTIVE" "Model: $MODEL"
elif [ -f "$BIONIC_CFG" ]; then
    LOCAL_NAME=$(python3 -c "import json; d=json.load(open('$BIONIC_CFG')); print(d.get('name', 'BIONIC'))" 2>/dev/null || echo "BIONIC")
    printf "%-12s %-12s %-15s %-30s\n" "$LOCAL_NAME" "session" "CONFIGURED" "Local session active"
elif which bionic >/dev/null 2>&1; then
    printf "%-12s %-12s %-15s %-30s\n" "BIONIC" "bionic" "INSTALLED" "Enterprise CLI"
else
    printf "%-12s %-12s %-15s %-30s\n" "LOCAL AI" "local" "NOT CONFIGURED" "Run 'masa setup' or 'masa setup-local'"
fi

echo "======================================================================"
