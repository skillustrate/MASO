#!/usr/bin/env bash
# ==============================================================================
# MASA: Pre-Approve & Trust Workspace Directory
# Pre-configures folder trust for Claude Code and Antigravity (AGY) so you never
# get prompted to confirm or type 'yes' to trust the folder.
# ==============================================================================

set -e

TARGET_DIR="${1:-$(pwd)}"
TARGET_DIR=$(cd "$TARGET_DIR" && pwd)

echo "======================================================================"
echo " MASA Workspace Trust Configuration"
echo " Target Directory: $TARGET_DIR"
echo "======================================================================"

# 1. Configure Claude Code (~/.claude.json)
CLAUDE_CONFIG="$HOME/.claude.json"
if [ -f "$CLAUDE_CONFIG" ]; then
    echo "Configuring Claude Code trust in $CLAUDE_CONFIG..."
    python3 -c "
import json
path = '$CLAUDE_CONFIG'
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    projects = data.setdefault('projects', {})
    proj = projects.setdefault('$TARGET_DIR', {})
    proj['hasTrustDialogAccepted'] = True
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print('  ✅ Claude Code: Folder marked as trusted (hasTrustDialogAccepted=true).')
except Exception as e:
    print(f'  ⚠️ Claude Code config update warning: {e}')
"
else
    echo "Claude Code config ($CLAUDE_CONFIG) not found yet. Creating skeleton..."
    mkdir -p "$HOME"
    python3 -c "
import json
path = '$CLAUDE_CONFIG'
data = {'projects': {'$TARGET_DIR': {'hasTrustDialogAccepted': True}}}
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
print('  ✅ Claude Code: Initialized config with folder trust.')
"
fi

# 2. Configure Antigravity AGY (~/.gemini/antigravity-cli/settings.json)
AGY_SETTINGS="$HOME/.gemini/antigravity-cli/settings.json"
if [ -f "$AGY_SETTINGS" ]; then
    echo "Configuring Antigravity CLI trust in $AGY_SETTINGS..."
    python3 -c "
import json
path = '$AGY_SETTINGS'
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    workspaces = data.setdefault('trustedWorkspaces', [])
    if '$TARGET_DIR' not in workspaces:
        workspaces.append('$TARGET_DIR')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print('  ✅ Antigravity (AGY): Folder added to trustedWorkspaces.')
except Exception as e:
    print(f'  ⚠️ Antigravity settings update warning: {e}')
"
fi

echo "======================================================================"
echo "✅ Workspace trust pre-approved! Both Claude and AGY will run without"
echo "   prompting you to trust this folder."
echo "======================================================================"
