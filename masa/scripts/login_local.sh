#!/usr/bin/env bash
# ==============================================================================
# MASA: Interactive Setup for Local AI Models
# Configures LM Studio, Ollama, Local AI Rig, or any OpenAI-compatible server.
# Defaults to localhost for portability across machines.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# If Python framework is available, invoke the rich interactive setup
if [ -f "$PROJECT_ROOT/framework.py" ] && command -v python3 >/dev/null 2>&1; then
    exec python3 "$PROJECT_ROOT/framework.py" setup-local "$@"
fi

CONFIG_DIR="$HOME/.masa"
LOCAL_SESSION="$CONFIG_DIR/local_model.json"
BIONIC_SESSION="$CONFIG_DIR/bionic_session.json"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

echo "=============================================================="
echo " MASA: Local AI Model Setup"
echo "=============================================================="
echo "Connect to LM Studio, Ollama, Local AI Rig, or local endpoints."
echo

read -p "Enter provider / server name [default: Local AI]: " PROVIDER_NAME
PROVIDER_NAME=${PROVIDER_NAME:-"Local AI"}

read -p "Enter host / IP [default: localhost]: " LOCAL_HOST
LOCAL_HOST=${LOCAL_HOST:-"localhost"}

read -p "Enter port [default: 1234]: " LOCAL_PORT
LOCAL_PORT=${LOCAL_PORT:-"1234"}

BASE_URL="http://${LOCAL_HOST}:${LOCAL_PORT}/v1"
echo
echo "🔍 Querying models from ${BASE_URL}/models ..."

MODELS_JSON=$(curl -s --connect-timeout 2 "${BASE_URL}/models" 2>/dev/null || true)
SELECTED_MODEL=""

if [ -n "$MODELS_JSON" ]; then
    echo "✅ Successfully contacted ${BASE_URL}/models!"
    # Try parsing model IDs if python or jq is installed
    if command -v python3 >/dev/null 2>&1; then
        MODEL_LIST=$(python3 -c "import json, sys; d=json.loads(sys.argv[1]); [print(m['id']) for m in d.get('data', []) if 'id' in m]" "$MODELS_JSON" 2>/dev/null || true)
    fi
    if [ -n "$MODEL_LIST" ]; then
        echo "Available models:"
        i=1
        declare -A model_map
        while IFS= read -r m; do
            echo "   [$i] $m"
            model_map[$i]="$m"
            i=$((i+1))
        done <<< "$MODEL_LIST"
        read -p "Select model number [default: 1]: " SEL_NUM
        SEL_NUM=${SEL_NUM:-"1"}
        SELECTED_MODEL="${model_map[$SEL_NUM]:-${model_map[1]}}"
    fi
fi

if [ -z "$SELECTED_MODEL" ]; then
    read -p "Enter model name manually [default: local-model]: " MANUAL_MODEL
    SELECTED_MODEL=${MANUAL_MODEL:-"local-model"}
fi

echo "✅ Selected model: $SELECTED_MODEL"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat <<EOF > "$LOCAL_SESSION"
{
  "provider": "local",
  "name": "$PROVIDER_NAME",
  "host": "$LOCAL_HOST",
  "port": $LOCAL_PORT,
  "base_url": "$BASE_URL",
  "selected_model": "$SELECTED_MODEL",
  "authenticated_at": "$TIMESTAMP",
  "status": "ACTIVE"
}
EOF
chmod 600 "$LOCAL_SESSION"
cp "$LOCAL_SESSION" "$BIONIC_SESSION"
chmod 600 "$BIONIC_SESSION"

echo "✅ Saved local model session to $LOCAL_SESSION (mode 0600)."
