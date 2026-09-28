#!/usr/bin/env bash
# ==============================================================================
# MASA Subscription Login: Local AI / BIONIC LMS
# Alias that delegates to login_local.sh for flexible local AI configuration.
# Defaults to localhost and auto-queries models.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/login_local.sh" ]; then
    exec "$SCRIPT_DIR/login_local.sh" "$@"
fi

echo "Error: login_local.sh not found."
exit 1
