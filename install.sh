#!/bin/sh
# ==============================================================================
# MASA One-Click Installer
# Installs MASA CLI, configures shell access, and pre-approves workspace trust.
# Fully POSIX-compliant (works on any Linux distribution, Alpine, and macOS).
# ==============================================================================

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$HOME/.local/bin"

echo "======================================================================"
echo " 🚀 Installing MASA (Multi-Agent Scaffolding Architecture)"
echo " Repository Location: $REPO_DIR"
echo "======================================================================"

# 1. Verify Python 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Error: python3 is required but not installed."
    echo "Please install Python 3.9 or higher and rerun this installer."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Found Python $PY_VERSION"

# 2. Ensure ~/.local/bin exists and is in PATH
mkdir -p "$BIN_DIR"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo "Adding $BIN_DIR to current session PATH..."
        export PATH="$BIN_DIR:$PATH"
        ;;
esac

# 3. Install MASA via pip or direct wrapper
echo "Registering 'masa' CLI command..."
if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
    python3 -m pip install -e "$REPO_DIR" --quiet 2>/dev/null || {
        echo "Pip install in user environment had restrictions; creating direct launcher..."
        cat <<EOF > "$BIN_DIR/masa"
#!/bin/sh
exec python3 "$REPO_DIR/framework.py" "\$@"
EOF
        chmod +x "$BIN_DIR/masa"
        cp "$BIN_DIR/masa" "$BIN_DIR/maso"
    }
else
    cat <<EOF > "$BIN_DIR/masa"
#!/bin/sh
exec python3 "$REPO_DIR/framework.py" "\$@"
EOF
    chmod +x "$BIN_DIR/masa"
    cp "$BIN_DIR/masa" "$BIN_DIR/maso"
fi

# 4. Make all helper scripts executable
chmod +x "$REPO_DIR/scripts/"*.sh 2>/dev/null || true

# 5. Build sandbox worker image if Podman or Docker is available
if command -v podman >/dev/null 2>&1; then
    echo "Building hardened worker image via Podman (rootless)..."
    podman build -t maso-skill-worker:v1.1 -f "$REPO_DIR/Containerfile.worker" "$REPO_DIR" >/dev/null 2>&1 || true
    podman tag localhost/maso-skill-worker:v1.1 maso-skill-worker:latest >/dev/null 2>&1 || true
elif command -v docker >/dev/null 2>&1; then
    echo "Building worker image via Docker..."
    docker build -t maso-skill-worker:v1.1 -f "$REPO_DIR/Containerfile.worker" "$REPO_DIR" >/dev/null 2>&1 || true
    docker tag maso-skill-worker:v1.1 maso-skill-worker:latest >/dev/null 2>&1 || true
fi

# 6. Pre-approve folder trust
echo "Pre-approving workspace trust for Claude and AGY..."
python3 "$REPO_DIR/framework.py" trust "$REPO_DIR" >/dev/null 2>&1 || true

echo "======================================================================"
echo "✅ Installation Complete! The 'masa' command is ready to use."
echo "======================================================================"
echo ""
python3 "$REPO_DIR/framework.py" status
