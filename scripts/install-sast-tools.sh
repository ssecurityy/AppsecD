#!/bin/bash
# VAPT Navigator - SAST tool installation
# Installs: Semgrep (pip), Trivy (optional), Gitleaks (optional). TruffleHog is in install-dast-tools.sh.
# Run from repo root: ./scripts/install-sast-tools.sh
set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
NAV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Installing SAST tools for Navigator..."

# ---------------------------------------------------------------------------
# Semgrep (required for SAST code scanning)
# ---------------------------------------------------------------------------
if [ -d "$NAV_ROOT/backend/venv" ]; then
    source "$NAV_ROOT/backend/venv/bin/activate"
    if ! python -c "import semgrep" 2>/dev/null; then
        echo "[*] Installing Semgrep..."
        pip install -q "semgrep>=1.95.0" 2>/dev/null || pip install "semgrep>=1.95.0"
    else
        echo "[✓] Semgrep already installed ($(semgrep --version 2>/dev/null | head -1 || echo 'ok'))"
    fi
    deactivate 2>/dev/null || true
else
    echo "[!] Backend venv not found. Create it and run: pip install semgrep>=1.95.0"
fi

# ---------------------------------------------------------------------------
# Go (for Gitleaks / Trivy if built from source)
# ---------------------------------------------------------------------------
export PATH="${PATH}:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin"
if ! command -v go &>/dev/null && [ "${INSTALL_TRIVY:-0}" = "1" ] || [ "${INSTALL_GITLEAKS:-0}" = "1" ]; then
    echo "[*] Go not found; install Go to build Gitleaks/Trivy, or use package manager."
fi

# ---------------------------------------------------------------------------
# Gitleaks (optional - fast secret scanner, 150+ rules)
# ---------------------------------------------------------------------------
if [ "${INSTALL_GITLEAKS:-1}" = "1" ]; then
    if ! command -v gitleaks &>/dev/null && [ ! -f "$INSTALL_DIR/gitleaks" ]; then
        echo "[*] Installing Gitleaks..."
        INSTALLED=0
        if command -v go &>/dev/null; then
            go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null && {
                if [ -f "$(go env GOPATH)/bin/gitleaks" ] 2>/dev/null; then
                    cp "$(go env GOPATH)/bin/gitleaks" "$INSTALL_DIR/gitleaks" 2>/dev/null && INSTALLED=1
                fi
            }
        fi
        if [ "$INSTALLED" != "1" ] && command -v curl &>/dev/null; then
            GITHUB_LATEST=$(curl -sSfL "https://api.github.com/repos/gitleaks/gitleaks/releases/latest" | grep -o '"tag_name": "[^"]*"' | cut -d'"' -f4)
            [ -n "$GITHUB_LATEST" ] && {
                case "$(uname -m)" in
                    aarch64|arm64) ARCH="arm64" ;;
                    x86_64|amd64) ARCH="x64" ;;
                    *)             ARCH="x64" ;;
                esac
                case "$(uname -s)" in
                    Linux)  OS="linux" ;;
                    Darwin) OS="darwin" ;;
                    *)      OS="linux" ;;
                esac
                VER="${GITHUB_LATEST#v}"
                URL="https://github.com/gitleaks/gitleaks/releases/download/${GITHUB_LATEST}/gitleaks_${VER}_${OS}_${ARCH}.tar.gz"
                if curl -sSfL "$URL" | tar -xzf - -C "$INSTALL_DIR" 2>/dev/null; then
                    [ -f "$INSTALL_DIR/gitleaks" ] && chmod +x "$INSTALL_DIR/gitleaks" && INSTALLED=1
                fi
            }
        fi
        [ "$INSTALLED" = "1" ] && echo "[✓] Gitleaks installed" || echo "[!] Gitleaks install failed. Try: go install github.com/gitleaks/gitleaks/v8@latest"
    else
        echo "[✓] Gitleaks already installed"
    fi
fi

# ---------------------------------------------------------------------------
# Trivy (optional - container/image and filesystem scanning)
# ---------------------------------------------------------------------------
if [ "${INSTALL_TRIVY:-0}" = "1" ]; then
    if ! command -v trivy &>/dev/null && [ ! -f "$INSTALL_DIR/trivy" ]; then
        echo "[*] Installing Trivy..."
        if command -v curl &>/dev/null; then
            curl -sSfL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" | sh -s -- -b "$INSTALL_DIR" 2>/dev/null && echo "[✓] Trivy installed" || echo "[!] Trivy install failed"
        else
            echo "[!] Install curl or run: go install github.com/aquasecurity/trivy/cmd/trivy@latest"
        fi
    else
        echo "[✓] Trivy already installed"
    fi
fi

# ---------------------------------------------------------------------------
# TruffleHog (shared with DAST - ensure present for SAST secret scan)
# ---------------------------------------------------------------------------
if ! command -v trufflehog &>/dev/null && [ ! -f "$INSTALL_DIR/trufflehog" ]; then
    echo "[*] TruffleHog not found. Run scripts/install-dast-tools.sh for full secret coverage."
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo ""
echo "[*] SAST tool verification:"
[ -d "$NAV_ROOT/backend/venv" ] && (source "$NAV_ROOT/backend/venv/bin/activate" && (semgrep --version 2>/dev/null | head -1 || echo "  semgrep: NOT FOUND") && deactivate 2>/dev/null) || echo "  semgrep: (venv not found)"
command -v gitleaks &>/dev/null && echo "  gitleaks: $(gitleaks version 2>/dev/null | head -1 || echo 'ok')" || echo "  gitleaks: NOT FOUND (optional)"
command -v trivy &>/dev/null && echo "  trivy: $(trivy --version 2>/dev/null | head -1 || echo 'ok')" || echo "  trivy: NOT FOUND (optional)"
command -v trufflehog &>/dev/null && echo "  trufflehog: ok" || echo "  trufflehog: NOT FOUND (run install-dast-tools.sh)"
echo "[*] Done."
