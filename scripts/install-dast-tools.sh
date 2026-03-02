#!/bin/bash
# VAPT Navigator - DAST tool installation
# Installs all tools per application: katana, ffuf, arjun, Playwright (chromium), trufflehog, retire
# Ref: https://github.com/projectdiscovery/katana
set -e

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
NAV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Installing DAST tools for Navigator..."

# ---------------------------------------------------------------------------
# Ensure backend venv exists (for arjun, Playwright)
# ---------------------------------------------------------------------------
if [ ! -d "$NAV_ROOT/backend/venv" ]; then
    echo "[*] Creating backend venv..."
    python3 -m venv "$NAV_ROOT/backend/venv" 2>/dev/null || python -m venv "$NAV_ROOT/backend/venv" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Go (required for katana, ffuf; katana needs Go 1.24+ per projectdiscovery/katana)
# ---------------------------------------------------------------------------
if ! command -v go &>/dev/null; then
    echo "[*] Installing Go..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y golang-go 2>/dev/null || true
    fi
    if ! command -v go &>/dev/null; then
        GOVERSION="1.22.4"
        wget -q "https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz 2>/dev/null || true
        if [ -f /tmp/go.tar.gz ]; then
            rm -rf /usr/local/go
            tar -C /usr/local -xzf /tmp/go.tar.gz
            export PATH="/usr/local/go/bin:$PATH"
        fi
    fi
fi
export PATH="${PATH}:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin"

# ---------------------------------------------------------------------------
# Katana - ProjectDiscovery web crawler (https://github.com/projectdiscovery/katana)
# Uses -j (jsonl) output, -fs fqdn/rdn/dn scope
# ---------------------------------------------------------------------------
if ! command -v katana &>/dev/null && [ ! -f "$INSTALL_DIR/katana" ]; then
    echo "[*] Installing Katana (projectdiscovery/katana)..."
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || {
        CGO_ENABLED=0 go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
    }
    if [ -f "$(go env GOPATH)/bin/katana" ] 2>/dev/null; then
        cp "$(go env GOPATH)/bin/katana" "$INSTALL_DIR/katana" 2>/dev/null || true
    fi
else
    echo "[✓] Katana already installed"
fi

# ---------------------------------------------------------------------------
# ffuf - Web fuzzer
# ---------------------------------------------------------------------------
if ! command -v ffuf &>/dev/null && [ ! -f "$INSTALL_DIR/ffuf" ]; then
    echo "[*] Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || {
        echo "[!] ffuf install failed. Try: go install github.com/ffuf/ffuf/v2@latest"
    }
    if [ -f "$(go env GOPATH)/bin/ffuf" ] 2>/dev/null; then
        cp "$(go env GOPATH)/bin/ffuf" "$INSTALL_DIR/ffuf" 2>/dev/null || true
    fi
else
    echo "[✓] ffuf already installed"
fi

# ---------------------------------------------------------------------------
# Arjun - Parameter discovery (pip)
# ---------------------------------------------------------------------------
if [ -d "$NAV_ROOT/backend/venv" ]; then
    source "$NAV_ROOT/backend/venv/bin/activate"
    if ! python -c "import arjun" 2>/dev/null; then
        echo "[*] Installing Arjun..."
        pip install -q arjun 2>/dev/null || echo "[!] Arjun install failed: pip install arjun"
    else
        echo "[✓] Arjun already installed"
    fi
    deactivate 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# TruffleHog - secret scanning (Go binary or prebuilt)
# ---------------------------------------------------------------------------
if ! command -v trufflehog &>/dev/null && [ ! -f "$INSTALL_DIR/trufflehog" ]; then
    echo "[*] Installing TruffleHog (secrets)..."
    INSTALLED=0
    if command -v go &>/dev/null; then
        go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null && {
            if [ -f "$(go env GOPATH)/bin/trufflehog" ] 2>/dev/null; then
                cp "$(go env GOPATH)/bin/trufflehog" "$INSTALL_DIR/trufflehog" 2>/dev/null && INSTALLED=1
            fi
        }
    fi
    if [ "$INSTALLED" != "1" ]; then
        echo "[*] Trying prebuilt TruffleHog binary (no Go required)..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$INSTALL_DIR" 2>/dev/null && INSTALLED=1 || true
    fi
    if [ "$INSTALLED" != "1" ]; then
        echo "[!] TruffleHog install failed. Try: go install github.com/trufflesecurity/trufflehog/v3@latest or install script"
    fi
else
    echo "[✓] TruffleHog already installed"
fi

# ---------------------------------------------------------------------------
# Retire.js - JS library vulnerability scan + SBOM
# ---------------------------------------------------------------------------
if ! command -v retire &>/dev/null; then
    echo "[*] Installing Retire.js..."
    npm install -g retire 2>/dev/null || npx retire --version &>/dev/null || echo "[!] Retire.js install failed. Try: npm install -g retire"
else
    echo "[✓] Retire.js already installed"
fi

# ---------------------------------------------------------------------------
# Playwright + Chromium (JS/SPA crawler - required for Spider JS mode)
# Requires system deps for headless Chromium
# ---------------------------------------------------------------------------
PLAYWRIGHT_DEPS="libxcb-shm0 libxrandr2 libxcomposite1 libxcursor1 libxdamage1 libxfixes3 libpangocairo-1.0-0 libpango-1.0-0 libcairo-gobject2 libcairo2 libxrender1 libatk1.0-0 libatk-bridge2.0-0 libgbm1"
if command -v apt-get &>/dev/null; then
    echo "[*] Installing Playwright Chromium system dependencies..."
    apt-get install -y $PLAYWRIGHT_DEPS libasound2t64 2>/dev/null || apt-get install -y $PLAYWRIGHT_DEPS 2>/dev/null || true
fi
if [ -d "$NAV_ROOT/backend/venv" ]; then
    source "$NAV_ROOT/backend/venv/bin/activate"
    if ! python -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
        echo "[*] Installing Playwright (JS/SPA mode)..."
        pip install -q playwright 2>/dev/null || pip install playwright
        echo "[*] Installing Chromium for Playwright..."
        playwright install chromium 2>/dev/null || {
            playwright install chromium 2>/dev/null || echo "[!] Run: playwright install chromium"
        }
    fi
    if python -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
        echo "[✓] Playwright + Chromium installed"
    else
        echo "[!] Playwright: pip install playwright && playwright install chromium"
    fi
    deactivate 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# spider_rs (optional - Python, high-perf crawler fallback)
# ---------------------------------------------------------------------------
if [ -d "$NAV_ROOT/backend/venv" ]; then
    source "$NAV_ROOT/backend/venv/bin/activate"
    if ! python -c "import spider_rs" 2>/dev/null; then
        echo "[*] Installing spider_rs (optional crawler)..."
        pip install -q spider_rs 2>/dev/null || echo "[!] spider_rs install failed (optional): pip install spider_rs"
    else
        echo "[✓] spider_rs already installed"
    fi
    deactivate 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Nuclei (optional - for CVE/template scanning)
# ---------------------------------------------------------------------------
if [ "${INSTALL_NUCLEI:-0}" = "1" ]; then
    if ! command -v nuclei &>/dev/null; then
        echo "[*] Installing Nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo ""
echo "[*] Verification:"
command -v katana &>/dev/null && echo "  katana: $(katana -version 2>/dev/null | head -1 || echo 'ok')" || echo "  katana: NOT FOUND"
command -v ffuf &>/dev/null && echo "  ffuf: $(ffuf -V 2>/dev/null || echo 'ok')" || echo "  ffuf: NOT FOUND"
command -v trufflehog &>/dev/null && echo "  trufflehog: ok" || echo "  trufflehog: NOT FOUND"
command -v retire &>/dev/null && echo "  retire: $(retire --version 2>/dev/null | head -1 || echo 'ok')" || echo "  retire: NOT FOUND"
[ -d "$NAV_ROOT/backend/venv" ] && (source "$NAV_ROOT/backend/venv/bin/activate" && python -c "import arjun; print('  arjun: ok')" 2>/dev/null) || echo "  arjun: (venv not found)"
[ -d "$NAV_ROOT/backend/venv" ] && (source "$NAV_ROOT/backend/venv/bin/activate" && python -c "from playwright.sync_api import sync_playwright; print('  playwright+chromium: ok')" 2>/dev/null) || echo "  playwright: (venv not found)"
[ -d "$NAV_ROOT/backend/venv" ] && (source "$NAV_ROOT/backend/venv/bin/activate" && python -c "import spider_rs; print('  spider_rs: ok')" 2>/dev/null) || echo "  spider_rs: (optional)"
echo "[*] Done."
