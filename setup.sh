#!/usr/bin/env bash
set -e

echo "========================================="
echo "  PENT - Penetration Testing Assistant   "
echo "  Setup Script                           "
echo "========================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is required but not installed."
    echo "    Install: sudo apt install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Python $PYTHON_VERSION found"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt --quiet

echo ""
echo "[+] Checking optional system tools..."

# Check for optional tools
tools=("nmap" "whois" "dig" "curl" "git")
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "    [+] $tool - installed"
    else
        echo "    [-] $tool - not found (optional)"
    fi
done

echo ""
echo "========================================="
echo "  Setup complete!                        "
echo "========================================="
echo ""
echo "  Web UI (recommended):"
echo "    source venv/bin/activate"
echo "    python web/server.py                 # Start web server"
echo "    Open http://localhost:5000            # Open in browser"
echo ""
echo "  CLI mode:"
echo "    source venv/bin/activate"
echo "    python pent.py                       # Interactive CLI"
echo "    python pent.py --help                # All CLI options"
echo ""
