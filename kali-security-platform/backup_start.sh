#!/bin/bash
#
# Kali Security Platform - Quick Start Script
# Hızlı ve kolay başlatma
#

echo "
╔══════════════════════════════════════════════════════════════╗
║     KALI SECURITY SCANNER - QUICK START                      ║
╚══════════════════════════════════════════════════════════════╝
"

# Check if running on Kali
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[*] OS Detected: $NAME"
fi

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install fastapi uvicorn requests aiohttp 2>/dev/null || {
    echo "[!] Some packages failed to install, but continuing..."
}

# Create necessary directories
echo "[+] Creating directories..."
mkdir -p outputs logs templates

# Check if tools are available
echo "[+] Checking tools..."
command -v nmap >/dev/null 2>&1 && echo "  ✓ Nmap found" || echo "  ✗ Nmap not found"
command -v dig >/dev/null 2>&1 && echo "  ✓ Dig found" || echo "  ✗ Dig not found"
command -v whois >/dev/null 2>&1 && echo "  ✓ Whois found" || echo "  ✗ Whois not found"
command -v curl >/dev/null 2>&1 && echo "  ✓ Curl found" || echo "  ✗ Curl not found"

# Start the platform
echo ""
echo "[+] Starting Kali Security Scanner..."
echo "[+] Opening browser in 3 seconds..."
sleep 3

# Open browser
firefox http://localhost:8000 2>/dev/null &

# Run the platform
python3 main_simple.py
