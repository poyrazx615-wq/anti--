#!/bin/bash
# Kali Security Platform - Simple Installation Script

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     KALI SECURITY PLATFORM - KURULUM                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo "[!] Warning: This script is optimized for Kali Linux"
fi

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
echo "[+] Creating directories..."
mkdir -p outputs/scans outputs/reports logs

# Set permissions
echo "[+] Setting permissions..."
chmod +x main.py
chmod +x setup.sh
chmod +x install.sh

# Check if .env exists
if [ ! -f .env ]; then
    echo "[+] Creating .env file from template..."
    cp .env.example .env 2>/dev/null || cp .env .env.backup
fi

echo "[✓] Installation complete!"
echo ""
echo "To start the platform:"
echo "  python3 main.py"
echo ""
echo "Access the platform at:"
echo "  http://localhost:8000"
