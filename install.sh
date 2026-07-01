#!/bin/bash
# Guardian — One-command install
# Run: curl -sL https://raw.githubusercontent.com/gnaixnaij/guardian/main/install.sh | bash

set -e

echo "🛡️ Installing Guardian EDR..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Install it first: sudo apt install python3 python3-pip"
    exit 1
fi

# Install deps
echo "📦 Installing Python dependencies..."
pip3 install psutil flask pyyaml --quiet 2>/dev/null || pip install psutil flask pyyaml --quiet

# Download guardian
echo "📥 Downloading Guardian..."
mkdir -p ~/guardian
curl -sL "https://raw.githubusercontent.com/gnaixnaij/guardian/main/guardian.py" -o ~/guardian/guardian.py
curl -sL "https://raw.githubusercontent.com/gnaixnaij/guardian/main/agent/monitor.py" -o ~/guardian/agent/monitor.py 2>/dev/null || mkdir -p ~/guardian/agent
curl -sL "https://raw.githubusercontent.com/gnaixnaij/guardian/main/detector/engine.py" -o ~/guardian/detector/engine.py 2>/dev/null || mkdir -p ~/guardian/detector
curl -sL "https://raw.githubusercontent.com/gnaixnaij/guardian/main/dashboard/app.py" -o ~/guardian/dashboard/app.py 2>/dev/null || mkdir -p ~/guardian/dashboard

# Make executable
chmod +x ~/guardian/guardian.py

echo ""
echo "✅ Guardian installed!"
echo ""
echo "▶️  Run with dashboard:  cd ~/guardian && python3 guardian.py"
echo "▶️  Run headless:        cd ~/guardian && python3 guardian.py --headless"
echo "📊  Dashboard:           http://localhost:5000"
echo ""
echo "💡 To run as a service, create a systemd unit or use: nohup python3 guardian.py &"
