#!/bin/bash
#
# DeQ - Installation Script
#

set -e

echo "================================================================"
echo "              DeQ - Admin Dashboard Installer                   "
echo "================================================================"
echo "                    DeQ RUNS AS ROOT!                           "
echo "          DO NOT directly expose to public internet!            "
echo "Learn about VPN, Wireguard and Tailscale before installing DeQ! "
echo "                     THIS IS NO JOKE!                           "
echo "================================================================"
echo "  By installing, you accept full responsibility for securing    "
echo "  your system. The authors are not liable for any damages.      "
echo "================================================================"
echo ""
read -p "I understand the risks and want to continue [y/N]: " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 1
fi
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root (sudo ./install.sh)"
    exit 1
fi

# Get server IP
DEFAULT_IP=$(hostname -I | awk '{print $1}')
echo "Your server IP addresses: $(hostname -I)"
read -p "Server IP for remote access [$DEFAULT_IP]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$DEFAULT_IP}

# Get port
read -p "Port [5050]: " PORT
PORT=${PORT:-5050}
echo ""

echo "Installing to /opt/deq..."

# Create directories
mkdir -p /opt/deq/fonts
mkdir -p /opt/deq/history

# Copy files
cp server.py /opt/deq/
chmod +x /opt/deq/server.py

# Copy fonts if present
if [ -d "fonts" ] && [ "$(ls -A fonts 2>/dev/null)" ]; then
    cp fonts/* /opt/deq/fonts/
    echo "[OK] Fonts installed"
else
    echo "[INFO] No fonts found. Download JetBrains Mono manually:"
    echo "       https://github.com/JetBrains/JetBrainsMono/releases"
    echo "       Extract .woff2 files to /opt/deq/fonts/"
fi

# Install systemd service
cat > /etc/systemd/system/deq.service << EOF
[Unit]
Description=DeQ - Homelab Dashboard
After=network.target docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/deq/server.py --port $PORT
WorkingDirectory=/opt/deq
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable deq

# Create initial config with correct host IP (if no config exists)
if [ ! -f "/opt/deq/config.json" ]; then
    cat > /opt/deq/config.json << EOFCONFIG
{
  "settings": {"theme": "dark", "text_color": "#e0e0e0", "accent_color": "#2ed573"},
  "links": [],
  "devices": [
    {
      "id": "host",
      "name": "DeQ Host",
      "ip": "$SERVER_IP",
      "icon": "server",
      "is_host": true
    }
  ],
  "tasks": []
}
EOFCONFIG
    echo "[OK] Initial config created with host IP: $SERVER_IP"
fi

systemctl start deq

# Wait for service to start
sleep 2

echo ""
echo "================================================================"
echo "  Installation complete!                                       "
echo "================================================================"
echo ""
echo "  Access URL:"
echo "  http://$SERVER_IP:$PORT/"
echo ""
echo " Important! Use Tailscale or another VPN for secure remote access."
echo ""
echo "  Configure everything through the web interface:"
echo "  1. Open the URL"
echo "  2. Click the pencil icon to enter edit mode"
echo "  3. Add links, devices and tasks"
echo ""
echo "================================================================"
echo ""
echo "Commands:"
echo "  systemctl status deq    # Check status"
echo "  systemctl restart deq   # Restart"
echo "  journalctl -u deq -f    # View logs"
echo ""
echo "Configuration is stored in:"
echo "  /opt/deq/config.json"
echo ""

# SSH hint
echo "================================================================"
echo "  For SSH features (stats, shutdown)"
echo "================================================================"
echo ""
echo "  1. Generate SSH key (if needed):"
echo "     ssh-keygen -t ed25519"
echo ""
echo "  2. Copy to target devices:"
echo "     ssh-copy-id user@device-ip"
echo ""
echo "  3. Copy key to root (DeQ runs as root):"
echo "     sudo mkdir -p /root/.ssh"
echo "     sudo cp ~/.ssh/id_ed25519* /root/.ssh/"
echo "     sudo chmod 600 /root/.ssh/id_ed25519"
echo ""
echo "  4. Test as root:"
echo "     sudo ssh user@device-ip 'echo OK'"
echo ""
echo "================================================================"
