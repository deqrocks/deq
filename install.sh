#!/bin/bash
#
# DeQ - Installation Script
#
# Usage:
#   ./install.sh              # Full installation
#   ./install.sh --set-password    # Set/change admin password
#   ./install.sh --remove-password # Remove password (disable auth)
#

set -e

DATA_DIR="/opt/deq"

# Password management functions
set_password() {
    echo ""
    read -s -p "Enter admin password: " password1
    echo ""
    read -s -p "Confirm password: " password2
    echo ""

    if [ "$password1" != "$password2" ]; then
        echo "[ERROR] Passwords do not match"
        exit 1
    fi

    if [ -z "$password1" ]; then
        echo "[ERROR] Password cannot be empty"
        exit 1
    fi

    hash=$(echo -n "$password1" | python3 -c "
import hashlib, secrets, sys
password = sys.stdin.buffer.read().decode('utf-8')
salt = secrets.token_bytes(16)
key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32)
print(salt.hex() + ':' + key.hex())
")

    echo "$hash" > "$DATA_DIR/.password"
    chmod 600 "$DATA_DIR/.password"

    # Invalidate all sessions
    rm -f "$DATA_DIR/.session_secret"

    # Restart service if running
    if systemctl is-active --quiet deq; then
        systemctl restart deq
        echo "[OK] Password set. Service restarted."
    else
        echo "[OK] Password set."
    fi
    echo ""
}

remove_password() {
    rm -f "$DATA_DIR/.password"
    rm -f "$DATA_DIR/.session_secret"

    # Restart service if running
    if systemctl is-active --quiet deq; then
        systemctl restart deq
        echo "[OK] Password removed. Service restarted."
    else
        echo "[OK] Password removed. Authentication disabled."
    fi
    echo ""
}

# Handle --set-password and --remove-password
if [ "$1" = "--set-password" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] Please run as root (sudo ./install.sh --set-password)"
        exit 1
    fi
    set_password
    exit 0
fi

if [ "$1" = "--remove-password" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] Please run as root (sudo ./install.sh --remove-password)"
        exit 1
    fi
    remove_password
    exit 0
fi

echo "================================================================"
echo "              DeQ - Admin Control Plane Installer                   "
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
mkdir -p /opt/deq/scripts

# Copy files
cp server.py /opt/deq/
chmod +x /opt/deq/server.py

# Install fonts
rm -rf /opt/deq/fonts/*
cp fonts/* /opt/deq/fonts/
echo "[OK] Fonts installed"

# Install systemd service
cat > /etc/systemd/system/deq.service << EOF
[Unit]
Description=DeQ - Homelab Control Plane
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

systemctl restart deq

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
