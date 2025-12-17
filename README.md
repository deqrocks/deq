# DeQ
<p align="center">Rethinking homelab tools. Less complexity, more control.<p align="center"></p>

<p align="center">A bare-metal homelab admin deck with root access and Android monitoring app. Small enough to live alongside Pi-hole on a Pi Zero. Capable enough to control your entire network. Get notifications on your smartphone when things go wrong.</p>

![DeQ Hero](assets/DeQ-Hero.jpg)

**Website:** [deq.rocks](https://deq.rocks) · **Support:** [Patreon](https://patreon.com/deqrocks)

## Concept

**DeQ runs bare metal, not in Docker.**

It's designed for low-power devices that are already online 24/7 - a Pi, a mini PC, even a WRT router. These give you always-on access to your homelab via Tailscale or LAN, without the overhead of a full server.
Docker would add overhead and break core features: Wake-on-LAN needs raw sockets, the file manager needs your filesystem, SSH and rsync run as host processes, and shutdown commands don't work from inside a container.
DeQ bridges monitoring and control - with a minimal footprint as its core principle. One file, focused scope, no bloat.

**This comes with responsibility.**

DeQ runs as root and has direct access to your system. That's what makes features like WOL, file transfers, and remote shutdown possible - but it also means you should never expose it to the public internet.

- Use Tailscale, Wireguard or another VPN for remote access
- Only run DeQ on trusted networks

## Features

- **Android Companion app** - free app for your smartphone to manage your servers or get notified when things go wrong
- **Device Control** - Wake-on-LAN, shutdown, Docker start/stop
- **Scheduled Tasks** - Automated backups, wake and shutdown
- **File Manager** - Dual-pane file browser, copy/move/upload between devices
- **System Stats** - CPU, RAM, temperature, disk usage
- **Quick Links** - Bookmarks to your services with custom icons (Lucide or Dashboard Icons)
- **Theming** - Custom colors, wallpapers, and transparency/blur effects
- **PWA Support** - Install as web app on any desktop or smartphone

## Installation

```bash
wget https://github.com/deqrocks/deq/releases/latest/download/deq.zip
unzip deq.zip -d deq && cd deq
sudo ./install.sh
```

The installer asks a few questions (IP, port) and gives you your access URL.

## Getting Started
<p align="center"><img src="assets/DeQ-Onboarding-Devices.jpg" width="700"></p>

1. Open your DeQ URL in a browser (like 192.168.1.1:5050)
2. Follow the onboarding dialog to scan your network for devices and containers
3. Click the pencil icon to edit existing items or to add devices manually
4. Add links and notes - assign icons
5. Drag links or devices to reorder them
6. Click the layout button (eco/1/4/2/4/4/4) to change link arrangement
7. Click the eye icon to hide sections you don't need
8. Click the palette icon to toggle monochrome icons
9. Scroll down to the Theme section to customize colors and wallpaper

The server running DeQ is automatically added as the "Host" device with local stats.

## Icons

Links and devices support three icon sources:

| Format | Example | Description |
|--------|---------|-------------|
| Lucide | `server` | Default. See [lucide.dev/icons](https://lucide.dev/icons) |
| Dashboard Icons | `dash:proxmox` | Self-hosted app icons. See [dashboardicons.com](https://dashboardicons.com) |
| Custom URL | `https://...` | Any image URL |

In edit mode, click the palette icon next to "Links" to toggle monochrome mode for all icons.

## Adding Devices
<p align="center"><img src="assets/DeQ-Device-Features.jpg" width="700"></p>

**Manually**

You can manually add devices by activating the edit mode > go to the devices section > click "+".
After you added the device you can manually add containers or scan for containers running on that device.

**Using the Wizard**

You can automatically add devices and containers by using the wizard: activate edit mode > go to the devices section > click "scan". Add your devices and SSH user name. Next step it will scan for Docker containers. Make sure to have ssh keypairs exchanged for that to work.

Each device can have:

| Feature | What it does |
|---------|--------------|
| **Wake-on-LAN** | Power on the device remotely |
| **Quick Connect** | Buttons for RDP, VNC, or web interfaces |
| **Docker** | Scan for containers or add manually, start/stop, optional RDP/VNC/Web buttons |
| **SSH** | Enables stats and shutdown for remote devices |


### Understanding IP addresses

DeQ uses different IPs for different purposes:

- **Local IP** (device settings): Always your LAN IP (192.168.x.x). Used by the DeQ server for Wake-on-LAN, SSH connections, and ping checks.

- **Quick Connect / Docker IPs**: These are for your browser/phone to connect. Use LAN IPs when at home, or Tailscale IPs when accessing remotely.

**Example with Tailscale:**
- Device Local IP: `192.168.1.100` (for WOL/SSH)
- Docker VNC: `100.x.x.x:8006` (Tailscale IP, so VNC works from anywhere)

### Connecting via SSH (optional)

To see stats or shutdown remote devices, DeQ needs SSH access. This is optional - devices without SSH still work for Wake-on-LAN and links.

**Quick setup:**
```bash
# Generate a key (skip if you already have one)
ssh-keygen -t ed25519

# Copy it to your device
ssh-copy-id user@device-ip

# DeQ runs as root, so copy the key there too
sudo cp ~/.ssh/id_ed25519* /root/.ssh/
sudo chmod 600 /root/.ssh/id_ed25519

# Test it
sudo ssh user@device-ip 'echo OK'
```

## Remote Access

DeQ has no built-in authentication. For secure remote access, use [Tailscale](https://tailscale.com) or another VPN. Access DeQ via your Tailscale IP.

## Scheduled Tasks
<p align="center"><img src="assets/DeQ-Task-Wizard.jpg" width="700"></p>

DeQ can run tasks automatically:

- **Wake** - Power on a device or start a Docker container
- **Shutdown** - Power off a device or stop a Docker container
- **Backup** - Sync files between devices using rsync

Example workflow: Wake your NAS at 3 AM, run a backup from your main server, shut it down when done.

## File Manager
<p align="center"><img src="assets/DeQ-File-Manager.jpg" width="700"></p>

Click the folder icon (top right) to open the dual-pane file manager. Browse files on any device with SSH configured. File Manager will also work on your smartphone. BE CAREFUL with what you're doing in the root folder!

**Features:**
- Copy and move files between devices
- Upload files (button or drag & drop)
- Delete files
- Create new Folders
- Create zip archives (or tar.gz as fallback)
- Download individual files

**Navigation:**
- Click to select (single pane only)
- Double-click to open folders
- Drag files from your desktop to upload

## Theming

In edit mode, scroll down to the Theme section to customize the look:

| Setting | Description |
|---------|-------------|
| **Colors** | Background, cards, borders, text, accent color |
| **Transparency** | Transparency effect for cards (0-100%) |
| **Blur** | Background blur amount (0-30px) |
| **Wallpaper** | Background image URL (https://...) |

Click "Reset to Defaults" to restore the original dark theme.

## Mobile App

Control your homelab from your phone - check stats, wake devices, manage containers.

### Android

Native Android apps for DeQ - faster startup, background notifications, no browser needed.

**Download:** Free app from the releases on github, Pro app coming soon on Playstore**

#### Free vs Pro

| Feature | DeQ (Free) | DeQ Pro (€4.99) |
|---------|------------|-----------------|
| WebView Dashboard | ✓ | ✓ |
| Background Polling | 30 min | custom |
| Push Notifications | ✓ | ✓ |
| Android Auto | ✗ | ✓ |

**Why a paid version?**

Unlike Patreon tiers with "exclusive updates" or "Discord access", the paid app offers real features that take real work to build:

- **Custom Polling**: Set your own interval - from seconds to hours
- **Android Auto**: Check your homelab status from your car's dashboard

Your support keeps this project alive as a full-time effort.

### iOS

Install DeQ as a PWA: Safari → Share → Add to Home Screen. Works like a native app.
Native iOS app planned when funding allows.

## Desktop App
<p align="center"><img src="assets/DeQ-PWA-Desktop.jpg" width="700"></p>

Install DeQ as a desktop app - no more hunting through browser tabs. One click in your dock or taskbar, and you're in.

**Why install as an app?**
- Clean window without browser UI
- Lives in your dock/taskbar - always one click away
- No tabs to dig through
- Same interface, instant access

**How to install:**

| Platform | Steps |
|----------|-------|
| **macOS (Safari)** | File → Add to Dock |
| **macOS (Chrome)** | Menu (⋮) → "Cast, save, and share" → "Install page as app..." |
| **Windows (Edge)** | Menu (···) → Apps → "Install this site as an app" |
| **Windows (Chrome)** | Menu (⋮) → "Cast, save, and share" → "Install page as app..." |
| **Linux** | Chrome → Menu (⋮) → "Cast, save, and share" → "Install page as app..." |

Once installed, DeQ opens in its own window and lives in your dock.

## Service Commands

```bash
sudo systemctl status deq     # Check status
sudo systemctl restart deq    # Restart
sudo journalctl -u deq -f     # View logs
```

## Data Storage

All data is stored in `/opt/deq/config.json`. To backup: just copy `config.json`. To restore: copy it back and restart.

## Updating

To update DeQ, download the latest release and run the installer again:

```bash
wget https://github.com/deqrocks/deq/releases/download/stable/deq.zip
unzip deq.zip -d deq && cd deq
sudo ./install.sh
```

Your `config.json` is preserved - the installer only overwrites `server.py`.

## Uninstall

```bash
sudo systemctl stop deq
sudo systemctl disable deq
sudo rm /etc/systemd/system/deq.service
sudo rm -rf /opt/deq
sudo systemctl daemon-reload
```

Or as single command

```bash
sudo systemctl stop deq && sudo systemctl disable deq && sudo rm /etc/systemd/system/deq.service && sudo rm -rf /opt/deq && sudo systemctl daemon-reload
```

## Disclaimer

DeQ is provided "as is" without warranty. The authors are not liable for any damages resulting from its use. By installing DeQ, you accept full responsibility for securing your system. See [LICENSE](LICENSE) for details.

## License

CC BY-NC 4.0 - Free for personal use, no commercial use without permission. See [LICENSE](LICENSE).

## Credits

- [Lucide Icons](https://lucide.dev)
- [Dashboard Icons](https://github.com/walkxcode/dashboard-icons)
- [JetBrains Mono](https://www.jetbrains.com/mono/)
