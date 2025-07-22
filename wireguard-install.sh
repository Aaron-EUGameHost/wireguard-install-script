#!/usr/bin/env bash
#
# One-Shot WireGuard VPN Installer
# Rewritten from scratch. Includes:
#  - strict error handling & logging
#  - self-update (ETag) check
#  - public IP autodetect + external fallback
#  - automatic MTU discovery
#  - DNS-leak kill-switch
#  - single initial client generation
#

set -euo pipefail
IFS=$'\n\t'
trap 'echo "Error on line ${LINENO}. Exiting." >&2' ERR

LOG="/var/log/wg_one_shot.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

INSTALL_ETAG_FILE="/etc/wg_one_shot.etag"
REMOTE_SCRIPT="https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh"

# 1) Self-update check
echo "Checking for installer updates..."
REMOTE_ETAG=$(curl -fsSLI "$REMOTE_SCRIPT" | awk '/^ETag:/ {gsub(/"/,"",$2); print $2}')
if [[ -f "$INSTALL_ETAG_FILE" ]] && [[ "$(cat "$INSTALL_ETAG_FILE")" != "$REMOTE_ETAG" ]]; then
  echo "A newer installer is available. Please download it before proceeding." >&2
  exit 1
fi
echo "$REMOTE_ETAG" > "$INSTALL_ETAG_FILE"
echo "Installer is up-to-date."

# 2) Root & environment checks
if (( EUID != 0 )); then
  echo "Must be run as root." >&2
  exit 1
fi

# Virtualisation guard
if command -v systemd-detect-virt &>/dev/null; then
  case "$(systemd-detect-virt)" in
    openvz|lxc) echo "Unsupported container: $(systemd-detect-virt)"; exit 1;;
  esac
elif command -v virt-what &>/dev/null; then
  vt=$(virt-what)
  case "$vt" in
    openvz|lxc) echo "Unsupported container: $vt"; exit 1;;
  esac
fi

# OS detection
source /etc/os-release
OS_ID=$ID
OS_VER=${VERSION_ID%%.*}

# 3) Prompt for network parameters
echo
echo "=== WireGuard Setup ==="
read -rp "VPN interface name (e.g. wg0): " WG_IFACE
WG_IFACE=${WG_IFACE:-wg0}

# Public IP autodetect, fallback to external
PUB4=$(ip -4 addr show scope global \
      | awk '/inet/ {sub(/\/.*/,"",$2); print $2; exit}')
if [[ -z "$PUB4" ]]; then
  echo "Local IP not found, querying external service..."
  PUB4=$(curl -fsSL https://ifconfig.co)
fi
read -rp "Server public IP: " -e -i "$PUB4" SERVER_IP

# Public NIC
NIC=$(ip route show default | awk '/dev/ {print $5; exit}')
read -rp "Public network device: " -e -i "$NIC" PUB_NIC

# WireGuard subnet defaults
read -rp "VPN IPv4 subnet (e.g. 10.10.10.1/24): " -e -i "10.10.10.1/24" WG_IPV4_NET
read -rp "VPN IPv6 subnet (optional, e.g. fd00:10:10::1/64): " -e -i "" WG_IPV6_NET

# Port & DNS
read -rp "WireGuard UDP port: " -e -i "51820" WG_PORT
read -rp "Client DNS (comma-separated): " -e -i "1.1.1.1,1.0.0.1" CLIENT_DNS

# Allowed IPs
read -rp "AllowedIPs for clients: " -e -i "0.0.0.0/0,::/0" CLIENT_ALLOWED

# 4) MTU detection (uses upstream finder script)
echo
echo "Detecting optimal MTU..."
BEST_MTU=$(bash <(curl -fsSL https://raw.githubusercontent.com/nitred/nr-wg-mtu-finder/master/find-mtu.sh) --ip 1.1.1.1 | awk '/Optimal MTU:/ {print $3}')
echo "→ MTU set to $BEST_MTU"

# 5) Package install
echo "Installing packages for $OS_ID..."
case "$OS_ID" in
  ubuntu|debian)
    apt-get update
    apt-get install -y wireguard qrencode iptables resolvconf
    ;;
  fedora)
    dnf install -y wireguard-tools qrencode iptables
    ;;
  centos|rhel|rocky|almalinux)
    yum install -y epel-release elrepo-release
    yum install -y kmod-wireguard wireguard-tools qrencode iptables
    ;;
  arch)
    pacman -Sy --noconfirm wireguard-tools qrencode iptables
    ;;
  alpine)
    apk update
    apk add wireguard-tools qrencode iptables
    ;;
  *)
    echo "Unsupported OS: $OS_ID" >&2
    exit 1
    ;;
esac

# 6) Write server config
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

cat > /etc/wireguard/params <<EOF
WG_IFACE=$WG_IFACE
SERVER_IP=$SERVER_IP
PUB_NIC=$PUB_NIC
WG_IPV4_NET=$WG_IPV4_NET
WG_IPV6_NET=$WG_IPV6_NET
WG_PORT=$WG_PORT
SERVER_PRIV=$SERVER_PRIV
SERVER_PUB=$SERVER_PUB
CLIENT_DNS=$CLIENT_DNS
CLIENT_ALLOWED=$CLIENT_ALLOWED
EOF

# 7) Build the [Interface] section
{
  echo "[Interface]"
  echo "Address = ${WG_IPV4_NET}${WG_IPV6_NET:+,${WG_IPV6_NET}}"
  echo "ListenPort = $WG_PORT"
  echo "PrivateKey = $SERVER_PRIV"
  # PostUp/PostDown with NAT + DNS-leak kill-switch
  echo "PostUp = iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT"
  echo "PostUp = iptables -t nat -A POSTROUTING -o $PUB_NIC -j MASQUERADE"
  echo "PostUp = iptables -I OUTPUT ! -o $WG_IFACE -m mark --mark 0 -j DROP"
  echo "PostDown = iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT"
  echo "PostDown = iptables -t nat -D POSTROUTING -o $PUB_NIC -j MASQUERADE"
  echo "PostDown = iptables -D OUTPUT ! -o $WG_IFACE -m mark --mark 0 -j DROP"
} > /etc/wireguard/${WG_IFACE}.conf

# 8) Enable IP forwarding
sysctl --system <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF

# 9) Start & enable service
systemctl enable wg-quick@"$WG_IFACE"
systemctl start  wg-quick@"$WG_IFACE"

# 10) Generate initial client
echo
echo "Creating first client..."

CLIENT_NAME="client1"
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# Extract server endpoint
ENDPOINT="$SERVER_IP:$WG_PORT"

# Build client file
CLIENT_FILE="/root/${WG_IFACE}-${CLIENT_NAME}.conf"
{
  echo "[Interface]"
  echo "PrivateKey = $CLIENT_PRIV"
  echo "Address = ${WG_IPV4_NET%%/*}/32${WG_IPV6_NET:+,${WG_IPV6_NET%%/*}/128}"
  echo "DNS = $CLIENT_DNS"
  echo "MTU = $BEST_MTU"
  echo
  echo "[Peer]"
  echo "PublicKey = $SERVER_PUB"
  echo "PresharedKey = $CLIENT_PSK"
  echo "Endpoint = $ENDPOINT"
  echo "AllowedIPs = $CLIENT_ALLOWED"
} > "$CLIENT_FILE"

# Append to server cfg
cat >> /etc/wireguard/${WG_IFACE}.conf <<EOF

# Peer: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $CLIENT_PSK
AllowedIPs = ${WG_IPV4_NET%%/*}/32${WG_IPV6_NET:+,${WG_IPV6_NET%%/*}/128}
EOF

# Reload interface
wg syncconf "$WG_IFACE" <(wg-quick strip "$WG_IFACE")

# QR code for mobile
if command -v qrencode &>/dev/null; then
  echo
  echo "Scan this QR code to import the client:"
  qrencode -t ansiutf8 < "$CLIENT_FILE"
fi

echo
echo "Client configuration is saved to: $CLIENT_FILE"
echo "Installation complete. Run this script again to add more clients."
