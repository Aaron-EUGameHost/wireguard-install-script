#!/usr/bin/env bash
#
# Simple WireGuard Installer & Manager
# - First run: installs server + creates an initial client
# - Subsequent runs: add, list, or revoke clients
#

set -euo pipefail

LOGFILE="/var/log/wireguard-install.log"
# All output goes to the log
exec >>"$LOGFILE" 2>&1

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root" >&2
    exit 1
  fi
}

check_virt() {
  # Block OpenVZ/LXC
  if command -v systemd-detect-virt &>/dev/null; then
    v=$(systemd-detect-virt)
    if [[ "$v" == "openvz" || "$v" == "lxc" ]]; then
      echo "Unsupported virtualization: $v" >&2
      exit 1
    fi
  fi
}

detect_os() {
  # Load /etc/os-release
  source /etc/os-release
  OS=$ID
  VER=${VERSION_ID%%.*}
}

install_pkgs() {
  case "$OS" in
    ubuntu|debian)
      apt-get update
      apt-get install -y wireguard qrencode iptables resolvconf curl
      ;;
    fedora)
      dnf install -y wireguard-tools qrencode iptables curl
      ;;
    centos|rhel|rocky|almalinux)
      yum install -y epel-release elrepo-release
      yum install -y kmod-wireguard wireguard-tools qrencode iptables curl
      ;;
    arch)
      pacman -Sy --noconfirm wireguard-tools qrencode iptables curl
      ;;
    alpine)
      apk update
      apk add wireguard-tools qrencode iptables curl openrc
      ;;
    *)
      echo "Unsupported OS: $OS" >&2
      exit 1
      ;;
  esac
}

write_server_conf() {
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard

  # 1) Prompts
  read -rp "Interface name (wg0): " IFACE; IFACE=${IFACE:-wg0}

  # Public IPv4 autodetect or fallback
  IP4=$(ip -4 addr show scope global \
    | awk '/inet/ {print $2; exit}' | cut -d/ -f1)
  [[ -n $IP4 ]] || IP4=$(curl -fsSL ifconfig.co)
  read -rp "Public IPv4 [$IP4]: " PUBLIC_IP4
  PUBLIC_IP4=${PUBLIC_IP4:-$IP4}

  # Public NIC autodetect
  DEFNIC=$(ip route show default | awk '/dev/ {print $5; exit}')
  read -rp "Public interface [$DEFNIC]: " PUBLIC_NIC
  PUBLIC_NIC=${PUBLIC_NIC:-$DEFNIC}

  # VPN subnets, port, DNS & allowed IPs
  read -rp "Server WG IPv4 subnet [10.0.0.1/24]: " WG4; WG4=${WG4:-10.0.0.1/24}
  read -rp "Server WG IPv6 subnet (optional): " WG6
  read -rp "WireGuard port [51820]: " PORT; PORT=${PORT:-51820}
  read -rp "Client DNS1 [1.1.1.1]: " DNS1; DNS1=${DNS1:-1.1.1.1}
  read -rp "Client DNS2 [1.0.0.1]: " DNS2; DNS2=${DNS2:-1.0.0.1}
  read -rp "AllowedIPs [0.0.0.0/0,::/0]: " ALLOW; ALLOW=${ALLOW:-0.0.0.0/0,::/0}

  # Save params for later runs
  cat > /etc/wireguard/params <<EOF
IFACE=$IFACE
PUBLIC_IP4=$PUBLIC_IP4
PUBLIC_NIC=$PUBLIC_NIC
WG4=$WG4
WG6=$WG6
PORT=$PORT
DNS1=$DNS1
DNS2=$DNS2
ALLOW=$ALLOW
EOF

  # 2) Generate server keys
  SERVER_PRIV=$(wg genkey)
  SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

  # 3) Write /etc/wireguard/${IFACE}.conf
  {
    echo "[Interface]"
    echo "Address = $WG4${WG6:+,$WG6}"
    echo "ListenPort = $PORT"
    echo "PrivateKey = $SERVER_PRIV"
    echo "PostUp = iptables -I INPUT -p udp --dport $PORT -j ACCEPT"
    echo "PostUp = iptables -t nat -A POSTROUTING -o $PUBLIC_NIC -j MASQUERADE"
    echo "PostDown = iptables -D INPUT -p udp --dport $PORT -j ACCEPT"
    echo "PostDown = iptables -t nat -D POSTROUTING -o $PUBLIC_NIC -j MASQUERADE"
  } > /etc/wireguard/${IFACE}.conf

  # 4) Enable IP forwarding
  sysctl -w net.ipv4.ip_forward=1
  [[ -n $WG6 ]] && sysctl -w net.ipv6.conf.all.forwarding=1

  # 5) Start service
  if [[ $OS == "alpine" ]]; then
    rc-update add wg-quick.$IFACE default
    rc-service wg-quick.$IFACE start
  else
    systemctl enable wg-quick@${IFACE}
    systemctl start wg-quick@${IFACE}
  fi

  # 6) Prepare client DB & save server pubkey
  : > /etc/wireguard/clients.db
  echo "$SERVER_PUB" > /etc/wireguard/server.pub
}

allocate_ip() {
  # Uses WG4's /24 to assign .2, .3, ...
  source /etc/wireguard/params
  base=$(echo $WG4 | cut -d/ -f1 | rev | cut -d. -f2- | rev)
  count=$(grep -c . /etc/wireguard/clients.db)
  echo "$base.$((count+2))"
}

add_client() {
  source /etc/wireguard/params
  read -rp "Client name: " NAME
  grep -q "^$NAME," /etc/wireguard/clients.db && { echo "Client exists"; return; }
  IP4=$(allocate_ip)
  CLIENT_PRIV=$(wg genkey)
  CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
  CLIENT_PSK=$(wg genpsk)
  ENDPOINT="$PUBLIC_IP4:$PORT"

  HOME=$(eval echo "~${SUDO_USER:-root}")
  CFG="$HOME/${IFACE}-${NAME}.conf"

  {
    echo "[Interface]"
    echo "PrivateKey = $CLIENT_PRIV"
    echo "Address    = $IP4/32${WG6:+,${IP4}/128}"
    echo "DNS        = $DNS1,$DNS2"
    echo
    echo "[Peer]"
    echo "PublicKey    = $(cat /etc/wireguard/server.pub)"
    echo "PresharedKey = $CLIENT_PSK"
    echo "Endpoint     = $ENDPOINT"
    echo "AllowedIPs   = $ALLOW"
  } > "$CFG"

  echo "$NAME,$IP4" >> /etc/wireguard/clients.db

  {
    echo ""
    echo "# Peer: $NAME"
    echo "[Peer]"
    echo "PublicKey    = $CLIENT_PUB"
    echo "PresharedKey = $CLIENT_PSK"
    echo "AllowedIPs   = $IP4/32${WG6:+,${IP4}/128}"
  } >> /etc/wireguard/${IFACE}.conf

  # Reload
  if [[ $OS == "alpine" ]]; then
    rc-service wg-quick.$IFACE restart
  else
    systemctl restart wg-quick@${IFACE}
  fi

  echo "Client config: $CFG"
}

list_clients() {
  cut -d, -f1 /etc/wireguard/clients.db
}

revoke_client() {
  list_clients
  read -rp "Revoke name: " NAME
  grep -v "^$NAME," /etc/wireguard/clients.db > /etc/wireguard/clients.tmp
  mv /etc/wireguard/clients.tmp /etc/wireguard/clients.db
  sed -i "/# Peer: $NAME/,/^\$/d" /etc/wireguard/${IFACE}.conf
  rm -f "$(eval echo "~${SUDO_USER:-root}")/${IFACE}-${NAME}.conf"
  if [[ $OS == "alpine" ]]; then
    rc-service wg-quick.$IFACE restart
  else
    systemctl restart wg-quick@${IFACE}
  fi
  echo "Revoked client $NAME"
}

manage_menu() {
  source /etc/wireguard/params
  PS3="Select: "
  options=("Add client" "List clients" "Revoke client" "Exit")
  select opt in "${options[@]}"; do
    case $REPLY in
      1) add_client;;
      2) list_clients;;
      3) revoke_client;;
      4) exit;;
      *) echo "Invalid";;
    esac
    break
  done
}

# Main
require_root
check_virt
detect_os

if [[ ! -f /etc/wireguard/params ]]; then
  install_pkgs
  write_server_conf
  add_client
else
  manage_menu
fi
