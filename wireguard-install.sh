#!/usr/bin/env bash
#
# WireGuard Installer + Client Manager
#  - First run: installs server + creates one client
#  - Subsequent runs: offers menu to add/list/revoke clients
#

set -euo pipefail
IFS=$'\n\t'
trap 'echo "Error on line ${LINENO}. Exiting." >&2' ERR

LOG="/var/log/wg_full.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

PARAMS_FILE="/etc/wireguard/params"
WG_CONF_DIR="/etc/wireguard"

#-----------------------------------------------------------------------------#
#  Helper functions
#-----------------------------------------------------------------------------#

require_root(){
  (( EUID == 0 )) || { echo "Must be root" >&2; exit 1; }
}

detect_os(){
  source /etc/os-release
  OS_ID=$ID
  OS_VER=${VERSION_ID%%.*}
}

install_packages(){
  case "$OS_ID" in
    ubuntu|debian)
      apt-get update
      apt-get install -y wireguard qrencode iptables resolvconf
      ;;
    fedora)
      dnf install -y wireguard-tools qrencode iptables
      ;;
    centos|rhel|almalinux|rocky)
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
}

enable_forwarding(){
  sysctl --system <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
}

reload_wg(){
  wg syncconf "$WG_IFACE" <(wg-quick strip "$WG_IFACE")
}

#-----------------------------------------------------------------------------#
#  Server install + initial client
#-----------------------------------------------------------------------------#

install_server(){
  require_root
  detect_os

  # -- gather settings --
  read -rp "Interface name [wg0]: " WG_IFACE
  WG_IFACE=${WG_IFACE:-wg0}

  LOCAL_IP=$(ip -4 addr show scope global \
    | awk '/inet/ {sub(/\/.*/,"",$2); print $2; exit}')
  [[ -n $LOCAL_IP ]] || LOCAL_IP=$(curl -fsSL https://ifconfig.co)
  read -rp "Server public IP [$LOCAL_IP]: " SERVER_IP
  SERVER_IP=${SERVER_IP:-$LOCAL_IP}

  DEF_NIC=$(ip route show default | awk '/dev/ {print $5; exit}')
  read -rp "Public NIC [$DEF_NIC]: " PUB_NIC
  PUB_NIC=${PUB_NIC:-$DEF_NIC}

  read -rp "VPN IPv4 subnet [10.0.0.1/24]: " WG_IPV4_NET
  WG_IPV4_NET=${WG_IPV4_NET:-10.0.0.1/24}
  read -rp "VPN IPv6 subnet (optional): " WG_IPV6_NET
  read -rp "WireGuard port [51820]: " WG_PORT
  WG_PORT=${WG_PORT:-51820}
  read -rp "Client DNS [1.1.1.1,1.0.0.1]: " CLIENT_DNS
  CLIENT_DNS=${CLIENT_DNS:-1.1.1.1,1.0.0.1}
  read -rp "AllowedIPs [0.0.0.0/0,::/0]: " CLIENT_ALLOWED
  CLIENT_ALLOWED=${CLIENT_ALLOWED:-0.0.0.0/0,::/0}

  # MTU
  BEST_MTU=$(bash <(curl -fsSL https://raw.githubusercontent.com/nitred/nr-wg-mtu-finder/master/find-mtu.sh) --ip 1.1.1.1 \
    | awk '/Optimal MTU:/ {print $3}')
  echo "Using MTU: $BEST_MTU"

  install_packages
  mkdir -p "$WG_CONF_DIR"
  chmod 700 "$WG_CONF_DIR"

  SERVER_PRIV=$(wg genkey)
  SERVER_PUB=$(echo "$SERVER_PRIV"|wg pubkey)

  # save params including MTU
  cat >"$PARAMS_FILE"<<EOF
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
BEST_MTU=$BEST_MTU
EOF

  # write server config
  {
    echo "[Interface]"
    echo "Address = ${WG_IPV4_NET}${WG_IPV6_NET:+,${WG_IPV6_NET}}"
    echo "ListenPort = $WG_PORT"
    echo "PrivateKey = $SERVER_PRIV"
    echo "PostUp = iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT"
    echo "PostUp = iptables -t nat -A POSTROUTING -o $PUB_NIC -j MASQUERADE"
    echo "PostUp = iptables -I OUTPUT ! -o $WG_IFACE -m mark --mark 0 -j DROP"
    echo "PostDown = iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT"
    echo "PostDown = iptables -t nat -D POSTROUTING -o $PUB_NIC -j MASQUERADE"
    echo "PostDown = iptables -D OUTPUT ! -o $WG_IFACE -m mark --mark 0 -j DROP"
  } >"$WG_CONF_DIR/$WG_IFACE.conf"

  enable_forwarding
  systemctl enable wg-quick@"$WG_IFACE"
  systemctl start  wg-quick@"$WG_IFACE"

  echo "Creating initial client 'client1'..."
  add_client client1
}

#-----------------------------------------------------------------------------#
#  Client management
#-----------------------------------------------------------------------------#

add_client(){
  name="$1"
  source "$PARAMS_FILE"
  CL_PRIV=$(wg genkey)
  CL_PUB=$(echo "$CL_PRIV"|wg pubkey)
  CL_PSK=$(wg genpsk)
  ENDPOINT="$SERVER_IP:$WG_PORT"

  CFG="/root/${WG_IFACE}-${name}.conf"
  {
    echo "[Interface]"
    echo "PrivateKey = $CL_PRIV"
    echo "Address    = ${WG_IPV4_NET%%/*}/32${WG_IPV6_NET:+,${WG_IPV6_NET%%/*}/128}"
    echo "DNS        = $CLIENT_DNS"
    echo "MTU        = $BEST_MTU"
    echo
    echo "[Peer]"
    echo "PublicKey    = $SERVER_PUB"
    echo "PresharedKey = $CL_PSK"
    echo "Endpoint     = $ENDPOINT"
    echo "AllowedIPs   = $CLIENT_ALLOWED"
  } >"$CFG"

  cat >>"$WG_CONF_DIR/$WG_IFACE.conf"<<EOF

# Peer: $name
[Peer]
PublicKey     = $CL_PUB
PresharedKey  = $CL_PSK
AllowedIPs    = ${WG_IPV4_NET%%/*}/32${WG_IPV6_NET:+,${WG_IPV6_NET%%/*}/128}
EOF

  reload_wg
  echo "Client '$name' added → $CFG"
}

list_clients(){
  grep -E "^# Peer:" "$WG_CONF_DIR/$WG_IFACE.conf" | cut -d' ' -f3
}

revoke_client(){
  list_clients
  read -rp "Name to revoke: " name
  sed -i "/# Peer: $name/,/^\$/d" "$WG_CONF_DIR/$WG_IFACE.conf"
  rm -f "/root/${WG_IFACE}-${name}.conf"
  reload_wg
  echo "Client '$name' revoked."
}

manage_menu(){
  source "$PARAMS_FILE"
  PS3="Select action: "
  options=(Add\ client List\ clients Revoke\ client Exit)
  select opt in "${options[@]}"; do
    case $REPLY in
      1) read -rp "New client name: " nm; add_client "$nm"; break;;
      2) list_clients; break;;
      3) revoke_client; break;;
      4) exit 0;;
      *) echo "Invalid";;
    esac
  done
}

#-----------------------------------------------------------------------------#
#  Main
#-----------------------------------------------------------------------------#

require_root
if [[ -f "$PARAMS_FILE" ]]; then
  echo "Existing install detected."
  manage_menu
else
  install_server
fi
