```bash
#!/usr/bin/env bash
#
# Enhanced WireGuard Installer & Manager
#  - Full feature parity with angristan reference
#  - Dynamic IP allocation, per-user config placement
#  - firewalld & OpenRC support
#  - Dual DNS, optional MTU comment
#  - Complete uninstall cleanup
#

set -euo pipefail
IFS=$'\n\t'
trap 'echo "Error at line ${LINENO}. Exiting." >&2' ERR

LOG="/var/log/wireguard-install.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

PARAMS="/etc/wireguard/params"
WG_DIR="/etc/wireguard"
CLIENT_DB="$WG_DIR/clients.db"
BACKPORT_FILE="/etc/apt/sources.list.d/backports.list"

require_root() {
  (( EUID==0 )) || { echo "Must run as root"; exit 1; }
}

check_virt() {
  local v
  if command -v systemd-detect-virt &>/dev/null; then
    v=$(systemd-detect-virt)
  elif command -v virt-what &>/dev/null; then
    v=$(virt-what)
  else
    return
  fi
  case "$v" in openvz|lxc) echo "Unsupported container: $v"; exit 1;; esac
}

detect_os() {
  source /etc/os-release
  OS=$ID
  VER=${VERSION_ID%%.*}
}

install_packages() {
  case "$OS" in
    ubuntu)
      apt-get update
      apt-get install -y wireguard iptables resolvconf qrencode curl
      ;;
    debian)
      if (( VER<10 )); then echo "Debian <10 not supported"; exit 1; fi
      if ! grep -q buster-backports "$BACKPORT_FILE" 2>/dev/null; then
        echo "deb http://deb.debian.org/debian buster-backports main" > "$BACKPORT_FILE"
      fi
      apt-get update
      apt-get install -y -t buster-backports wireguard iptables resolvconf qrencode curl
      ;;
    fedora)
      dnf install -y wireguard-tools iptables qrencode curl
      ;;
    centos|rhel|rocky|almalinux)
      if (( VER<8 )); then echo "$OS <8 not supported"; exit 1; fi
      yum install -y epel-release elrepo-release curl
      yum install -y kmod-wireguard wireguard-tools iptables qrencode
      ;;
    arch)
      pacman -Sy --noconfirm wireguard-tools iptables qrencode curl
      ;;
    alpine)
      apk update
      apk add wireguard-tools iptables qrencode curl openrc
      ;;
    oracle)
      dnf config-manager --enable ol8_developer_UEKR6
      dnf install -y wireguard-tools iptables qrencode curl
      ;;
    *)
      echo "Unsupported OS: $OS"; exit 1;;
  esac
}

enable_forwarding() {
  sysctl --system <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
}

get_home_dir() {
  local user=$1
  if id "$user" &>/dev/null; then
    echo "$(eval echo ~$user)"
  else
    echo /root
  fi
}

reload_wg() {
  if [[ $OS == "alpine" ]]; then
    rc-service "wg-quick.${IFACE}" restart
  else
    wg syncconf "$IFACE" <(wg-quick strip "$IFACE")
  fi
}

ask_params() {
  echo "== WireGuard Installer =="
  read -rp "Interface name [wg0]: " IFACE; IFACE=${IFACE:-wg0}

  local ip4 ip6
  ip4=$(ip -4 addr show scope global | awk '/inet/ {print $2; exit}' | cut -d/ -f1)
  ip6=$(ip -6 addr show scope global | awk '/inet6/ {print $2; exit}' | cut -d/ -f1)
  [[ -n $ip4 ]] || ip4=$(curl -fsSL ifconfig.co)
  read -rp "Public IPv4 [$ip4]: " PUBLIC_IP4; PUBLIC_IP4=${PUBLIC_IP4:-$ip4}

  local nic
  nic=$(ip route show default | awk '/dev/ {print $5; exit}')
  read -rp "Public NIC [$nic]: " PUBLIC_NIC; PUBLIC_NIC=${PUBLIC_NIC:-$nic}

  read -rp "Server WireGuard IPv4 [10.0.0.1/24]: " WG4; WG4=${WG4:-10.0.0.1/24}
  read -rp "Server WireGuard IPv6 [optional fd00:42::1/64]: " WG6
  read -rp "WireGuard port [51820]: " PORT; PORT=${PORT:-51820}

  read -rp "Primary DNS [1.1.1.1]: " DNS1; DNS1=${DNS1:-1.1.1.1}
  read -rp "Secondary DNS [1.0.0.1]: " DNS2; DNS2=${DNS2:-1.0.0.1}
  read -rp "AllowedIPs [0.0.0.0/0,::/0]: " ALLOW; ALLOW=${ALLOW:-0.0.0.0/0,::/0}

  MTU=$(bash <(curl -fsSL https://raw.githubusercontent.com/nitred/nr-wg-mtu-finder/master/find-mtu.sh) --ip 1.1.1.1 \
    | awk '/Optimal MTU:/ {print $3}')
  echo "Detected MTU: $MTU"

  mkdir -p "$WG_DIR"
  chmod 700 "$WG_DIR"
  : > "$CLIENT_DB"

  cat >"$PARAMS"<<EOF
IFACE=$IFACE
PUBLIC_IP4=$PUBLIC_IP4
PUBLIC_NIC=$PUBLIC_NIC
WG4=$WG4
WG6=$WG6
PORT=$PORT
DNS1=$DNS1
DNS2=$DNS2
ALLOW=$ALLOW
MTU=$MTU
EOF
}

write_server_conf() {
  source "$PARAMS"
  SERVER_PRIV=$(wg genkey)
  SERVER_PUB=$(echo "$SERVER_PRIV"|wg pubkey)

  local addr="$WG4"
  [[ -n $WG6 ]] && addr+=",${WG6}"

  {
    echo "[Interface]"
    echo "Address = $addr"
    echo "ListenPort = $PORT"
    echo "PrivateKey = $SERVER_PRIV"
  } >"$WG_DIR/$IFACE.conf"

  # firewall rules
  if pgrep firewalld &>/dev/null; then
    firewall-cmd --permanent --zone=public --add-port="$PORT/udp"
    firewall-cmd --permanent --zone=public --add-masquerade
    firewall-cmd --reload
    cat >>"$WG_DIR/$IFACE.conf"<<EOF

PostUp = firewall-cmd --add-rich-rule="rule family=ipv4 source address=${WG4%/*}/24 masquerade"
PostDown = firewall-cmd --remove-rich-rule="rule family=ipv4 source address=${WG4%/*}/24 masquerade"
EOF
  else
    cat >>"$WG_DIR/$IFACE.conf"<<EOF

PostUp = iptables -I INPUT -p udp --dport $PORT -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $PUBLIC_NIC -j MASQUERADE
PostUp = iptables -I OUTPUT ! -o $IFACE -m mark --mark 0 -j DROP
PostDown = iptables -D INPUT -p udp --dport $PORT -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $PUBLIC_NIC -j MASQUERADE
PostDown = iptables -D OUTPUT ! -o $IFACE -m mark --mark 0 -j DROP
EOF
  fi

  enable_forwarding

  if [[ $OS == "alpine" ]]; then
    rc-update add "wg-quick.$IFACE" default
    rc-service "wg-quick.$IFACE" start
  else
    systemctl enable wg-quick@"$IFACE"
    systemctl start  wg-quick@"$IFACE"
  fi
}

allocate_ips() {
  # pick next free .2–.254 in WG4 subnet
  source "$PARAMS"
  base=${WG4%.*}
  for i in {2..254}; do
    ip="$base.$i"
    if ! grep -q "$ip" "$WG_DIR/$IFACE.conf"; then
      echo "$ip"
      return
    fi
  done
  echo "No free IPs" >&2
  exit 1
}

add_client() {
  source "$PARAMS"
  read -rp "Client name: " NAME
  grep -q "^$NAME," "$CLIENT_DB" && { echo "Client exists"; return; }
  CL_PRIV=$(wg genkey)
  CL_PUB=$(echo "$CL_PRIV"|wg pubkey)
  CL_PSK=$(wg genpsk)
  END="$PUBLIC_IP4:$PORT"
  IP4=$(allocate_ips)
  # IPv6: take WG6 base + same host
  if [[ -n $WG6 ]]; then
    v6base=${WG6%%::*}
    only=${IP4##*.}
    IP6="$v6base::${only}"
  fi

  HOME=$(get_home_dir "$SUDO_USER")
  CFG="$HOME/${IFACE}-${NAME}.conf"

  {
    echo "[Interface]"
    echo "PrivateKey = $CL_PRIV"
    echo "Address    = ${IP4}/32${IP6:+,${IP6}/128}"
    echo "DNS        = $DNS1,$DNS2"
    echo "#MTU      = $MTU"
    echo
    echo "[Peer]"
    echo "PublicKey    = $SERVER_PUB"
    echo "PresharedKey = $CL_PSK"
    echo "Endpoint     = $END"
    echo "AllowedIPs   = $ALLOW"
  } >"$CFG"

  echo "$NAME,$CL_PUB,$CL_PSK,$IP4" >>"$CLIENT_DB"

  cat >>"$WG_DIR/$IFACE.conf"<<EOF

# Peer: $NAME
[Peer]
PublicKey    = $CL_PUB
PresharedKey = $CL_PSK
AllowedIPs   = ${IP4}/32${IP6:+,${IP6}/128}
EOF

  reload_wg
  echo "Client config → $CFG"
}

list_clients() {
  cut -d, -f1 "$CLIENT_DB"
}

revoke_client() {
  list_clients
  read -rp "Revoke name: " NAME
  grep -v "^$NAME," "$CLIENT_DB" >"$CLIENT_DB.tmp" && mv "$CLIENT_DB.tmp" "$CLIENT_DB"
  sed -i "/# Peer: $NAME/,/^\$/d" "$WG_DIR/$IFACE.conf"
  rm -f "$(get_home_dir "$SUDO_USER")/${IFACE}-${NAME}.conf"
  reload_wg
  echo "Revoked $NAME"
}

uninstall_all() {
  read -rp "Remove WireGuard and configs? [y/N]: " yn
  [[ $yn =~ ^[Yy] ]] || return
  if [[ $OS == "alpine" ]]; then
    rc-service "wg-quick.$IFACE" stop
    rc-update del "wg-quick.$IFACE"
  else
    systemctl stop wg-quick@"$IFACE"
    systemctl disable wg-quick@"$IFACE"
  fi
  rm -rf "$WG_DIR" "$PARAMS" "$CLIENT_DB" "$BACKPORT_FILE"
  case "$OS" in
    ubuntu|debian) apt-get remove -y wireguard resolvconf qrencode ;;
    fedora) dnf remove -y wireguard-tools qrencode ;;
    centos|almalinux|rocky) yum remove -y wireguard-tools qrencode ;;
    arch) pacman -Rs --noconfirm wireguard-tools qrencode ;;
    alpine) apk del wireguard-tools qrencode ;;
  esac
  echo "Uninstalled."
}

manage_menu() {
  PS3="Action: "
  options=("Add client" "List clients" "Revoke client" "Uninstall" "Exit")
  select opt in "${options[@]}"; do
    case $REPLY in
      1) add_client;;
      2) list_clients;;
      3) revoke_client;;
      4) uninstall_all; exit;;
      5) exit;;
      *) echo "Invalid";;
    esac
    break
  done
}

main() {
  require_root
  check_virt
  detect_os

  if [[ ! -f "$PARAMS" ]]; then
    install_packages
    ask_params
    write_server_conf
    echo "Creating initial client 'client1'..."
    NAME="client1"
    add_client
  else
    source "$PARAMS"
    echo "WireGuard detected on $IFACE."
    manage_menu
  fi
}

main "$@"
```
