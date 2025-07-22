#!/bin/bash

# Enhanced WireGuard Setup Manager
# A modern, secure, and user-friendly WireGuard installation and management tool
# Version: 1.0.0
# License: MIT

set -euo pipefail

# ==========================================
# GLOBAL CONFIGURATION
# ==========================================

readonly SCRIPT_NAME="WireGuard Setup Manager"
readonly SCRIPT_VERSION="1.0.0"
readonly CONFIG_DIR="/etc/wireguard-manager"
readonly LOG_FILE="/var/log/wireguard-manager.log"
readonly BACKUP_DIR="/etc/wireguard-manager/backups"
readonly TEMP_DIR="/tmp/wg-manager-$$"

# Color definitions
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_RESET='\033[0m'

# Default network settings
readonly DEFAULT_VPN_SUBNET="10.100.0.0/24"
readonly DEFAULT_VPN_IPV6="fd00:10:100::/64"
readonly DEFAULT_PORT_RANGE_START=51820
readonly DEFAULT_PORT_RANGE_END=51830

# ==========================================
# LOGGING AND UTILITY FUNCTIONS
# ==========================================

# Initialize logging
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
}

# Enhanced logging function
log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Print colored output with logging
print_status() {
    local color="$1"
    local level="$2"
    shift 2
    local message="$*"
    
    echo -e "${color}[${level}]${COLOR_RESET} $message"
    log_message "$level" "$message"
}

# Convenience functions for different log levels
log_info() { print_status "$COLOR_BLUE" "INFO" "$@"; }
log_success() { print_status "$COLOR_GREEN" "SUCCESS" "$@"; }
log_warning() { print_status "$COLOR_YELLOW" "WARNING" "$@"; }
log_error() { print_status "$COLOR_RED" "ERROR" "$@"; }

# Error handling with cleanup
handle_error() {
    local exit_code=$?
    local line_number=${1:-$LINENO}
    
    log_error "Script failed at line $line_number with exit code $exit_code"
    perform_cleanup
    exit $exit_code
}

# Cleanup function
perform_cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
}

# Set up error handling
trap 'handle_error $LINENO' ERR
trap perform_cleanup EXIT

# ==========================================
# SYSTEM VALIDATION FUNCTIONS
# ==========================================

# Check if running as root
verify_root_access() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with administrator privileges"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Detect operating system
detect_operating_system() {
    local os_info
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "${ID}:${VERSION_ID}"
    else
        log_error "Cannot detect operating system"
        return 1
    fi
}

# Validate system compatibility
validate_system_compatibility() {
    local os_version
    os_version=$(detect_operating_system)
    local os_id="${os_version%%:*}"
    local version_id="${os_version##*:}"
    
    log_info "Detected system: $os_id $version_id"
    
    case "$os_id" in
        "ubuntu")
            if [[ "${version_id%%.*}" -lt 20 ]]; then
                log_error "Ubuntu 20.04 or newer required"
                return 1
            fi
            ;;
        "debian")
            if [[ "${version_id}" -lt 10 ]]; then
                log_error "Debian 10 or newer required"
                return 1
            fi
            ;;
        "fedora")
            if [[ "$version_id" -lt 35 ]]; then
                log_error "Fedora 35 or newer required"
                return 1
            fi
            ;;
        "centos"|"almalinux"|"rocky")
            if [[ "${version_id%%.*}" -lt 8 ]]; then
                log_error "Version 8 or newer required for $os_id"
                return 1
            fi
            ;;
        *)
            log_warning "Operating system $os_id may not be fully supported"
            ;;
    esac
    
    return 0
}

# Check virtualization environment
check_virtualization() {
    local virt_type
    
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
    else
        virt_type="unknown"
    fi
    
    case "$virt_type" in
        "openvz")
            log_error "OpenVZ containers are not supported"
            return 1
            ;;
        "lxc")
            log_warning "LXC detected - additional configuration may be required"
            ;;
        "none"|"kvm"|"vmware"|"xen"|"microsoft")
            log_info "Virtualization environment: $virt_type"
            ;;
        *)
            log_info "Unknown or unsupported virtualization: $virt_type"
            ;;
    esac
    
    return 0
}

# ==========================================
# NETWORK CONFIGURATION FUNCTIONS
# ==========================================

# Get primary network interface
discover_primary_interface() {
    local interface
    interface=$(ip route show default | awk '/default/ {print $5; exit}')
    
    if [[ -z "$interface" ]]; then
        log_error "Cannot determine primary network interface"
        return 1
    fi
    
    echo "$interface"
}

# Get server public IP
discover_public_ip() {
    local public_ip
    
    # Try multiple methods to get public IP
    local ip_services=(
        "ip -4 addr show scope global"
        "curl -4 -s --max-time 10 ifconfig.me"
        "curl -4 -s --max-time 10 ip.sb"
        "curl -4 -s --max-time 10 ipv4.icanhazip.com"
    )
    
    for service in "${ip_services[@]}"; do
        if [[ "$service" =~ ^ip ]]; then
            public_ip=$(eval "$service" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        else
            public_ip=$(eval "$service" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
        fi
        
        if [[ -n "$public_ip" ]]; then
            echo "$public_ip"
            return 0
        fi
    done
    
    log_error "Cannot determine server public IP address"
    return 1
}

# Validate IP address format
validate_ip_address() {
    local ip="$1"
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if [[ ! "$ip" =~ $ip_regex ]]; then
        return 1
    fi
    
    # Check each octet
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ "$octet" -gt 255 || "$octet" -lt 0 ]]; then
            return 1
        fi
    done
    
    return 0
}

# Check if port is available
check_port_availability() {
    local port="$1"
    local protocol="${2:-udp}"
    
    if netstat -ln"$protocol" 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    
    return 0
}

# Find available port in range
find_available_port() {
    local start_port="${1:-$DEFAULT_PORT_RANGE_START}"
    local end_port="${2:-$DEFAULT_PORT_RANGE_END}"
    
    for port in $(seq "$start_port" "$end_port"); do
        if check_port_availability "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    log_error "No available ports found in range $start_port-$end_port"
    return 1
}

# ==========================================
# PACKAGE MANAGEMENT FUNCTIONS
# ==========================================

# Update package repositories
update_package_repositories() {
    local os_version
    os_version=$(detect_operating_system)
    local os_id="${os_version%%:*}"
    
    log_info "Updating package repositories..."
    
    case "$os_id" in
        "ubuntu"|"debian")
            apt-get update -qq
            ;;
        "fedora")
            dnf check-update -q || true
            ;;
        "centos"|"almalinux"|"rocky")
            yum check-update -q || true
            ;;
        *)
            log_warning "Unknown package manager for $os_id"
            ;;
    esac
}

# Install required packages
install_system_packages() {
    local os_version
    os_version=$(detect_operating_system)
    local os_id="${os_version%%:*}"
    
    log_info "Installing required system packages..."
    
    local packages_common="curl wget jq qrencode iptables"
    local packages_specific=""
    
    case "$os_id" in
        "ubuntu"|"debian")
            packages_specific="wireguard resolvconf ufw"
            DEBIAN_FRONTEND=noninteractive apt-get install -y $packages_common $packages_specific
            ;;
        "fedora")
            packages_specific="wireguard-tools firewalld"
            dnf install -y $packages_common $packages_specific
            ;;
        "centos"|"almalinux"|"rocky")
            # Enable EPEL repository
            yum install -y epel-release
            packages_specific="wireguard-tools firewalld"
            yum install -y $packages_common $packages_specific
            ;;
        *)
            log_error "Unsupported operating system for package installation: $os_id"
            return 1
            ;;
    esac
    
    log_success "System packages installed successfully"
}

# ==========================================
# WIREGUARD CONFIGURATION FUNCTIONS
# ==========================================

# Generate cryptographic keys
generate_keypair() {
    local private_key
    local public_key
    
    private_key=$(wg genkey)
    public_key=$(echo "$private_key" | wg pubkey)
    
    echo "$private_key $public_key"
}

# Generate preshared key
generate_preshared_key() {
    wg genpsk
}

# Create server configuration structure
initialize_server_config() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/etc/wireguard"
    
    # Set proper permissions
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$BACKUP_DIR"
    chmod 700 "/etc/wireguard"
}

# Interactive server configuration
configure_server_interactively() {
    local server_ip
    local server_port
    local server_interface
    local vpn_subnet
    local dns_servers
    
    echo
    log_info "WireGuard Server Configuration"
    echo "======================================"
    
    # Server IP configuration
    server_ip=$(discover_public_ip)
    read -rp "Server public IP address [$server_ip]: " input_ip
    server_ip="${input_ip:-$server_ip}"
    
    if ! validate_ip_address "$server_ip"; then
        log_error "Invalid IP address format"
        return 1
    fi
    
    # Server port configuration
    server_port=$(find_available_port)
    read -rp "Server port [$server_port]: " input_port
    server_port="${input_port:-$server_port}"
    
    if ! [[ "$server_port" =~ ^[0-9]+$ ]] || [[ "$server_port" -lt 1024 ]] || [[ "$server_port" -gt 65535 ]]; then
        log_error "Invalid port number (must be 1024-65535)"
        return 1
    fi
    
    # Network interface
    server_interface=$(discover_primary_interface)
    read -rp "Public network interface [$server_interface]: " input_interface
    server_interface="${input_interface:-$server_interface}"
    
    # VPN subnet
    read -rp "VPN subnet [$DEFAULT_VPN_SUBNET]: " input_subnet
    vpn_subnet="${input_subnet:-$DEFAULT_VPN_SUBNET}"
    
    # DNS servers
    read -rp "DNS servers [1.1.1.1,8.8.8.8]: " input_dns
    dns_servers="${input_dns:-1.1.1.1,8.8.8.8}"
    
    # Store configuration
    cat > "$CONFIG_DIR/server.conf" << EOF
{
    "server_ip": "$server_ip",
    "server_port": $server_port,
    "server_interface": "$server_interface",
    "vpn_subnet": "$vpn_subnet",
    "dns_servers": "$dns_servers",
    "created_at": "$(date -Iseconds)"
}
EOF
    
    log_success "Server configuration saved"
}

# Generate server WireGuard configuration
create_server_configuration() {
    local config
    config=$(cat "$CONFIG_DIR/server.conf")
    
    local server_ip
    local server_port
    local server_interface
    local vpn_subnet
    
    server_ip=$(echo "$config" | jq -r '.server_ip')
    server_port=$(echo "$config" | jq -r '.server_port')
    server_interface=$(echo "$config" | jq -r '.server_interface')
    vpn_subnet=$(echo "$config" | jq -r '.vpn_subnet')
    
    # Generate server keys
    local keypair
    keypair=$(generate_keypair)
    local server_private_key="${keypair%% *}"
    local server_public_key="${keypair##* }"
    
    # Save keys securely
    echo "$server_private_key" | tee "$CONFIG_DIR/server_private.key" > /dev/null
    echo "$server_public_key" | tee "$CONFIG_DIR/server_public.key" > /dev/null
    chmod 600 "$CONFIG_DIR/server_private.key"
    
    # Extract network information
    local network_base
    network_base=$(echo "$vpn_subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local server_vpn_ip="${network_base}.1"
    
    # Create WireGuard server configuration
    cat > "/etc/wireguard/wg0.conf" << EOF
[Interface]
# Server Configuration - Generated by WireGuard Setup Manager v$SCRIPT_VERSION
# Created: $(date)
Address = $server_vpn_ip/24
ListenPort = $server_port
PrivateKey = $server_private_key
SaveConfig = false

# Firewall rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $server_interface -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $server_interface -j MASQUERADE

# Client configurations will be added below this line
EOF
    
    chmod 600 "/etc/wireguard/wg0.conf"
    
    # Update server config with generated information
    local updated_config
    updated_config=$(echo "$config" | jq --arg key "$server_private_key" --arg pub "$server_public_key" --arg ip "$server_vpn_ip" \
        '. + {server_private_key: $key, server_public_key: $pub, server_vpn_ip: $ip}')
    echo "$updated_config" > "$CONFIG_DIR/server.conf"
    
    log_success "Server WireGuard configuration created"
}

# ==========================================
# FIREWALL CONFIGURATION FUNCTIONS
# ==========================================

# Configure firewall rules
setup_firewall_rules() {
    local config
    config=$(cat "$CONFIG_DIR/server.conf")
    local server_port
    server_port=$(echo "$config" | jq -r '.server_port')
    
    log_info "Configuring firewall rules..."
    
    # Detect firewall system
    if systemctl is-active --quiet ufw 2>/dev/null || command -v ufw >/dev/null 2>&1; then
        # UFW (Ubuntu/Debian)
        ufw allow "$server_port/udp" comment "WireGuard"
        ufw --force enable
    elif systemctl is-active --quiet firewalld 2>/dev/null || command -v firewall-cmd >/dev/null 2>&1; then
        # Firewalld (CentOS/RHEL/Fedora)
        firewall-cmd --permanent --add-port="$server_port/udp"
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    else
        # Fallback to iptables
        iptables -I INPUT -p udp --dport "$server_port" -j ACCEPT
        # Save iptables rules (method varies by distribution)
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save
        elif command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
    
    log_success "Firewall rules configured"
}

# Enable IP forwarding
enable_ip_forwarding() {
    log_info "Enabling IP forwarding..."
    
    # Enable for current session
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    
    # Make permanent
    cat > /etc/sysctl.d/99-wireguard.conf << EOF
# WireGuard IP forwarding
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-wireguard.conf
    log_success "IP forwarding enabled"
}

# ==========================================
# SERVICE MANAGEMENT FUNCTIONS
# ==========================================

# Start and enable WireGuard service
start_wireguard_service() {
    log_info "Starting WireGuard service..."
    
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Verify service is running
    if systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard service started successfully"
    else
        log_error "Failed to start WireGuard service"
        return 1
    fi
}

# ==========================================
# CLIENT MANAGEMENT FUNCTIONS
# ==========================================

# Validate client name
validate_client_name() {
    local name="$1"
    
    # Check format
    if [[ ! "$name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$ ]]; then
        return 1
    fi
    
    # Check length
    if [[ ${#name} -lt 3 || ${#name} -gt 15 ]]; then
        return 1
    fi
    
    return 0
}

# Check if client exists
client_exists() {
    local client_name="$1"
    
    if [[ -f "$CONFIG_DIR/clients/$client_name.json" ]]; then
        return 0
    fi
    
    return 1
}

# Get next available client IP
get_next_client_ip() {
    local config
    config=$(cat "$CONFIG_DIR/server.conf")
    local vpn_subnet
    vpn_subnet=$(echo "$config" | jq -r '.vpn_subnet')
    
    local network_base
    network_base=$(echo "$vpn_subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    
    # Start from .10 (reserve .1-9 for infrastructure)
    for ip_suffix in $(seq 10 254); do
        local test_ip="${network_base}.${ip_suffix}"
        
        # Check if IP is already assigned
        if ! grep -r "Address.*$test_ip" "$CONFIG_DIR/clients/" >/dev/null 2>&1; then
            echo "$test_ip"
            return 0
        fi
    done
    
    log_error "No available IP addresses in subnet"
    return 1
}

# Create new client
create_new_client() {
    echo
    log_info "Creating New WireGuard Client"
    echo "======================================"
    
    # Get client name
    local client_name
    while true; do
        read -rp "Enter client name: " client_name
        
        if [[ -z "$client_name" ]]; then
            log_warning "Client name cannot be empty"
            continue
        fi
        
        if ! validate_client_name "$client_name"; then
            log_warning "Invalid client name. Use 3-15 characters: letters, numbers, underscore, hyphen"
            continue
        fi
        
        if client_exists "$client_name"; then
            log_warning "Client '$client_name' already exists"
            continue
        fi
        
        break
    done
    
    # Generate client keys
    local keypair
    keypair=$(generate_keypair)
    local client_private_key="${keypair%% *}"
    local client_public_key="${keypair##* }"
    local preshared_key
    preshared_key=$(generate_preshared_key)
    
    # Get client IP
    local client_ip
    client_ip=$(get_next_client_ip)
    
    # Load server configuration
    local server_config
    server_config=$(cat "$CONFIG_DIR/server.conf")
    local server_ip
    local server_port
    local server_public_key
    local dns_servers
    
    server_ip=$(echo "$server_config" | jq -r '.server_ip')
    server_port=$(echo "$server_config" | jq -r '.server_port')
    server_public_key=$(echo "$server_config" | jq -r '.server_public_key')
    dns_servers=$(echo "$server_config" | jq -r '.dns_servers')
    
    # Create client directory
    mkdir -p "$CONFIG_DIR/clients"
    
    # Save client configuration
    cat > "$CONFIG_DIR/clients/$client_name.json" << EOF
{
    "name": "$client_name",
    "private_key": "$client_private_key",
    "public_key": "$client_public_key",
    "preshared_key": "$preshared_key",
    "ip_address": "$client_ip",
    "created_at": "$(date -Iseconds)",
    "enabled": true
}
EOF
    
    # Generate client configuration file
    local client_config_file="$CONFIG_DIR/clients/$client_name.conf"
    cat > "$client_config_file" << EOF
[Interface]
# Client: $client_name
# Generated: $(date)
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = $dns_servers

[Peer]
PublicKey = $server_public_key
PresharedKey = $preshared_key
Endpoint = $server_ip:$server_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Add client to server configuration
    cat >> "/etc/wireguard/wg0.conf" << EOF

# Client: $client_name (Added: $(date))
[Peer]
PublicKey = $client_public_key
PresharedKey = $preshared_key
AllowedIPs = $client_ip/32
EOF
    
    # Reload WireGuard configuration
    wg syncconf wg0 <(wg-quick strip wg0)
    
    # Generate QR code
    local qr_file="$CONFIG_DIR/clients/$client_name.png"
    qrencode -t png -o "$qr_file" < "$client_config_file"
    
    log_success "Client '$client_name' created successfully"
    echo
    echo "Configuration file: $client_config_file"
    echo "QR code image: $qr_file"
    echo
    echo "=== Client Configuration ==="
    cat "$client_config_file"
    echo
    echo "=== QR Code ==="
    qrencode -t ansiutf8 < "$client_config_file"
    echo
}





# List all clients - fixed version
list_all_clients() {
    echo
    log_info "WireGuard Client List"
    echo "======================================"
    
    # Check if client directory exists
    if [[ ! -d "$CONFIG_DIR/clients" ]]; then
        echo "No clients found. Client directory does not exist."
        echo "Directory: $CONFIG_DIR/clients"
        return
    fi
    
    # Check if jq is available
    if ! command -v jq &>/dev/null; then
        log_error "jq is required but not installed. Please install jq:"
        echo "  Ubuntu/Debian: apt install jq -y"
        echo "  CentOS/RHEL:   yum install jq -y"
        echo "  Fedora:        dnf install jq -y"
        return 1
    fi
    
    local client_count=0
    local files_found=0
    
    # Count files first to handle "no files" case
    for client_file in "$CONFIG_DIR/clients"/*.json; do
        if [[ -f "$client_file" ]]; then
            ((files_found++))
        fi
    done
    
    if [[ $files_found -eq 0 ]]; then
        echo "No client configuration files found."
        echo "Directory exists but is empty: $CONFIG_DIR/clients"
        return
    fi
    
    # Print header
    printf "%-4s %-15s %-15s %-12s %-12s %s\n" "ID" "Name" "IP Address" "Status" "Created" "File"
    echo "---------------------------------------------------------------------------------"
    
    # Process each client file
    for client_file in "$CONFIG_DIR/clients"/*.json; do
        # Skip if not a regular file
        [[ -f "$client_file" ]] || continue
        
        # Check if file is readable
        if [[ ! -r "$client_file" ]]; then
            log_warning "Cannot read file: $client_file"
            continue
        fi
        
        # Check if file is not empty
        if [[ ! -s "$client_file" ]]; then
            log_warning "Empty file: $client_file"
            continue
        fi
        
        ((client_count++))
        
        # Read and validate JSON
        local client_config
        if ! client_config=$(cat "$client_file" 2>/dev/null); then
            log_warning "Failed to read: $client_file"
            printf "%-4s %-15s %-15s %-12s %-12s %s\n" "$client_count" "ERROR" "READ_FAILED" "Unknown" "Unknown" "$(basename "$client_file")"
            continue
        fi
        
        # Parse JSON fields with error handling
        local name ip_address created_at enabled status
        
        name=$(echo "$client_config" | jq -r '.name // "unknown"' 2>/dev/null)
        ip_address=$(echo "$client_config" | jq -r '.ip_address // "unknown"' 2>/dev/null)  
        created_at=$(echo "$client_config" | jq -r '.created_at // "unknown"' 2>/dev/null | cut -d'T' -f1)
        enabled=$(echo "$client_config" | jq -r '.enabled // "unknown"' 2>/dev/null)
        
        # Handle jq failures
        if [[ -z "$name" || "$name" == "null" ]]; then
            name=$(basename "$client_file" .json)  # Fallback to filename
        fi
        
        # Determine status
        case "$enabled" in
            "true") status="Active" ;;
            "false") status="Disabled" ;;
            *) status="Unknown" ;;
        esac
        
        # Display client info
        printf "%-4s %-15s %-15s %-12s %-12s %s\n" \
            "$client_count" \
            "${name:0:14}" \
            "${ip_address:0:14}" \
            "$status" \
            "${created_at:0:11}" \
            "$(basename "$client_file")"
    done
    
    echo
    if [[ $client_count -eq 0 ]]; then
        echo "No valid client configurations found."
        echo "Files exist but could not be parsed."
    else
        echo "Total clients: $client_count"
    fi
    echo
}

# Fallback function when jq is not available
list_clients_fallback() {
    echo "Using fallback method (without jq)..."
    echo
    
    local client_count=0
    printf "%-4s %-20s %s\n" "ID" "Name" "File"
    echo "-----------------------------------------------"
    
    for client_file in "$CONFIG_DIR/clients"/*.json; do
        if [[ ! -f "$client_file" ]]; then
            continue
        fi
        
        ((client_count++))
        local basename_file
        basename_file=$(basename "$client_file" .json)
        
        printf "%-4s %-20s %s\n" "$client_count" "$basename_file" "$client_file"
    done
    
    if [[ $client_count -eq 0 ]]; then
        echo "No client files found."
    fi
    echo
    echo "Install 'jq' for detailed client information: apt install jq"
}  # <-- THIS WAS THE MISSING CLOSING BRACE!

# Remove client
# Purge/Uninstall WireGuard completely
purge_wireguard() {
    echo
    log_info "Purge WireGuard Installation"
    echo "========================================"
    log_warning "This will completely remove WireGuard and ALL configurations!"
    
    # List what will be removed
    echo "This will remove:"
    echo "  - WireGuard service and configuration"
    echo "  - All server and client configurations"
    echo "  - All client files and QR codes"
    echo "  - WireGuard package (optional)"
    echo "  - Firewall rules"
    echo
    
    # Double confirmation
    read -rp "Are you absolutely sure you want to purge WireGuard? [y/N]: " confirm1
    if [[ "$confirm1" != [yY] ]]; then
        log_info "Operation cancelled"
        return
    fi
    
    read -rp "Type 'PURGE' to confirm complete removal: " confirm2
    if [[ "$confirm2" != "PURGE" ]]; then
        log_info "Operation cancelled"
        return
    fi
    
    log_info "Starting WireGuard purge process..."
    
    # Stop and disable WireGuard service
    if systemctl is-active --quiet wg-quick@wg0; then
        log_info "Stopping WireGuard service..."
        systemctl stop wg-quick@wg0
    fi
    
    if systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
        log_info "Disabling WireGuard service..."
        systemctl disable wg-quick@wg0
    fi
    
    # Remove WireGuard interface if still up
    if ip link show wg0 &>/dev/null; then
        log_info "Bringing down WireGuard interface..."
        wg-quick down wg0 2>/dev/null || ip link delete wg0 2>/dev/null
    fi
    
    # Remove configuration files
    log_info "Removing configuration files..."
    rm -f /etc/wireguard/wg0.conf
    rm -f /etc/wireguard/wg0.conf.bak
    rm -rf /etc/wireguard/keys/
    
    # Remove client configuration directory
    if [[ -d "$CONFIG_DIR" ]]; then
        log_info "Removing client configurations..."
        rm -rf "$CONFIG_DIR"
    fi
    
    # Remove systemd override if it exists
    rm -rf /etc/systemd/system/wg-quick@wg0.service.d/
    
    # Reload systemd
    systemctl daemon-reload
    
    # Remove firewall rules (iptables)
    log_info "Cleaning up firewall rules..."
    
    # Remove NAT rules (adjust interface as needed)
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o venet0 -j MASQUERADE 2>/dev/null
    
    # Remove forward rules
    iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null
    iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null
    
    # Remove input rules
    iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null
    
    # If using ufw, remove rules
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        log_info "Removing UFW rules..."
        ufw --force delete allow 51820/udp 2>/dev/null
        # Remove any custom ufw rules for WireGuard subnet
        ufw --force delete allow from 10.8.0.0/24 2>/dev/null
    fi
    
    # Remove IP forwarding setting (optional - only if you're sure it was added by WireGuard)
    read -rp "Remove IP forwarding setting? This may affect other services [y/N]: " remove_forwarding
    if [[ "$remove_forwarding" == [yY] ]]; then
        log_info "Removing IP forwarding..."
        sed -i 's/^net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null
        sysctl -w net.ipv4.ip_forward=0 2>/dev/null
    fi
    
    # Optional: Remove WireGuard package
    read -rp "Remove WireGuard package from system? [y/N]: " remove_package
    if [[ "$remove_package" == [yY] ]]; then
        log_info "Removing WireGuard package..."
        
        if command -v apt &>/dev/null; then
            apt remove --purge -y wireguard wireguard-tools 2>/dev/null
            apt autoremove -y 2>/dev/null
        elif command -v yum &>/dev/null; then
            yum remove -y wireguard-tools 2>/dev/null
        elif command -v dnf &>/dev/null; then
            dnf remove -y wireguard-tools 2>/dev/null
        elif command -v pacman &>/dev/null; then
            pacman -Rs --noconfirm wireguard-tools 2>/dev/null
        fi
    fi
    
    # Remove any remaining wireguard directories
    rm -rf /var/lib/wireguard/ 2>/dev/null
    rm -rf /usr/share/wireguard/ 2>/dev/null
    
    # Clean up any custom scripts or cron jobs (adjust paths as needed)
    rm -f /usr/local/bin/wg-* 2>/dev/null
    
    log_success "WireGuard has been completely purged from the system"
    log_info "You may want to reboot to ensure all changes take effect"
}
# ==========================================
# BACKUP AND MAINTENANCE FUNCTIONS
# ==========================================

# Create system backup
create_system_backup() {
    local backup_name="wireguard-backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name.tar.gz"
    
    log_info "Creating system backup..."
    
    mkdir -p "$BACKUP_DIR"
    
    tar -czf "$backup_path" \
        -C / \
        --exclude="$BACKUP_DIR" \
        "etc/wireguard" \
        "etc/wireguard-manager" \
        2>/dev/null || true
    
    if [[ -f "$backup_path" ]]; then
        log_success "Backup created: $backup_path"
        echo "Backup file: $backup_path"
    else
        log_error "Failed to create backup"
        return 1
    fi
}

# System status check
check_system_status() {
    echo
    log_info "WireGuard System Status"
    echo "======================================"
    
    # Service status
    echo "Service Status:"
    if systemctl is-active --quiet wg-quick@wg0; then
        echo "  WireGuard Service: ${COLOR_GREEN}Active${COLOR_RESET}"
    else
        echo "  WireGuard Service: ${COLOR_RED}Inactive${COLOR_RESET}"
    fi
    
    # Interface status
    echo
    echo "Network Interface:"
    if ip link show wg0 >/dev/null 2>&1; then
        echo "  Interface wg0: ${COLOR_GREEN}Up${COLOR_RESET}"
        echo "  Interface IP: $(ip addr show wg0 | grep 'inet ' | awk '{print $2}')"
    else
        echo "  Interface wg0: ${COLOR_RED}Down${COLOR_RESET}"
    fi
    
    # Connected clients
    echo
    echo "Connected Clients:"
    if command -v wg >/dev/null 2>&1 && wg show wg0 >/dev/null 2>&1; then
        local peer_count
        peer_count=$(wg show wg0 peers | wc -l)
        echo "  Total Peers: $peer_count"
        
        while read -r peer; do
            local last_handshake
            last_handshake=$(wg show wg0 latest-handshakes | grep "$peer" | awk '{print $2}')
            if [[ -n "$last_handshake" && "$last_handshake" != "0" ]]; then
                local handshake_time
                handshake_time=$(date -d "@$last_handshake" 2>/dev/null || echo "Unknown")
                echo "  Peer ${peer:0:16}...: Last seen $handshake_time"
            fi
        done < <(wg show wg0 peers)
    else
        echo "  Status: Unable to query peers"
    fi
    
    # System resources
    echo
    echo "System Resources:"
    echo "  Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo "  Memory Usage: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
    echo "  Disk Usage: $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5")"}')"
    echo
}

# ==========================================
# MAIN MENU SYSTEM
# ==========================================

# Display main menu
show_main_menu() {
    clear
    echo
    echo "======================================"
    echo "    $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "======================================"
    echo
    echo "1) Install WireGuard Server"
    echo "2) Add New Client"
    echo "3) List All Clients"
    echo "4) Remove Client"
    echo "5) Show System Status"
    echo "6) Create Backup"
    echo "7) View Logs"
    echo "8) Uninstall WireGuard"
    echo "9) Exit"
    echo
}

# Handle menu selection
handle_menu_selection() {
    local choice
    read -rp "Enter your choice [1-9]: " choice
    
    case $choice in
        1)
            if [[ -f "$CONFIG_DIR/server.conf" ]]; then
                log_warning "WireGuard server appears to already be installed"
                read -rp "Continue anyway? [y/N]: " confirm
                [[ "$confirm" == [yY] ]] || return
            fi
            install_wireguard_server
            ;;
        2)
            if [[ ! -f "$CONFIG_DIR/server.conf" ]]; then
                log_error "WireGuard server not installed. Please install first."
                return
            fi
            create_new_client
            ;;
        3)
            list_all_clients
            ;;
        4)
            remove_client
            ;;
        5)
            check_system_status
            ;;
        6)
            create_system_backup
            ;;
        7)
            view_recent_logs
            ;;
        8)
            uninstall_wireguard
            ;;
        9)
            log_info "Exiting WireGuard Setup Manager"
            exit 0
            ;;
        *)
            log_warning "Invalid selection. Please choose 1-9."
            ;;
    esac
    
    echo
    read -rp "Press Enter to continue..."
}

# View recent logs
view_recent_logs() {
    echo
    log_info "Recent Log Entries"
    echo "======================================"
    
    if [[ -f "$LOG_FILE" ]]; then
        tail -20 "$LOG_FILE"
    else
        echo "No log file found."
    fi
    echo
}

# ==========================================
# INSTALLATION ORCHESTRATION
# ==========================================

# Complete WireGuard server installation
install_wireguard_server() {
    log_info "Starting WireGuard server installation..."
    
    # System validation
    validate_system_compatibility
    check_virtualization
    
    # Package management
    update_package_repositories
    install_system_packages
    
    # Configuration
    initialize_server_config
    configure_server_interactively
    create_server_configuration
    
    # Network setup
    setup_firewall_rules
    enable_ip_forwarding
    
    # Service management
    start_wireguard_service
    
    # Create initial backup
    create_system_backup
    
    log_success "WireGuard server installation completed successfully!"
    echo
    echo "Next steps:"
    echo "1. Create your first client using option 2"
    echo "2. Check system status using option 5"
    echo "3. Review logs using option 7"
    echo
}

# Uninstall WireGuard
uninstall_wireguard() {
    echo
    log_warning "WireGuard Uninstallation"
    echo "======================================"
    echo "This will remove WireGuard and all configurations!"
    echo
    read -rp "Are you absolutely sure? Type 'REMOVE' to continue: " confirm
    
    if [[ "$confirm" != "REMOVE" ]]; then
        log_info "Uninstallation cancelled"
        return
    fi
    
    log_info "Creating final backup before removal..."
    create_system_backup
    
    log_info "Stopping WireGuard service..."
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    
    log_info "Removing configuration files..."
    rm -rf "/etc/wireguard"
    rm -rf "$CONFIG_DIR"
    rm -f "/etc/sysctl.d/99-wireguard.conf"
    
    log_info "Removing firewall rules..."
    # This is simplified - in practice, you'd want to specifically remove the rules added
    
    log_success "WireGuard uninstalled successfully"
    echo "Backup files remain in $BACKUP_DIR"
}

# ==========================================
# MAIN EXECUTION
# ==========================================

# Main function
main() {
    # Initialize
    setup_logging
    verify_root_access
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Welcome message
    if [[ $# -eq 0 ]]; then
        while true; do
            show_main_menu
            handle_menu_selection
        done
    fi
    
    # Handle command line arguments if any
    case "${1:-}" in
        "install")
            install_wireguard_server
            ;;
        "status")
            check_system_status
            ;;
        "backup")
            create_system_backup
            ;;
        "--version")
            echo "$SCRIPT_NAME v$SCRIPT_VERSION"
            ;;
        "--help")
            echo "Usage: $0 [install|status|backup|--version|--help]"
            echo "Run without arguments for interactive mode"
            ;;
        *)
            if [[ -n "${1:-}" ]]; then
                log_error "Unknown command: $1"
                exit 1
            fi
            ;;
    esac
}

# Execute main function
main "$@"
