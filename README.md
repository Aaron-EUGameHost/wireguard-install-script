# wireguard-install-script# 🔐 WireGuard Setup Manager

**A modern, secure, and user-friendly WireGuard VPN installation script with advanced management features**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Aaron-EUGameHost/wireguard-install-script/graphs/commit-activity)

---

## 🚀 Quick Installation

### One-Line Installation
```bash
curl -fsSL https://raw.githubusercontent.com/Aaron-EUGameHost/wireguard-install-script/main/install.sh | sudo bash
```

### Step-by-Step Installation
```bash
curl -O https://raw.githubusercontent.com/Aaron-EUGameHost/wireguard-install-script/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

---

## 📋 What This Script Does

This script provides a **complete WireGuard VPN solution** that transforms your Linux server into a secure, high-performance VPN server in minutes. Unlike basic installers, our script offers enterprise-grade features with consumer-friendly simplicity.

---

## 🏆 Recommended VPS Providers

*Get the best performance and reliability for your WireGuard VPN with these tested providers:*

| Provider       | Starting Price              | Locations                            | DDoS Protection                                                                               | Has WireGuard DDoS Filter | Why Choose                                                                                                                                                 |
| -------------- | --------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EUGameHost** | £2.00 /mo ([EUGameHost][1]) | UK ([EUGameHost][2])        | Global Anycast Network, Custom Wireguard Filter, Up to 6Tbps filtering capacity                    | Yes      | Game-focused host with military-grade CosmicGuard scrubbing, NVMe Gen4 SSDs, 10 Gbps uplinks, and daily offsite backups ([EUGameHost][4], [EUGameHost][2]) |
| **Hetzner**    | €3.79 /mo ([Hetzner][5])    | Germany, Finland, USA ([Hetzner][5]) | Minimal                        | No          | Best price-performance CX shared vCPU plans; GDPR-compliant EU hosting with free, included DDoS mitigation ([Hetzner][5], [Hetzner][6])                    |
| **OVHcloud**   | \$2.52 /mo ([OVHcloud][7])  | Worldwide ([OVHcloud][8])            | On demand  Anti-DDoS infrastructure | No         | Integrated mitigation at no extra cost, backed by a global backbone for rapid traffic scrubbing and maximum uptime ([OVHcloud][9], [OVHcloud][9])          |


> **💡 Pro Tip:** For personal use, we recommend **Vultr** or **Hetzner** for the best balance of performance, price, and reliability. For business use, consider **AWS** or **Google Cloud** for their advanced networking features.

---


### 🎯 Core Functionality

**Automated Server Setup:**
- Detects your operating system and installs compatible WireGuard packages
- Configures network interfaces and routing automatically
- Sets up secure firewall rules (UFW, Firewalld, or iptables)
- Enables IP forwarding for optimal VPN performance
- Creates systemd services for automatic startup

**Intelligent Client Management:**
- Interactive client creation with input validation
- Automatic IP address assignment with conflict prevention
- QR code generation for mobile devices (both terminal and PNG)
- Client configuration file generation with optimal settings
- Easy client removal with automatic cleanup

---

## ✨ Advanced Features & Why They Matter

### 🔒 **Enterprise-Grade Security**
- **Cryptographic Key Management**: Secure generation and storage of private keys with proper file permissions (600/700)
- **Input Validation**: Comprehensive validation prevents configuration errors and security vulnerabilities
- **Firewall Integration**: Automatically detects and configures your system's firewall (UFW, Firewalld, iptables)
- **Network Isolation**: Proper subnet management prevents IP conflicts and ensures network security

*Why it matters: Your VPN is only as secure as its weakest configuration point. We eliminate common security mistakes.*

### 🎨 **Superior User Experience**
- **Interactive Menu System**: Intuitive colored menus make complex operations simple
- **Real-Time Status Monitoring**: Live connection tracking and system resource monitoring
- **QR Code Generation**: Instant mobile device setup - scan and connect
- **Comprehensive Logging**: Detailed logs help troubleshoot issues quickly

*Why it matters: Complex doesn't have to mean complicated. Spend time using your VPN, not configuring it.*

### 🛠️ **Professional Management Tools**
- **JSON Configuration Storage**: Structured configuration management for reliability and scalability
- **Automated Backup System**: Timestamped backups protect against data loss
- **Client Metadata Tracking**: Track creation dates, status, and usage patterns
- **Service Health Monitoring**: Real-time monitoring of WireGuard service status

*Why it matters: Professional tools for professional results. Manage dozens of clients as easily as one.*

### 🌐 **Multi-Platform Compatibility**
- **Ubuntu 20.04+** - Full support with APT package management
- **Debian 10+** - Native WireGuard support with backports handling
- **CentOS 8+** - EPEL repository integration and RPM management  
- **Fedora 35+** - Latest WireGuard tools with DNF
- **AlmaLinux & Rocky Linux** - Enterprise Linux compatibility
- **Raspberry Pi OS** - ARM architecture support for Pi-based VPNs

*Why it matters: One script works everywhere. No need to learn different tools for different systems.*

### 📊 **Smart Network Management**
- **Automatic Interface Detection**: Finds your primary network interface automatically
- **Port Availability Checking**: Scans for available ports to prevent conflicts  
- **IP Range Management**: Intelligent IP assignment prevents subnet collisions
- **DNS Configuration**: Optimized DNS settings for performance and privacy

*Why it matters: Networking complexity handled automatically. Just answer simple questions and go.*

### 🔄 **Maintenance & Operations**
- **Live Configuration Reloading**: Add/remove clients without service interruption
- **System Status Dashboard**: Real-time view of connections, resources, and performance
- **Automated Cleanup**: Proper resource cleanup when removing clients or uninstalling
- **Log Management**: Structured logging with different severity levels

*Why it matters: VPNs need ongoing management. We make it effortless.*

## 📱 Supported Client Platforms

Your WireGuard VPN works seamlessly across all devices:

- **🪟 Windows** - Official WireGuard client
- **🍎 macOS** - App Store or official client  
- **🐧 Linux** - Native WireGuard support
- **📱 iOS** - WireGuard app from App Store
- **🤖 Android** - WireGuard app from Google Play
- **🌐 OpenWRT** - Router-level VPN support

---

## 🛠️ System Requirements

### **Minimum Requirements:**
- **OS**: Ubuntu 20.04+, Debian 10+, CentOS 8+, Fedora 35+
- **RAM**: 512MB (1GB+ recommended)  
- **Storage**: 1GB free space
- **Network**: Public IP address
- **Access**: Root/sudo privileges

### **Recommended Specifications:**
- **CPU**: 2+ cores for multiple clients
- **RAM**: 2GB+ for optimal performance
- **Storage**: SSD for better I/O performance  
- **Bandwidth**: Unmetered or high allocation

### **Tested Operating Systems:**
- ✅ Ubuntu 20.04, 22.04, 24.04 LTS
- ✅ Debian 10 (Buster), 11 (Bullseye), 12 (Bookworm)
- ✅ CentOS 8, 9 Stream
- ✅ AlmaLinux 8, 9  
- ✅ Rocky Linux 8, 9
- ✅ Fedora 35, 36, 37, 38+
- ✅ Raspberry Pi OS (ARM)

---

## 🎯 Usage Examples

### **Basic Installation**
```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/Aaron-EUGameHost/wireguard-install-script/main/install.sh | sudo bash

# Follow the interactive prompts:
# 1) Install WireGuard Server
# Enter your preferences or press Enter for defaults
```

### **Adding Your First Client**  
```bash
# Run the script again after installation
sudo ./wireguard-install.sh

# Select: 2) Add New Client
# Enter client name: "laptop"
# QR code and config file generated automatically
```

### **Command Line Usage**
```bash
# Direct installation
sudo ./wireguard-install.sh install

# Check system status  
sudo ./wireguard-install.sh status

# Create backup
sudo ./wireguard-install.sh backup
```

---

## 🔧 Advanced Configuration

### **Custom Network Settings**
```bash
# Edit server configuration before installation
nano /etc/wireguard-manager/server.conf

# Customize VPN subnet, DNS servers, port ranges
# Full JSON schema documentation included
```

### **Firewall Customization**
```bash
# Script automatically detects and configures:
# - UFW (Ubuntu/Debian)
# - Firewalld (CentOS/RHEL/Fedora)  
# - iptables (fallback)

# Manual firewall rules also supported
```

### **Performance Tuning**
```bash
# Optimized settings included:
# - Kernel parameter tuning
# - Network interface optimization
# - Connection keepalive settings
# - MTU size optimization
```

---

## 📊 Why WireGuard?

**WireGuard vs. OpenVPN Performance:**
- 🚀 **4x faster** connection speeds
- 🔋 **Better battery life** on mobile devices  
- 🛡️ **Modern cryptography** (ChaCha20, Poly1305)
- 🔧 **Simpler configuration** (less than 100 lines of code)
- ✅ **Kernel-level integration** for maximum performance

**Real-World Speed Comparison:**
- **OpenVPN**: ~300 Mbps maximum throughput
- **WireGuard**: ~1000+ Mbps throughput possible
- **Latency**: 50% lower ping times vs OpenVPN
- **CPU Usage**: 80% less CPU overhead

---

## 🚨 Security Features

### **Built-in Security Measures:**
- 🔐 **Perfect Forward Secrecy** - Keys rotated automatically
- 🛡️ **DDoS Protection** - Built-in rate limiting
- 🔒 **Strong Encryption** - ChaCha20-Poly1305 cipher suite  
- 🚫 **No Log Policy** - Script creates no persistent logs by default
- 🌐 **DNS Leak Protection** - Secure DNS configuration included

### **Network Security:**  
- **Automatic Firewall Rules** - Only necessary ports opened
- **IP Forwarding Controls** - Secure routing configuration
- **Network Isolation** - Client traffic properly segmented
- **Access Control** - Per-client IP and routing restrictions

---

## 📈 Monitoring & Maintenance

### **Built-in Monitoring:**
```bash
# Real-time connection status
sudo ./wireguard-install.sh status

# View system resources
# Check connected clients  
# Monitor network traffic
# Review system logs
```

### **Automated Maintenance:**
- 🔄 **Configuration Validation** - Automatic syntax checking
- 💾 **Backup Management** - Automated timestamped backups
- 🧹 **Log Rotation** - Prevents disk space issues
- 🔍 **Health Checks** - Service monitoring included

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### **Reporting Issues:**
- 🐛 **Bug Reports** - Use GitHub issues with detailed info
- 💡 **Feature Requests** - Suggest new functionality
- 📝 **Documentation** - Help improve our guides

### **Code Contributions:**
- 🔧 **Shell Scripting** - Bash expertise welcome
- 🌐 **Network Configuration** - VPN and networking knowledge
- 🧪 **Testing** - Multi-platform testing needed

### **Support the Project:**
- ⭐ **Star this repository** - Help others discover it
- 📢 **Share with friends** - Spread the word
- 💬 **Join discussions** - Help answer questions

---

## 🆘 Support & Troubleshooting

### **Common Issues:**

**❓ "Port already in use" error**
```bash
# Script automatically finds available ports
# If you need a specific port, stop conflicting services first
```

**❓ "Cannot detect public IP" error**  
```bash
# Manual IP specification supported
# Check your cloud provider's networking setup
```

**❓ "Kernel module not found" error**
```bash
# Script handles kernel module installation
# Older kernels may need system updates
```

### **Getting Help:**
- 💬 **GitHub Issues** - Search existing issues first
- 🌐 **Discord Community**:  
  [![Discord](https://img.shields.io/discord/4bcN48qvYa?label=Support%20Chat&logo=discord)](https://discord.gg/4bcN48qvYa)

---

## 📜 License & Legal

**MIT License** - Free for personal and commercial use

This project is not affiliated with the WireGuard project. WireGuard is a registered trademark of Jason A. Donenfeld.

### **Privacy Notice:**
- No user data collected or transmitted
- No telemetry or analytics included
- Configuration remains on your server only
- Open source - audit the code yourself

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Aaron-EUGameHost/wireguard-install-script&type=Date)](https://star-history.com/#Aaron-EUGameHost/wireguard-install-script&Date)

---

**Made with ❤️ by [EUGameHost](https://github.com/Aaron-EUGameHost)**

*Secure your connections. Protect your privacy. Own your VPN.*
