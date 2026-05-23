#!/bin/bash

# HTunnel Interactive Setup Script
# This script helps you configure HTunnel for client or server mode
# Repository: https://github.com/Hiddify2/HTunnel

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository info
GITHUB_REPO="Hiddify2/HTunnel"

# Print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect default network interface
detect_interface() {
    local iface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$iface" ]; then
        print_warning "Could not auto-detect interface"
        echo "eth0"
    else
        echo "$iface"
    fi
}

# Get public IP
get_public_ip() {
    local ip=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "1.1.1.1")
    echo "$ip"
}

# Validate IP address (supports partial validation)
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Main script
clear
echo "========================================"
echo "   HTunnel Interactive Setup Script"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_warning "This script should be run as root (sudo) for proper setup"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Ask for mode
echo "Which mode do you want to configure?"
echo "  1) Client"
echo "  2) Server"
echo ""
read -p "Enter your choice (1 or 2): " MODE_CHOICE

if [ "$MODE_CHOICE" = "1" ]; then
    MODE="client"
    CONFIG_FILE="config/client.json"
    print_info "Configuring HTunnel Client..."
elif [ "$MODE_CHOICE" = "2" ]; then
    MODE="server"
    CONFIG_FILE="config/server.json"
    print_info "Configuring HTunnel Server..."
else
    print_error "Invalid choice. Exiting."
    exit 1
fi

echo ""
print_info "Gathering system information..."
AUTO_INTERFACE=$(detect_interface)
PUBLIC_IP=$(get_public_ip)

print_info "Auto-detected interface: $AUTO_INTERFACE"
print_info "Your public IP: $PUBLIC_IP"
echo ""

# Create config directory if not exists
mkdir -p config

# Ask for configuration values
echo "========================================"
echo "   Configuration for $MODE"
echo "========================================"
echo ""

# Local/Real IP
read -p "Enter your real IP [$PUBLIC_IP]: " REAL_IP
REAL_IP=${REAL_IP:-$PUBLIC_IP}

# Validate IP
if ! validate_ip "$REAL_IP"; then
    print_error "Invalid IP address format"
    exit 1
fi

# Peer real IP
read -p "Enter peer's real IP: " PEER_REAL_IP
if ! validate_ip "$PEER_REAL_IP"; then
    print_error "Invalid IP address format"
    exit 1
fi

# Interface
echo ""
echo "Network interface options:"
echo "  1) Auto-detect (recommended) - will use: $AUTO_INTERFACE"
echo "  2) Enter manually"
read -p "Choose interface option (1 or 2): " IF_CHOICE

if [ "$IF_CHOICE" = "1" ]; then
    INTERFACE="auto"
    print_info "Using auto-detection for interface"
else
    read -p "Enter network interface (e.g., eth0, ens3): " INTERFACE
fi

# Data port
read -p "Enter data channel port [51820]: " DATA_PORT
DATA_PORT=${DATA_PORT:-51820}

if [ "$MODE" = "server" ]; then
    # Server-specific configuration
    echo ""
    echo "Server Configuration"
    echo "=================="
    
    read -p "Enter fake source IP for outgoing packets [1.2.3.4]: " FAKED_IP
    FAKED_IP=${FAKED_IP:-"1.2.3.4"}
    
    read -p "Enter fake IP pool (comma-separated, or press Enter to skip): " FAKED_POOL_INPUT
    
    if [ -z "$FAKED_POOL_INPUT" ]; then
        FAKED_POOL_JSON="[\"$FAKED_IP\"]"
    else
        # Convert comma-separated to JSON array
        FAKED_POOL_JSON="["
        IFS=',' read -ra IPS <<< "$FAKED_POOL_INPUT"
        for i in "${!IPS[@]}"; do
            if [ $i -eq 0 ]; then
                FAKED_POOL_JSON+="\"${IPS[$i]}\""
            else
                FAKED_POOL_JSON+="\"${IPS[$i]}\""
            fi
            if [ $i -lt $((${#IPS[@]}-1)) ]; then
                FAKED_POOL_JSON+=", "
            fi
        done
        FAKED_POOL_JSON+="]"
    fi
    
    # Allowed peers
    read -p "Enter additional allowed peer IPs (comma-separated, or press Enter for none): " ALLOWED_PEERS_INPUT
    
    if [ -z "$ALLOWED_PEERS_INPUT" ]; then
        ALLOWED_PEERS_JSON="[]"
    else
        ALLOWED_PEERS_JSON="["
        IFS=',' read -ra PEERS <<< "$ALLOWED_PEERS_INPUT"
        for i in "${!PEERS[@]}"; do
            ALLOWED_PEERS_JSON+="\"${PEERS[$i]}\""
            if [ $i -lt $((${#PEERS[@]}-1)) ]; then
                ALLOWED_PEERS_JSON+=", "
            fi
        done
        ALLOWED_PEERS_JSON+="]"
    fi
    
    # Create server config
    cat > "$CONFIG_FILE" << EOF
{
  // Listen address for tunnel data channel
  "listen": "0.0.0.0:$DATA_PORT",

  // Network interface for raw sockets (or "auto" for auto-detection)
  "interface": "$INTERFACE",

  // Server's real IP address
  "real_ip": "$REAL_IP",

  // Client's real IP address
  "peer_real_ip": "$PEER_REAL_IP",

  // Fake source IP for outgoing packets
  "faked_ip": "$FAKED_IP",

  // Pool of fake IPs for rotation
  "faked_ip_pool": $FAKED_POOL_JSON,

  // UDP data channel port (must match client)
  "data_port": $DATA_PORT,

  // Additional allowed client IPs (add proxy IPs here)
  "allowed_peers": $ALLOWED_PEERS_JSON,

  // Performance settings
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // Not used on server (kept for schema consistency)
  "uplink_proxy": null
}
EOF
    
    print_success "Server configuration saved to $CONFIG_FILE"
    
else
    # Client-specific configuration
    echo ""
    echo "Client Configuration"
    echo "=================="
    
    read -p "Enter expected fake IP from server [1.2.3.4]: " PEER_FAKE_IP
    PEER_FAKE_IP=${PEER_FAKE_IP:-"1.2.3.4"}
    
    read -p "Enter local SOCKS5 listen address [127.0.0.1:9234]: " LISTEN_ADDR
    LISTEN_ADDR=${LISTEN_ADDR:-"127.0.0.1:9234"}
    
    read -p "Use upstream SOCKS5 proxy for uplink? (y/n): " -n 1 -r USE_PROXY
    echo ""
    
    if [[ $USE_PROXY =~ ^[Yy]$ ]]; then
        read -p "Enter SOCKS5 proxy address (host:port): " UPLINK_PROXY
        UPLINK_PROXY_JSON="\"$UPLINK_PROXY\""
    else
        UPLINK_PROXY_JSON="null"
    fi
    
    # Allowed peers
    read -p "Enter additional allowed server IPs (comma-separated, or press Enter for none): " ALLOWED_PEERS_INPUT
    
    if [ -z "$ALLOWED_PEERS_INPUT" ]; then
        ALLOWED_PEERS_JSON="[]"
    else
        ALLOWED_PEERS_JSON="["
        IFS=',' read -ra PEERS <<< "$ALLOWED_PEERS_INPUT"
        for i in "${!PEERS[@]}"; do
            ALLOWED_PEERS_JSON+="\"${PEERS[$i]}\""
            if [ $i -lt $((${#PEERS[@]}-1)) ]; then
                ALLOWED_PEERS_JSON+=", "
            fi
        done
        ALLOWED_PEERS_JSON+="]"
    fi
    
    # Create client config
    cat > "$CONFIG_FILE" << EOF
{
  // Local SOCKS5 proxy address. Configure your browser/app to use this.
  "listen": "$LISTEN_ADDR",

  // Network interface for raw sockets (or "auto" for auto-detection)
  "interface": "$INTERFACE",

  // Client's real IP address
  "real_ip": "$REAL_IP",

  // Server's real IP address
  "peer_real_ip": "$PEER_REAL_IP",

  // Expected fake IP that server uses for replies
  "peer_fake_ip": "$PEER_FAKE_IP",

  // UDP data channel port (must match server)
  "data_port": $DATA_PORT,

  // Additional allowed server IPs
  "allowed_peers": $ALLOWED_PEERS_JSON,

  // Performance settings
  "tunnel_count": 4,
  "mtu": 1380,
  "initial_cwnd": 10.0,

  // Upstream SOCKS5 proxy for uplink (host:port)
  "uplink_proxy": $UPLINK_PROXY_JSON
}
EOF
    
    print_success "Client configuration saved to $CONFIG_FILE"
fi

echo ""
echo "========================================"
print_success "Setup completed!"
echo "========================================"
echo ""
print_info "Configuration file: $CONFIG_FILE"
print_info "You can edit it manually if needed."
echo ""

# Ask if user wants to install as systemd service
read -p "Do you want to install HTunnel $MODE as a systemd service? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Installing HTunnel $MODE as systemd service..."
    
    # Determine binary path
    if [ "$MODE" = "client" ]; then
        BINARY_PATH="/usr/local/bin/client"
        SERVICE_NAME="htunnel-client"
    else
        BINARY_PATH="/usr/local/bin/server"
        SERVICE_NAME="htunnel-server"
    fi
    
    # Move binary to system path if needed
    if [ -f "./$BINARY_LOCAL" ]; then
        sudo mv "./$BINARY_LOCAL" "$BINARY_PATH"
        sudo chmod +x "$BINARY_PATH"
    elif [ -f "target/release/$BINARY_LOCAL" ]; then
        sudo cp "target/release/$BINARY_LOCAL" "$BINARY_PATH"
        sudo chmod +x "$BINARY_PATH"
    fi
    
    # Create systemd service file
    sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null << EOF
[Unit]
Description=HTunnel ${MODE^}
After=network.target

[Service]
Type=simple
ExecStart=$BINARY_PATH --config /etc/htunnel/$CONFIG_FILE
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    
    # Create config directory and copy config
    sudo mkdir -p /etc/htunnel
    sudo cp "$CONFIG_FILE" "/etc/htunnel/$CONFIG_FILE"
    
    # Reload and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_NAME"
    
    read -p "Do you want to start the service now? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo systemctl start "$SERVICE_NAME"
        print_success "Service $SERVICE_NAME started!"
        print_info "Check status with: sudo systemctl status $SERVICE_NAME"
        print_info "View logs with: sudo journalctl -u $SERVICE_NAME -f"
    fi
fi

# Ask if user wants to run now (if not installed as service)
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    read -p "Do you want to run HTunnel $MODE now? (y/n): " -n 1 -r
    echo ""
fi

if [[ $REPLY =~ ^[Yy]$ ]]; then

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Determine binary name based on mode
    if [ "$MODE" = "client" ]; then
        BINARY_NAME="HTunnel-client-linux-x86_64"
        BINARY_LOCAL="client"
    else
        BINARY_NAME="HTunnel-server-linux-x86_64"
        BINARY_LOCAL="server"
    fi
    
    # Check if binary already exists locally
    if [ -f "./$BINARY_LOCAL" ]; then
        BINARY="./$BINARY_LOCAL"
        print_info "Using existing binary: $BINARY"
    elif [ -f "target/release/$BINARY_LOCAL" ]; then
        BINARY="target/release/$BINARY_LOCAL"
        print_info "Using local build: $BINARY"
    else
        # Download from GitHub releases
        print_info "Downloading latest $MODE binary from GitHub releases..."
        
        # Get latest release download URL
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/$BINARY_NAME"
        
        print_info "Downloading from: $DOWNLOAD_URL"
        
        if curl -L -o "$BINARY_LOCAL" "$DOWNLOAD_URL"; then
            chmod +x "$BINARY_LOCAL"
            BINARY="./$BINARY_LOCAL"
            print_success "Downloaded and made executable: $BINARY"
        else
            print_warning "Download failed. Attempting to build from source..."
            
            if [ -f "Cargo.toml" ]; then
                print_info "Running cargo build --release..."
                cargo build --release
                BINARY="target/release/$BINARY_LOCAL"
            else
                print_error "Cannot download or build. Please manually download from:"
                print_error "https://github.com/Hiddify2/HTunnel/releases/latest"
                exit 1
            fi
        fi
    fi
    
    print_info "Starting HTunnel $MODE..."
    print_info "Press Ctrl+C to stop"
    echo ""
    
    # Check if we have CAP_NET_RAW capability
    if sudo -n true 2>/dev/null; then
        sudo ./$BINARY_LOCAL --config "$CONFIG_FILE"
    else
        # Try using capabilities
        if command -v setcap &> /dev/null; then
            print_info "Setting CAP_NET_RAW capability..."
            sudo setcap cap_net_raw+ep "./$BINARY_LOCAL"
            ./$BINARY_LOCAL --config "$CONFIG_FILE"
        else
            print_warning "setcap not found. Running with sudo..."
            sudo ./$BINARY_LOCAL --config "$CONFIG_FILE"
        fi
    fi
fi
