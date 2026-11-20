#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/sysvoidscan"
SERVICE_NAME="sysvoidscan"
REPO_URL="https://github.com/SysVoid/SysVoidScan.git"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${CYAN}[*]${NC} $1"; }
ok()     { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
err()    { echo -e "${RED}[-]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root or with sudo."
        exit 1
    fi
    ok "Running as root."
}

check_python() {
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [[ "$PY_MAJOR" -ge 3 ]] && [[ "$PY_MINOR" -ge 8 ]]; then
            ok "Python $PY_VER found."
            PYTHON=python3
            return
        fi
    fi
    warn "Python 3.8+ not found. Installing..."
    install_python
}

install_python() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq python3 python3-pip python3-venv
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm python python-pip
    else
        err "Cannot install Python automatically. Install Python 3.8+ manually."
        exit 1
    fi
    PYTHON=python3
    ok "Python installed."
}

install_pip() {
    if ! $PYTHON -m pip --version &>/dev/null; then
        log "Installing pip..."
        $PYTHON -m ensurepip --upgrade 2>/dev/null || {
            wget -q https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
            $PYTHON /tmp/get-pip.py
            rm -f /tmp/get-pip.py
        }
    fi
    ok "pip is available."
}

install_system_tools() {
    log "Installing system tools..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq nmap curl wget git unzip ruby ruby-dev build-essential libssl-dev libffi-dev
    elif command -v yum &>/dev/null; then
        yum install -y nmap curl wget git unzip ruby ruby-devel gcc make openssl-devel libffi-devel
    elif command -v dnf &>/dev/null; then
        dnf install -y nmap curl wget git unzip ruby ruby-devel gcc make openssl-devel libffi-devel
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm nmap curl wget git unzip base-devel
    fi

    if command -v gem &>/dev/null && ! command -v wpscan &>/dev/null; then
        log "Installing wpscan via gem..."
        gem install wpscan 2>/dev/null || warn "wpscan gem install failed."
    fi

    ok "System tools installed."
}

install_go() {
    if ! command -v go &>/dev/null; then
        log "Installing Go..."
        GO_VER="1.22.5"
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  GO_ARCH="amd64" ;;
            aarch64) GO_ARCH="arm64" ;;
            armv7l)  GO_ARCH="armv6l" ;;
            *)       err "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        wget -q "https://go.dev/dl/go${GO_VER}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
        echo 'export GOPATH=$HOME/go' >> /etc/profile.d/go.sh
        echo 'export PATH=$PATH:$GOPATH/bin' >> /etc/profile.d/go.sh
    fi
    ok "Go is available."
}

install_go_tools() {
    log "Installing Go-based tools..."
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH=$PATH:$GOPATH/bin

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/dalfox/v2@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        name=$(basename "$tool" | cut -d@ -f1)
        if command -v "$name" &>/dev/null; then
            ok "$name already installed."
            continue
        fi
        log "Installing $name..."
        go install "$tool" 2>/dev/null && ok "$name installed." || warn "Failed to install $name."
    done
}

install_python_deps() {
    log "Installing Python dependencies..."
    cd "$INSTALL_DIR"
    $PYTHON -m pip install --upgrade pip -q
    $PYTHON -m pip install -r requirements.txt -q
    $PYTHON -m pip install pytest pytest-cov -q
    ok "Python dependencies installed."
}

clone_repository() {
    log "Cloning SysVoidScan to $INSTALL_DIR..."
    if [[ -d "$INSTALL_DIR" ]]; then
        warn "Directory $INSTALL_DIR already exists. Updating..."
        cd "$INSTALL_DIR"
        git pull --quiet
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    ok "Repository ready at $INSTALL_DIR."
}

install_service() {
    log "Installing systemd service..."
    cp "$INSTALL_DIR/linux/sysvoidscan.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null
    ok "Service installed and enabled."
}

make_executable() {
    chmod +x "$INSTALL_DIR/main.py"
    chmod +x "$INSTALL_DIR/linux/install.sh"
    chmod +x "$INSTALL_DIR/linux/uninstall.sh"
    if [[ -f "$INSTALL_DIR/SysVoidScan.py" ]]; then
        chmod +x "$INSTALL_DIR/SysVoidScan.py"
    fi
    ok "Scripts marked as executable."
}

create_aliases() {
    log "Creating system-wide alias..."
    if ! grep -q "sysvoidscan" /etc/bash.bashrc 2>/dev/null; then
        echo "alias sysvoidscan='python3 $INSTALL_DIR/main.py'" >> /etc/bash.bashrc
    fi
    ok "Alias 'sysvoidscan' available in new shells."
}

print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SysVoidScan Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "  Install dir: ${CYAN}$INSTALL_DIR${NC}"
    echo -e "  Run scan:    ${CYAN}python3 $INSTALL_DIR/main.py -t <target>${NC}"
    echo -e "  Or alias:    ${CYAN}sysvoidscan -t <target>${NC}"
    echo -e "  Service:     ${CYAN}systemctl start $SERVICE_NAME${NC}"
    echo -e "  Tests:       ${CYAN}cd $INSTALL_DIR && python3 -m pytest tests/${NC}"
    echo ""
}

main() {
    echo -e "${CYAN}"
    echo "   _____            _  __        __   ____       _ "
    echo "  / ____|          (_) \ \      / /  / ___|  ___| |_ ___  _ __  _ __ "
    echo "  \___ \ _ __  _ __ _| |\ \ /\ / /   \___ \ / __| __/ _ \| '__|| '_ \\"
    echo "   ___) | '_ \| '__| | | \ V  V /     ___) | (__| || (_) | |   | | | |"
    echo "  |____/| .__/|_|  |_|_|  \_/\_/     |____/ \___|\__\___/|_|   |_| |_|"
    echo "        | |"
    echo "        |_|  - Installer"
    echo -e "${NC}"

    check_root
    check_python
    install_pip
    install_system_tools
    install_go
    install_go_tools
    clone_repository
    install_python_deps
    install_service
    make_executable
    create_aliases
    print_summary
}

main "$@"
