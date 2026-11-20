#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/sysvoidscan"
SERVICE_NAME="sysvoidscan"

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
}

stop_service() {
    log "Stopping and disabling $SERVICE_NAME service..."
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        ok "Service stopped."
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        ok "Service disabled."
    fi
}

remove_service_file() {
    log "Removing systemd service file..."
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    ok "Service file removed."
}

remove_install_dir() {
    log "Removing $INSTALL_DIR..."
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        ok "Installation directory removed."
    else
        warn "$INSTALL_DIR not found."
    fi
}

remove_alias() {
    log "Removing alias from bashrc..."
    if grep -q "sysvoidscan" /etc/bash.bashrc 2>/dev/null; then
        sed -i '/alias sysvoidscan=/d' /etc/bash.bashrc
        ok "Alias removed."
    fi
}

remove_go_tools() {
    log "Removing Go tools..."
    export GOPATH=${GOPATH:-$HOME/go}
    export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

    GO_BINS=(subfinder httpx katana dalfox ffuf gobuster nuclei)
    for bin in "${GO_BINS[@]}"; do
        if [[ -f "$GOPATH/bin/$bin" ]]; then
            rm -f "$GOPATH/bin/$bin"
            ok "Removed $bin."
        fi
    done
}

print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SysVoidScan Uninstalled!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "  ${YELLOW}Note:${NC} System packages (nmap, python3, etc.) were NOT removed."
    echo -e "  ${YELLOW}Note:${NC} Go was NOT removed from /usr/local/go."
    echo ""
}

main() {
    echo -e "${CYAN}SysVoidScan Uninstaller${NC}"
    echo ""

    check_root
    stop_service
    remove_service_file
    remove_alias
    remove_go_tools
    remove_install_dir
    print_summary
}

main "$@"
