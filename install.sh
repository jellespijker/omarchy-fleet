#!/usr/bin/env bash
set -euo pipefail

# Colors
BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}================================================================${RESET}"
echo -e "${BOLD} 󰓠 Omarchy Fleet Security Plugin Installer${RESET}"
echo -e "${BOLD}${CYAN}================================================================${RESET}\n"

# 1. Dependency Checks
echo -e "${BOLD}[1/5] Checking prerequisites...${RESET}"

has_dep() {
  command -v "$1" >/dev/null 2>&1
}

MISSING_DEPS=()
if ! has_dep python3; then MISSING_DEPS+=("python3"); fi
if ! has_dep wl-copy; then MISSING_DEPS+=("wl-clipboard"); fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
  echo -e "${RED}Error: Missing required packages: ${MISSING_DEPS[*]}${RESET}"
  echo "Please install them using your package manager, e.g.:"
  echo "  omarchy pkg add ${MISSING_DEPS[*]}"
  exit 1
fi
echo -e "  ${GREEN}✓${RESET} Core utilities found (python3, wl-clipboard)"

if ! has_dep fleetctl; then
  echo -e "${YELLOW}Warning: 'fleetctl' CLI was not found in PATH.${RESET}"
  echo "Fleet Security requires 'fleetctl' to query your FleetDM instance."
  echo "To install fleetctl:"
  echo "  - Arch/AUR: yay -S fleetctl-bin (or paru -S fleetctl-bin)"
  echo "  - Direct download: https://github.com/fleetdm/fleet/releases"
  echo "  - Official docs: https://fleetdm.com/docs/using-fleet/fleetctl-cli"
  echo ""
  read -r -p "Do you want to continue installation anyway? [y/N] " continue_without_fleetctl
  if [[ ! "$continue_without_fleetctl" =~ ^[Yy]$ ]]; then
    exit 1
  fi
else
  echo -e "  ${GREEN}✓${RESET} 'fleetctl' command found: $(fleetctl version 2>/dev/null || echo 'installed')"
fi

# 2. Target Directory Setup
echo -e "\n${BOLD}[2/5] Setting up plugin directory...${RESET}"
PLUGIN_DIR="${HOME}/.config/omarchy/plugins/jellespijker.fleet"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

mkdir -p "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR/bin"
mkdir -p "${HOME}/.cache/omarchy-fleet"

if [ "$SCRIPT_DIR" != "$PLUGIN_DIR" ]; then
  echo "Copying plugin files from $SCRIPT_DIR to $PLUGIN_DIR..."
  cp -r "$SCRIPT_DIR/manifest.json" "$PLUGIN_DIR/"
  cp -r "$SCRIPT_DIR/Panel.qml" "$PLUGIN_DIR/"
  cp -r "$SCRIPT_DIR/README.md" "$PLUGIN_DIR/"
  if [ -f "$SCRIPT_DIR/LICENSE" ]; then cp "$SCRIPT_DIR/LICENSE" "$PLUGIN_DIR/"; fi
  if [ -f "$SCRIPT_DIR/preview.png" ]; then cp "$SCRIPT_DIR/preview.png" "$PLUGIN_DIR/"; fi
  if [ -f "$SCRIPT_DIR/config.json.example" ]; then cp "$SCRIPT_DIR/config.json.example" "$PLUGIN_DIR/"; fi
  if [ -f "$SCRIPT_DIR/demo.html" ]; then cp "$SCRIPT_DIR/demo.html" "$PLUGIN_DIR/"; fi
  cp -r "$SCRIPT_DIR/bin/"* "$PLUGIN_DIR/bin/"
fi

chmod +x "$PLUGIN_DIR/bin/fleet-monitor"
chmod +x "$PLUGIN_DIR/bin/fleet-triage"
chmod +x "$PLUGIN_DIR/bin/fleet-setup"
echo -e "  ${GREEN}✓${RESET} Plugin files installed to ${PLUGIN_DIR}"

# 3. Configuration & Fleet Discovery
echo -e "\n${BOLD}[3/5] Configuring FleetDM Connection...${RESET}"

DEFAULT_URL=""
# Try to discover address from ~/.fleet/config
if [ -f "${HOME}/.fleet/config" ]; then
  DISCOVERED_ADDR=$(grep -E '^\s*address:' "${HOME}/.fleet/config" | head -n 1 | awk '{print $2}' || true)
  if [ -n "$DISCOVERED_ADDR" ]; then
    DEFAULT_URL="$DISCOVERED_ADDR"
    echo -e "  Found Fleet address in ~/.fleet/config: ${CYAN}${DEFAULT_URL}${RESET}"
  fi
fi

if [ -z "$DEFAULT_URL" ]; then
  if has_dep tailscale; then
    TS_IP=$(tailscale ip -4 2>/dev/null | head -n 1 || true)
    if [ -n "$TS_IP" ]; then
      DEFAULT_URL="https://${TS_IP}:8080"
    fi
  fi
  DEFAULT_URL="${DEFAULT_URL:-https://localhost:8080}"
fi

if [ ! -f "$PLUGIN_DIR/config.json" ]; then
  echo "Creating initial config.json..."
  if [ -t 0 ]; then
    read -r -p "Enter your Fleet Web / API URL [default: ${DEFAULT_URL}]: " USER_URL
    FLEET_URL="${USER_URL:-$DEFAULT_URL}"
  else
    FLEET_URL="$DEFAULT_URL"
  fi

  cat <<EOF > "$PLUGIN_DIR/config.json"
{
  "fleet_url": "${FLEET_URL}",
  "refresh_interval_sec": 60,
  "terminal_cmd": "omarchy-launch-floating-terminal-with-presentation"
}
EOF
  echo -e "  ${GREEN}✓${RESET} Created config.json with Fleet URL: ${FLEET_URL}"
else
  echo -e "  ${GREEN}✓${RESET} Preserving existing configuration at $PLUGIN_DIR/config.json"
fi

# Optional Interactive Setup Wizard
if [ -t 0 ] && has_dep fleetctl; then
  echo ""
  read -r -p "Would you like to run the interactive Fleet setup wizard now? [Y/n]: " RUN_WIZARD
  if [[ "$RUN_WIZARD" =~ ^[Yy]?$ ]]; then
    python3 "$PLUGIN_DIR/bin/fleet-setup"
  fi
fi

# 4. Global CLI Symlinks
echo -e "\n${BOLD}[4/5] Setting up global CLI helpers...${RESET}"
mkdir -p "${HOME}/.local/bin"
ln -sf "$PLUGIN_DIR/bin/fleet-setup" "${HOME}/.local/bin/fleet-setup"
ln -sf "$PLUGIN_DIR/bin/fleet-triage" "${HOME}/.local/bin/fleet-triage"
ln -sf "$PLUGIN_DIR/bin/fleet-monitor" "${HOME}/.local/bin/fleet-monitor"
echo -e "  ${GREEN}✓${RESET} Symlinked ${CYAN}fleet-setup${RESET}   -> ~/.local/bin/fleet-setup"
echo -e "  ${GREEN}✓${RESET} Symlinked ${CYAN}fleet-triage${RESET}  -> ~/.local/bin/fleet-triage"
echo -e "  ${GREEN}✓${RESET} Symlinked ${CYAN}fleet-monitor${RESET} -> ~/.local/bin/fleet-monitor"

# 5. Omarchy Registration & Activation
echo -e "\n${BOLD}[5/5] Registering with Omarchy shell...${RESET}"
if has_dep omarchy; then
  echo "Validating plugin manifest..."
  omarchy plugin validate "$PLUGIN_DIR"
  echo "Enabling plugin on right bar..."
  omarchy plugin enable jellespijker.fleet right || true
  
  if has_dep omarchy; then
    echo "Reloading Omarchy shell..."
    omarchy restart shell || true
  fi
  echo -e "  ${GREEN}✓${RESET} Fleet Security plugin enabled successfully!"
else
  echo -e "  ${YELLOW}Notice: 'omarchy' CLI not in PATH. Please reload your shell manually.${RESET}"
fi

echo -e "\n${BOLD}${GREEN}================================================================${RESET}"
echo -e "${BOLD}${GREEN} Installation Complete!${RESET}"
echo -e "${BOLD}${GREEN}================================================================${RESET}"
echo -e "• Click the ${BOLD}󰓠${RESET} icon in your Omarchy status bar to open the security panel."
echo -e "• Run ${BOLD}fleet-triage${RESET} anywhere in your terminal for deep CISA KEV reports."
echo -e "• Press ${BOLD}R${RESET} in the panel or right-click the bar icon to refresh vulnerabilities."
echo -e "• Click any host chip (e.g. [omarchy], [arch-prod]) to copy instant remediation commands.\n"
