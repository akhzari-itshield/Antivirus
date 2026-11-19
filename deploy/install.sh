#!/bin/bash
# ITShield Antivirus - Linux installer (Phase 10)
#
# Installs ITShield as a systemd service. Run as root or with sudo.
#
# Usage:
#   sudo ./deploy/install.sh           # install
#   sudo ./deploy/install.sh --uninstall  # remove

set -e

SERVICE_NAME="itshield"
INSTALL_DIR="/opt/itshield"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
DATA_DIR="/var/lib/itshield"
LOG_DIR="/var/log/itshield"
RUN_DIR="/run/itshield"
USER_NAME="itshield"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Must run as root.
if [ "$(id -u)" -ne 0 ]; then
  error "This script must be run as root (use sudo)."
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "${SCRIPT_DIR}/.." && pwd )"

# ---------------------------------------------------------- uninstall
if [ "$1" = "--uninstall" ]; then
  info "Stopping service..."
  systemctl stop ${SERVICE_NAME} 2>/dev/null || true
  systemctl disable ${SERVICE_NAME} 2>/dev/null || true
  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload
  info "Removing install directory..."
  rm -rf "${INSTALL_DIR}"
  warn "Data directory ${DATA_DIR} preserved. Remove manually if no longer needed:"
  warn "  sudo rm -rf ${DATA_DIR}"
  info "Uninstall complete."
  exit 0
fi

# ---------------------------------------------------------- install
info "Installing ITShield Antivirus..."

# 1. Create dedicated user (system user, no login).
if ! id "${USER_NAME}" &>/dev/null; then
  info "Creating system user '${USER_NAME}'..."
  useradd --system --no-create-home --shell /usr/sbin/nologin "${USER_NAME}"
fi

# 2. Create directories.
for d in "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}" "${RUN_DIR}"; do
  mkdir -p "${d}"
done

# 3. Copy project files.
info "Copying project files to ${INSTALL_DIR}..."
cp -r "${PROJECT_DIR}/itshield" "${INSTALL_DIR}/"
cp -r "${PROJECT_DIR}/signatures" "${INSTALL_DIR}/"
cp -r "${PROJECT_DIR}/rules" "${INSTALL_DIR}/"
cp "${PROJECT_DIR}/pyproject.toml" "${INSTALL_DIR}/"
cp "${PROJECT_DIR}/test_scanner.py" "${INSTALL_DIR}/"
cp "${PROJECT_DIR}/README.md" "${INSTALL_DIR}/"

# 4. Install Python dependencies.
info "Installing Python dependencies..."
if command -v pip3 &>/dev/null; then
  pip3 install --system protobuf yara-python PySide6 grpcio-tools inotify_simple || \
    pip3 install protobuf yara-python PySide6 grpcio-tools inotify_simple
else
  warn "pip3 not found. Please install dependencies manually:"
  warn "  pip3 install protobuf yara-python PySide6 grpcio-tools inotify_simple"
fi

# 5. Set ownership.
chown -R "${USER_NAME}:${USER_NAME}" "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}" "${RUN_DIR}"
chmod 700 "${DATA_DIR}"
chmod 755 "${RUN_DIR}"

# 6. Install systemd service.
info "Installing systemd service..."
cp "${PROJECT_DIR}/deploy/itshield.service" "${SERVICE_FILE}"
systemctl daemon-reload

# 7. Enable and start.
info "Enabling service to start on boot..."
systemctl enable ${SERVICE_NAME}

info "Starting service..."
systemctl start ${SERVICE_NAME}

sleep 2
if systemctl is-active --quiet ${SERVICE_NAME}; then
  info "ITShield service is running."
  info "  Status:  systemctl status ${SERVICE_NAME}"
  info "  Logs:    journalctl -u ${SERVICE_NAME} -f"
  info "  CLI:     cd ${INSTALL_DIR} && python3 -m itshield.cli status"
else
  error "Service failed to start. Check: journalctl -u ${SERVICE_NAME}"
fi

echo ""
info "Installation complete!"
echo ""
echo "Quick commands:"
echo "  sudo systemctl start ${SERVICE_NAME}     # start"
echo "  sudo systemctl stop ${SERVICE_NAME}      # stop"
echo "  sudo systemctl restart ${SERVICE_NAME}   # restart"
echo "  sudo systemctl status ${SERVICE_NAME}    # status"
echo "  journalctl -u ${SERVICE_NAME} -f          # follow logs"
echo ""
echo "To uninstall: sudo ${SCRIPT_DIR}/install.sh --uninstall"
