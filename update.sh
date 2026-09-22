#!/bin/bash
#===============================================================================
# FLYNE ENGINE - in-place updater
#
# Refreshes CODE ONLY from the install.sh / index.php sitting next to this file:
#   * every agent script   (/opt/flyne/scripts/*.sh, incl. lib.sh)
#   * helper binaries      (/opt/flyne/bin/*: flyne-agent, flyne-fpm-run, ...)
#   * the control-plane API (/opt/flyne/api/index.php)
#   * control-plane tables  (CREATE TABLE IF NOT EXISTS only - never drops/alters)
#
# It never touches sites, site files, databases, certificates, nginx vhosts,
# systemd units or /etc/flyne. The current code is backed up first and restored
# automatically if the new code fails its self-test.
#
# Usage:  sudo bash update.sh
#===============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[FLYNE-UPDATE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
die()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash update.sh"
[[ -f /etc/flyne/flyne.conf ]] || die "Flyne is not installed here - run install.sh instead"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${SRC_DIR}/install.sh"
API_SRC="${SRC_DIR}/index.php"
[[ -f "$INSTALLER" ]] || die "install.sh not found next to update.sh"
[[ -f "$API_SRC" ]]   || die "index.php not found next to update.sh"

# shellcheck disable=SC1091
source /etc/flyne/flyne.conf
API_PHP="${DEFAULT_PHP:-8.4}"
PHP_BIN="/usr/bin/php${API_PHP}"
[[ -x "$PHP_BIN" ]] || PHP_BIN=$(command -v php || true)

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/scripts" "$STAGE/bin"

#--- 1. extract every scripts/ and bin/ file from install.sh -------------------
# The installer writes them with QUOTED heredocs (<< 'SCRIPT', << 'EOF', ...), so
# the text between the markers is exactly the file content - no expansion.
log "Extracting code from install.sh..."
re='^cat > "\$\{FLYNE_DIR\}/(scripts|bin)/([A-Za-z0-9._-]+)" << '"'"'([A-Z_]+)'"'"'$'
current=""; term=""
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$current" ]]; then
        if [[ "$line" =~ $re ]]; then
            current="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
            term="${BASH_REMATCH[3]}"
            : > "${STAGE}/${current}"
        fi
    elif [[ "$line" == "$term" ]]; then
        current=""; term=""
    else
        printf '%s\n' "$line" >> "${STAGE}/${current}"
    fi
done < "$INSTALLER"
[[ -z "$current" ]] || die "install.sh is truncated: heredoc for ${current} never closes"

# control-plane schema (idempotent CREATE TABLE IF NOT EXISTS statements)
awk "/^mysql flyne_engine << 'SCHEMA'\$/{f=1;next} /^SCHEMA\$/{f=0} f" "$INSTALLER" > "${STAGE}/schema.sql"

#--- 2. validate before touching anything --------------------------------------
N_SCRIPTS=$(find "$STAGE/scripts" -type f | wc -l)
N_BIN=$(find "$STAGE/bin" -type f | wc -l)
log "Found ${N_SCRIPTS} agent scripts and ${N_BIN} helper binaries"
(( N_SCRIPTS >= 20 )) || die "Only ${N_SCRIPTS} scripts extracted - is this the right install.sh?"
for f in lib.sh create-site.sh delete-site.sh php-switch.sh wp-cli.sh; do
    [[ -s "$STAGE/scripts/$f" ]] || die "Required script missing from install.sh: $f"
done
[[ -s "$STAGE/bin/flyne-agent" ]] || die "flyne-agent missing from install.sh"

for f in "$STAGE"/scripts/* "$STAGE"/bin/*; do
    bash -n "$f" 2>/dev/null || die "Syntax error in $(basename "$f") - aborting, nothing changed"
done
if [[ -n "$PHP_BIN" ]]; then
    "$PHP_BIN" -l "$API_SRC" >/dev/null 2>&1 || die "PHP syntax error in index.php - aborting, nothing changed"
fi
grep -q "CREATE TABLE IF NOT EXISTS sites" "${STAGE}/schema.sql" || die "Could not extract the schema from install.sh"
if grep -Eiq '^\s*(DROP|ALTER|TRUNCATE|DELETE)\b' "${STAGE}/schema.sql"; then
    die "Schema block contains destructive statements - refusing to apply automatically"
fi
log "All files pass syntax checks"

#--- 3. back up the current code -----------------------------------------------
BACKUP="/var/lib/flyne/update-backups/$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"; chmod 700 /var/lib/flyne/update-backups "$BACKUP"
cp -a /opt/flyne/scripts "$BACKUP/scripts"
cp -a /opt/flyne/bin "$BACKUP/bin"
cp -a /opt/flyne/api/index.php "$BACKUP/index.php" 2>/dev/null || true
log "Current code backed up to ${BACKUP}"

restore() {
    warn "Restoring previous code from ${BACKUP}"
    rm -rf /opt/flyne/scripts /opt/flyne/bin
    cp -a "$BACKUP/scripts" /opt/flyne/scripts
    cp -a "$BACKUP/bin" /opt/flyne/bin
    [[ -f "$BACKUP/index.php" ]] && cp -a "$BACKUP/index.php" /opt/flyne/api/index.php
    systemctl reload flyne-api-fpm 2>/dev/null || true
}

#--- 4. install -----------------------------------------------------------------
log "Installing new code..."
install -o root -g root -m 750 "$STAGE"/scripts/*.sh /opt/flyne/scripts/
chmod 640 /opt/flyne/scripts/lib.sh
install -o root -g root -m 755 "$STAGE"/bin/* /opt/flyne/bin/
install -o root -g flyne-api -m 640 "$API_SRC" /opt/flyne/api/index.php

log "Applying control-plane schema (new tables only)..."
mysql flyne_engine < "${STAGE}/schema.sql" || { restore; die "Schema update failed - previous code restored"; }

systemctl daemon-reload
systemctl reload flyne-api-fpm || { restore; die "API failed to reload - previous code restored"; }

#--- 5. self-test through the real path the API uses ---------------------------
log "Self-test: API user -> sudo -> agent..."
OUT=$(sudo -u flyne-api sudo -n /opt/flyne/bin/flyne-agent system-check 2>&1 || true)
if ! grep -q '"success":true' <<< "$OUT"; then
    echo "$OUT" | tail -5
    restore
    die "Agent self-test failed - previous code restored"
fi

log "Update complete. Previous code kept in ${BACKUP}"
echo "  scripts: ${N_SCRIPTS}   helpers: ${N_BIN}   API: $(basename "$API_SRC")"
