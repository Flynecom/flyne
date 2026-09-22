#!/bin/bash
#===============================================================================
# FLYNE ENGINE v5.0 - Managed WordPress Hosting Platform (nginx-only)
#
# Ubuntu 22.04 / 24.04 | Multi-tenant, hard-isolated, Kinsta-class defaults
#
# Isolation model (one site == one tenant):
#   * dedicated Linux user + group per site, 0750 home, no shared group
#   * dedicated PHP-FPM master per site  (systemd flyne-php@<domain>)
#       -> own opcache, own cgroup: CPUQuota / MemoryMax / TasksMax
#       -> a broken pool or an exploited site can only take itself down
#   * dedicated Redis instance per site  (systemd flyne-redis@<domain>)
#       -> own socket (0600), own maxmemory, no shared password
#   * dedicated MariaDB user per site with MAX_USER_CONNECTIONS
#   * control-plane API runs as its own user (flyne-api) in its own FPM master
#     and can only call ONE root-owned dispatcher with a fixed action allowlist
#   * nginx FastCGI page cache per site, static asset caching, HTTP/2, TLS 1.2/1.3
#   * PHP switching = restart of that site's FPM service after a config test,
#     with automatic rollback. Nothing else on the server is touched.
#===============================================================================

set -uo pipefail
trap 'echo -e "\033[0;31m[ERROR]\033[0m Installer failed at line $LINENO (command: $BASH_COMMAND)"; exit 1' ERR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[FLYNE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error(){ echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    [[ "${ID:-}" != "ubuntu" ]] && error "Only Ubuntu 22.04 / 24.04 is supported"
    case "${VERSION_ID:-}" in 22.04|24.04) ;; *) warn "Untested Ubuntu release ${VERSION_ID:-?}; continuing" ;; esac
else
    error "Cannot detect OS"
fi

if [[ -f /etc/flyne/flyne.conf ]]; then
    warn "An existing Flyne installation was found at /etc/flyne."
    warn "This installer is not an upgrader. Aborting to protect existing sites."
    exit 1
fi

clear
echo -e "${BLUE}"
cat << "EOF"
   _____ _                   _____             _
  |  ___| |_   _ _ __   ___ | ____|_ __   __ _(_)_ __   ___
  | |_  | | | | | '_ \ / _ \|  _| | '_ \ / _` | | '_ \ / _ \
  |  _| | | |_| | | | |  __/| |___| | | | (_| | | | | |  __/
  |_|   |_|\__, |_| |_|\___||_____|_| |_|\__, |_|_| |_|\___|
           |___/                         |___/
  Managed WordPress Hosting Engine v5.0  (nginx / PHP-FPM / MariaDB / Redis)
EOF
echo -e "${NC}"

#===============================================================================
# CONFIGURATION PROMPTS
#===============================================================================
echo -e "${CYAN}=== Server Configuration ===${NC}"
read -rp "Control Panel API Domain (e.g. api.flyne.ge): " PANEL_DOMAIN
read -rp "phpMyAdmin Domain (optional, blank to skip): " PMA_DOMAIN
read -rp "Server Hostname (e.g. wp1.flyne.ge): " SERVER_HOSTNAME
read -rp "Admin Email (Let's Encrypt + alerts): " ADMIN_EMAIL
read -rp "API allowed IPs / CIDRs, comma separated (blank = any IP, key only): " API_ALLOWED_IPS
echo ""
echo -e "${CYAN}=== Outbound mail relay (optional, recommended for deliverability) ===${NC}"
read -rp "SMTP relay host (e.g. smtp.postmarkapp.com, blank = direct delivery): " RELAY_HOST
RELAY_USER=""; RELAY_PASS=""
if [[ -n "$RELAY_HOST" ]]; then
    read -rp "SMTP relay port [587]: " RELAY_PORT; RELAY_PORT="${RELAY_PORT:-587}"
    read -rp "SMTP relay username: " RELAY_USER
    read -rsp "SMTP relay password: " RELAY_PASS; echo ""
fi

# bounded read first so tr never gets SIGPIPE (this script runs with pipefail + ERR trap)
gen_secret() { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$1"; }
DEFAULT_API_SECRET=$(gen_secret 64)

echo ""
echo -e "${YELLOW}Generated API secret (press Enter to accept):${NC}"
read -rp "API Secret [$DEFAULT_API_SECRET]: " API_SECRET
API_SECRET="${API_SECRET:-$DEFAULT_API_SECRET}"

PANEL_DOMAIN="${PANEL_DOMAIN,,}"; PMA_DOMAIN="${PMA_DOMAIN,,}"; SERVER_HOSTNAME="${SERVER_HOSTNAME,,}"
[[ -z "$PANEL_DOMAIN" ]] && error "Panel domain required"
[[ -z "$SERVER_HOSTNAME" ]] && error "Hostname required"
[[ -z "$ADMIN_EMAIL" ]] && error "Admin email required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ chars"
[[ "$API_SECRET" =~ ^[A-Za-z0-9._-]+$ ]] || error "API secret may only contain A-Z a-z 0-9 . _ -"
[[ "$PANEL_DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || error "Invalid panel domain"
[[ -z "$PMA_DOMAIN" || "$PMA_DOMAIN" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || error "Invalid phpMyAdmin domain"
[[ "$ADMIN_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[a-z]{2,}$ ]] || error "Invalid admin email"

DB_API_PASS=$(gen_secret 40)
PMA_ENABLED=0; [[ -n "$PMA_DOMAIN" ]] && PMA_ENABLED=1

TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
SERVER_IP=$(curl -s4 --max-time 8 https://api.ipify.org 2>/dev/null || true)
[[ "$SERVER_IP" =~ ^[0-9.]+$ ]] || SERVER_IP=$(hostname -I | awk '{print $1}')
[[ "$SERVER_IP" =~ ^[0-9.]+$ ]] || error "Could not determine server IPv4 address"

log "Detected: ${TOTAL_RAM}MB RAM, ${CPU_CORES} CPUs, IP ${SERVER_IP}, Ubuntu ${VERSION_ID}"

FLYNE_DIR="/opt/flyne"
FLYNE_ETC="/etc/flyne"
SITES_DIR="/var/www/sites"
ACME_DIR="/var/www/acme"
BACKUP_DIR="/var/lib/flyne/backups"
LOG_DIR="/var/log/flyne"
PHP_VERSIONS="7.4 8.0 8.1 8.2 8.3 8.4"
API_PHP="8.4"

log "Starting installation..."

#===============================================================================
# 1. SYSTEM PACKAGES
#===============================================================================
log "Updating system..."
export DEBIAN_FRONTEND=noninteractive
hostnamectl set-hostname "$SERVER_HOSTNAME"
grep -q "$SERVER_HOSTNAME" /etc/hosts || echo "$SERVER_IP $SERVER_HOSTNAME" >> /etc/hosts
echo "$SERVER_HOSTNAME" > /etc/mailname

apt-get update -q
apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade

log "Installing core packages..."
apt-get install -y --no-install-recommends \
    software-properties-common ca-certificates curl wget gnupg unzip zip tar gzip pigz \
    jq bc pwgen htop ncdu rsync lsof net-tools dnsutils openssl \
    certbot fail2ban ufw logrotate cron \
    unattended-upgrades apt-listchanges needrestart \
    quota python3 \
    ssl-cert

# Debconf answers so postfix does not prompt (send-only relay, no inbound mail)
debconf-set-selections <<< "postfix postfix/mailname string ${SERVER_HOSTNAME}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt-get install -y --no-install-recommends postfix libsasl2-modules

#--- PHP (all versions, FPM + CLI) ---
log "Installing PHP versions..."
add-apt-repository -y ppa:ondrej/php
apt-get update -q

PHP_EXTS="fpm cli mysql curl gd mbstring xml zip bcmath intl soap redis imagick opcache readline exif"
for V in $PHP_VERSIONS; do
    log "  PHP ${V}..."
    PKGS=""
    for E in $PHP_EXTS; do PKGS="$PKGS php${V}-${E}"; done
    # shellcheck disable=SC2086
    if ! apt-get install -y --no-install-recommends $PKGS >/dev/null 2>&1; then
        warn "  PHP ${V}: bulk install failed, installing packages individually"
        for P in $PKGS; do
            apt-get install -y --no-install-recommends "$P" >/dev/null 2>&1 || warn "    unavailable: $P"
        done
    fi
    [[ -x "/usr/sbin/php-fpm${V}" ]] || warn "  PHP ${V} FPM binary missing - this version will be unavailable"
done
[[ -x "/usr/sbin/php-fpm${API_PHP}" ]] || error "PHP ${API_PHP} is required for the control plane"

# Stock per-version FPM services are NOT used: every site (and the API) gets its
# own FPM master via flyne-php@.service. Disable the shared ones so nothing
# collides on sockets or restarts them by accident.
for V in $PHP_VERSIONS; do
    systemctl disable --now "php${V}-fpm" >/dev/null 2>&1 || true
    systemctl mask "php${V}-fpm" >/dev/null 2>&1 || true
done

#--- Nginx ---
log "Installing Nginx..."
apt-get install -y --no-install-recommends nginx
NGX_PURGE=0
if apt-get install -y --no-install-recommends libnginx-mod-http-cache-purge >/dev/null 2>&1; then
    NGX_PURGE=1; log "  nginx cache purge module installed"
else
    warn "  nginx cache purge module unavailable (purge via filesystem only)"
fi
NGX_BROTLI=0
if apt-get install -y --no-install-recommends libnginx-mod-brotli >/dev/null 2>&1 || \
   apt-get install -y --no-install-recommends libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static >/dev/null 2>&1; then
    NGX_BROTLI=1; log "  nginx brotli module installed"
fi
systemctl stop nginx >/dev/null 2>&1 || true

#--- MariaDB ---
log "Installing MariaDB..."
apt-get install -y --no-install-recommends mariadb-server mariadb-client

#--- Redis (binary only; the shared instance is disabled, sites get their own) ---
log "Installing Redis..."
apt-get install -y --no-install-recommends redis-server redis-tools
systemctl disable --now redis-server >/dev/null 2>&1 || true

#--- WP-CLI ---
log "Installing WP-CLI..."
curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod 755 /usr/local/bin/wp
"/usr/bin/php${API_PHP}" /usr/local/bin/wp --info >/dev/null 2>&1 || error "WP-CLI download is broken"

#--- phpMyAdmin (optional) ---
if [[ $PMA_ENABLED -eq 1 ]]; then
    log "Installing phpMyAdmin..."
    PMA_OK=0
    for PMA_VERSION in 5.2.2 5.2.1; do
        if wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.zip" -O /tmp/pma.zip; then
            PMA_OK=1; break
        fi
    done
    if [[ $PMA_OK -eq 1 ]]; then
        rm -rf /usr/share/phpmyadmin /tmp/pma-extract
        mkdir -p /tmp/pma-extract
        unzip -qo /tmp/pma.zip -d /tmp/pma-extract
        mv "/tmp/pma-extract/phpMyAdmin-${PMA_VERSION}-all-languages" /usr/share/phpmyadmin
        rm -rf /tmp/pma.zip /tmp/pma-extract /usr/share/phpmyadmin/setup
    else
        warn "phpMyAdmin download failed - skipping"
        PMA_ENABLED=0
    fi
fi

#===============================================================================
# 2. SYSTEM USERS & GROUPS
#===============================================================================
log "Creating system users and groups..."
groupadd -f flyne-sites          # every site user is a member (for auditing only, grants nothing)
groupadd -f sftpusers            # membership == SFTP enabled (sshd Match block)

# Control-plane API user: owns nothing but its log, talks to root only via the dispatcher
if ! id flyne-api &>/dev/null; then
    useradd -r -M -d "${FLYNE_DIR}/api" -s /usr/sbin/nologin -c "Flyne API" flyne-api
fi
# phpMyAdmin runs as its own user so a PMA exploit gains nothing else
if ! id flyne-pma &>/dev/null; then
    useradd -r -M -d /usr/share/phpmyadmin -s /usr/sbin/nologin -c "Flyne phpMyAdmin" flyne-pma
fi

#===============================================================================
# 3. DIRECTORY STRUCTURE
#===============================================================================
log "Creating directory structure..."
mkdir -p "${FLYNE_DIR}"/{api,bin,scripts,templates}
mkdir -p "${FLYNE_ETC}"/{sites,api,ssl}
mkdir -p "${SITES_DIR}" "${ACME_DIR}/.well-known/acme-challenge" "${BACKUP_DIR}" "${LOG_DIR}"
mkdir -p /var/cache/nginx/fastcgi
mkdir -p /etc/nginx/{flyne-sites,flyne-cache,snippets}
mkdir -p /var/lib/flyne/pma-tmp /var/lib/mysql-files

chown root:root "${FLYNE_DIR}" "${FLYNE_DIR}"/{bin,scripts,templates}
chmod 755 "${FLYNE_DIR}" "${FLYNE_DIR}"/{bin,templates}
chmod 750 "${FLYNE_DIR}/scripts"
chown root:flyne-api "${FLYNE_DIR}/api"; chmod 750 "${FLYNE_DIR}/api"

chown root:root "${FLYNE_ETC}"; chmod 711 "${FLYNE_ETC}"
chown root:root "${FLYNE_ETC}/sites"; chmod 711 "${FLYNE_ETC}/sites"
chown root:flyne-api "${FLYNE_ETC}/api"; chmod 750 "${FLYNE_ETC}/api"
chmod 700 "${FLYNE_ETC}/ssl"

# /var/www/sites is traverse-only: a site user cannot list other tenants
chown root:root "${SITES_DIR}"; chmod 711 "${SITES_DIR}"
chown -R www-data:www-data "${ACME_DIR}"; chmod 755 "${ACME_DIR}"
chown root:root "${BACKUP_DIR}"; chmod 700 "${BACKUP_DIR}"
chown root:adm "${LOG_DIR}"; chmod 750 "${LOG_DIR}"
touch "${LOG_DIR}"/{agent.log,api.log,auth.log,cron.log}
chown root:adm "${LOG_DIR}"/agent.log "${LOG_DIR}"/cron.log; chmod 640 "${LOG_DIR}"/agent.log "${LOG_DIR}"/cron.log
chown flyne-api:adm "${LOG_DIR}"/api.log "${LOG_DIR}"/auth.log; chmod 640 "${LOG_DIR}"/api.log "${LOG_DIR}"/auth.log
chown www-data:www-data /var/cache/nginx/fastcgi; chmod 700 /var/cache/nginx/fastcgi
chown flyne-pma:flyne-pma /var/lib/flyne/pma-tmp; chmod 700 /var/lib/flyne/pma-tmp
chown mysql:mysql /var/lib/mysql-files; chmod 700 /var/lib/mysql-files

#===============================================================================
# 4. MARIADB (tuned + hardened)
#===============================================================================
log "Configuring MariaDB..."

if   [[ $TOTAL_RAM -gt 32768 ]]; then IB="12G"; IL="2G";   MC=500
elif [[ $TOTAL_RAM -gt 16384 ]]; then IB="6G";  IL="1G";   MC=400
elif [[ $TOTAL_RAM -gt 8192  ]]; then IB="3G";  IL="512M"; MC=300
elif [[ $TOTAL_RAM -gt 4096  ]]; then IB="1536M"; IL="256M"; MC=200
elif [[ $TOTAL_RAM -gt 2048  ]]; then IB="768M"; IL="128M"; MC=150
else IB="384M"; IL="64M"; MC=100; fi

cat > /etc/mysql/mariadb.conf.d/99-flyne.cnf << EOF
[mysqld]
# --- network / security ---
bind-address            = 127.0.0.1
skip-name-resolve
local-infile            = 0
secure_file_priv        = /var/lib/mysql-files
symbolic-links          = 0
max_connect_errors      = 100000
max_allowed_packet      = 256M

# --- InnoDB ---
innodb_buffer_pool_size         = ${IB}
innodb_log_file_size            = ${IL}
innodb_flush_log_at_trx_commit  = 1
innodb_flush_method             = O_DIRECT
innodb_file_per_table           = 1
innodb_io_capacity              = 2000
innodb_io_capacity_max          = 4000
innodb_read_io_threads          = 8
innodb_write_io_threads         = 8
innodb_lru_scan_depth           = 1024

# --- connections / caches ---
max_connections         = ${MC}
thread_cache_size       = 64
table_open_cache        = 4000
table_definition_cache  = 2000
open_files_limit        = 65535
tmp_table_size          = 64M
max_heap_table_size     = 64M
join_buffer_size        = 2M
sort_buffer_size        = 2M
read_rnd_buffer_size    = 1M
wait_timeout            = 300
interactive_timeout     = 300
query_cache_type        = 0
query_cache_size        = 0

# --- logging ---
skip-log-bin
slow_query_log          = 1
slow_query_log_file     = /var/log/mysql/mariadb-slow.log
long_query_time         = 2
log_warnings            = 2

# --- charset ---
character-set-server    = utf8mb4
collation-server        = utf8mb4_unicode_ci
performance_schema      = OFF
EOF

mkdir -p /var/log/mysql; chown mysql:adm /var/log/mysql
systemctl enable mariadb >/dev/null 2>&1 || true
systemctl restart mariadb || error "MariaDB failed to start"

# root stays on unix_socket auth (only OS root can use it - no password to leak).
# The API gets a least-privilege user scoped to the control-plane database only.
mysql << SQLEOF
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
DELETE FROM mysql.global_priv WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
CREATE DATABASE IF NOT EXISTS flyne_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS 'flyne_api'@'localhost';
CREATE USER 'flyne_api'@'localhost' IDENTIFIED BY '${DB_API_PASS}' WITH MAX_USER_CONNECTIONS 20;
GRANT SELECT, INSERT, UPDATE, DELETE ON flyne_engine.* TO 'flyne_api'@'localhost';
FLUSH PRIVILEGES;
SQLEOF
log "MariaDB configured"

#===============================================================================
# 5. CONTROL-PLANE SCHEMA
#===============================================================================
log "Creating control plane schema..."
mysql flyne_engine << 'SCHEMA'
CREATE TABLE IF NOT EXISTS sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(253) NOT NULL UNIQUE,
    site_user VARCHAR(32) NOT NULL UNIQUE,
    site_hash CHAR(12) NOT NULL UNIQUE,
    php_version VARCHAR(5) NOT NULL DEFAULT '8.4',
    status ENUM('creating','active','suspended','error','deleting') NOT NULL DEFAULT 'creating',
    ssl_enabled TINYINT(1) NOT NULL DEFAULT 0,
    db_name VARCHAR(64) NULL,
    db_user VARCHAR(64) NULL,
    db_pass VARCHAR(255) NULL,
    redis_db INT NOT NULL DEFAULT 0,
    wp_admin_user VARCHAR(64) NULL,
    wp_admin_email VARCHAR(255) NULL,
    plan VARCHAR(32) NOT NULL DEFAULT 'standard',
    cpu_quota INT NOT NULL DEFAULT 200,
    memory_max_mb INT NOT NULL DEFAULT 1024,
    php_max_children INT NOT NULL DEFAULT 5,
    php_memory_limit_mb INT NOT NULL DEFAULT 256,
    redis_max_mb INT NOT NULL DEFAULT 64,
    disk_quota_mb INT NOT NULL DEFAULT 10240,
    disk_used_mb INT NOT NULL DEFAULT 0,
    db_used_mb INT NOT NULL DEFAULT 0,
    db_max_connections INT NOT NULL DEFAULT 30,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sftp_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL UNIQUE,
    sftp_user VARCHAR(32) NOT NULL,
    is_enabled TINYINT(1) NOT NULL DEFAULT 1,
    expires_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_site (site_id),
    INDEX idx_created (created_at),
    INDEX idx_action (action)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    type ENUM('full','files','database') NOT NULL DEFAULT 'full',
    status ENUM('running','completed','failed') NOT NULL DEFAULT 'running',
    file_path VARCHAR(500) NULL,
    file_size BIGINT NOT NULL DEFAULT 0,
    note VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,
    INDEX idx_site (site_id),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB;
SCHEMA
log "Schema created"

#===============================================================================
# 6. PHP BASE CONFIGURATION (per version; the per-site pool overrides the rest)
#===============================================================================
log "Configuring PHP base settings..."
for V in $PHP_VERSIONS; do
    [[ -d "/etc/php/${V}/fpm" ]] || continue
    cat > "/etc/php/${V}/fpm/conf.d/99-flyne.ini" << 'PHPINI'
; Flyne hardening + performance baseline (site pools override limits)
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
html_errors = Off
allow_url_fopen = On
allow_url_include = Off
enable_dl = Off
cgi.fix_pathinfo = 0
file_uploads = On
max_input_vars = 5000
max_input_time = 300
default_socket_timeout = 30
date.timezone = UTC
realpath_cache_size = 4096k
realpath_cache_ttl = 600
output_buffering = 4096
zend.enable_gc = On
mail.add_x_header = Off
session.use_strict_mode = 1
session.cookie_httponly = 1
session.use_only_cookies = 1
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
PHPINI

    cat > "/etc/php/${V}/fpm/conf.d/10-opcache.ini" << 'OPCACHE'
[opcache]
opcache.enable = 1
opcache.enable_cli = 0
opcache.memory_consumption = 128
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 30000
opcache.validate_timestamps = 1
opcache.revalidate_freq = 60
opcache.save_comments = 1
opcache.fast_shutdown = 1
opcache.huge_code_pages = 0
opcache.max_wasted_percentage = 10
opcache.jit = off
opcache.jit_buffer_size = 0
OPCACHE

    [[ -d "/etc/php/${V}/cli" ]] && cat > "/etc/php/${V}/cli/conf.d/99-flyne.ini" << 'CLIINI'
; WP-CLI runs as the site user; keep it quiet and predictable
display_errors = stderr
log_errors = Off
date.timezone = UTC
opcache.enable_cli = 0
CLIINI
done

#===============================================================================
# 7. SYSTEMD UNITS  (one PHP-FPM master + one Redis per site, cgroup limited)
#===============================================================================
log "Installing systemd unit templates..."

# --- PHP-FPM per site --------------------------------------------------------
# Instance name is the (systemd-escaped) domain. %I gives the raw domain back.
# Resource limits below are DEFAULTS; render-site writes a per-site drop-in.
cat > /etc/systemd/system/flyne-php@.service << 'UNIT'
[Unit]
Description=Flyne PHP-FPM for site %I
After=network.target flyne-redis@%i.service
Wants=flyne-redis@%i.service
ConditionPathExists=/etc/flyne/sites/%I/site.env

[Service]
Type=notify
NotifyAccess=main
ExecStart=/opt/flyne/bin/flyne-fpm-run %I
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
RestartSec=2s
KillMode=mixed
TimeoutStopSec=30
UMask=0027
LimitNOFILE=65535
RuntimeDirectory=flyne-php/%I
RuntimeDirectoryMode=0755
OOMPolicy=continue

# --- resource isolation (per-site drop-in overrides these) ---
CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
IOAccounting=yes
CPUQuota=200%
MemoryHigh=920M
MemoryMax=1024M
TasksMax=256

# --- sandboxing (master is root, workers drop to the site user) ---
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_FOWNER CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_RESOURCE
# NoNewPrivileges is intentionally NOT set: PHP mail() relies on the setgid postdrop helper.

[Install]
WantedBy=multi-user.target
UNIT

# --- Redis per site -----------------------------------------------------------
# User=/Group=/MemoryMax= are set by the per-site drop-in.
cat > /etc/systemd/system/flyne-redis@.service << 'UNIT'
[Unit]
Description=Flyne Redis for site %I
After=network.target
ConditionPathExists=/etc/flyne/sites/%I/redis.conf

[Service]
Type=notify
ExecStart=/usr/bin/redis-server /etc/flyne/sites/%I/redis.conf
Restart=always
RestartSec=2s
TimeoutStopSec=20
User=nobody
Group=nogroup
UMask=0077
LimitNOFILE=10240
RuntimeDirectory=flyne-redis/%I
RuntimeDirectoryMode=0750
OOMScoreAdjust=200

CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
CPUQuota=50%
MemoryMax=112M
TasksMax=32

PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
UNIT

# --- Control-plane API FPM (own master, own user) ---------------------------
cat > /etc/systemd/system/flyne-api-fpm.service << UNIT
[Unit]
Description=Flyne Control Plane API (PHP-FPM ${API_PHP})
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=notify
ExecStart=/usr/sbin/php-fpm${API_PHP} --nodaemonize --fpm-config /etc/flyne/api/php-fpm.conf
ExecReload=/bin/kill -USR2 \$MAINPID
Restart=always
RestartSec=2s
KillMode=mixed
UMask=0027
LimitNOFILE=16384
RuntimeDirectory=flyne-api
RuntimeDirectoryMode=0755
MemoryAccounting=yes
MemoryMax=512M
TasksMax=64
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_FOWNER CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT

if [[ $PMA_ENABLED -eq 1 ]]; then
cat > /etc/systemd/system/flyne-pma-fpm.service << UNIT
[Unit]
Description=Flyne phpMyAdmin (PHP-FPM ${API_PHP})
After=network.target mariadb.service

[Service]
Type=notify
ExecStart=/usr/sbin/php-fpm${API_PHP} --nodaemonize --fpm-config /etc/flyne/pma-php-fpm.conf
ExecReload=/bin/kill -USR2 \$MAINPID
Restart=always
RestartSec=2s
KillMode=mixed
UMask=0027
RuntimeDirectory=flyne-pma
RuntimeDirectoryMode=0755
MemoryAccounting=yes
MemoryMax=384M
TasksMax=48
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_CHOWN CAP_FOWNER CAP_KILL CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
UNIT
fi

# Redis prefers THP disabled; do it once at boot.
cat > /etc/systemd/system/flyne-thp.service << 'UNIT'
[Unit]
Description=Flyne: disable transparent hugepages (Redis latency)
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled || true'
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/defrag || true'

[Install]
WantedBy=basic.target
UNIT
systemctl daemon-reload
systemctl enable --now flyne-thp.service >/dev/null 2>&1 || true

#===============================================================================
# 8. HELPER BINARIES (/opt/flyne/bin, root-owned)
#===============================================================================
log "Installing helper binaries..."

# Runs a site's PHP-FPM master with the PHP version recorded in site.env.
# systemd cannot put a variable in the executable path, hence this wrapper.
cat > "${FLYNE_DIR}/bin/flyne-fpm-run" << 'EOF'
#!/bin/bash
set -euo pipefail
DOMAIN="${1:?domain required}"
ENV_FILE="/etc/flyne/sites/${DOMAIN}/site.env"
[[ -f "$ENV_FILE" ]] || { echo "site.env missing for ${DOMAIN}" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ "${PHP_VERSION:-}" =~ ^[0-9]\.[0-9]$ ]] || { echo "invalid PHP_VERSION in site.env" >&2; exit 1; }
BIN="/usr/sbin/php-fpm${PHP_VERSION}"
[[ -x "$BIN" ]] || { echo "PHP ${PHP_VERSION} is not installed" >&2; exit 1; }
OPC="${PHP_OPCACHE_MB:-128}"; [[ "$OPC" =~ ^[0-9]{2,4}$ ]] || OPC=128
exec "$BIN" --nodaemonize --fpm-config "/etc/flyne/sites/${DOMAIN}/php-fpm.conf" \
    -d "opcache.memory_consumption=${OPC}"
EOF
chmod 755 "${FLYNE_DIR}/bin/flyne-fpm-run"

# WordPress cron runner, executed by cron AS THE SITE USER (see render-site).
cat > "${FLYNE_DIR}/bin/flyne-wp-cron" << 'EOF'
#!/bin/bash
set -uo pipefail
DOMAIN="${1:?domain required}"
[[ "$DOMAIN" =~ ^[a-z0-9.-]+$ ]] || exit 1
ENV_FILE="/etc/flyne/sites/${DOMAIN}/site.env"
[[ -r "$ENV_FILE" ]] || exit 0
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ "${SUSPENDED:-0}" == "1" ]] && exit 0
SITE_DIR="/var/www/sites/${DOMAIN}"
DOC_ROOT="${SITE_DIR}/public"
[[ -f "${DOC_ROOT}/wp-config.php" ]] || exit 0
exec 9>"${SITE_DIR}/tmp/.wpcron.lock"
flock -n 9 || exit 0
export HOME="$SITE_DIR" TMPDIR="${SITE_DIR}/tmp"
export WP_CLI_CACHE_DIR="${SITE_DIR}/tmp/wp-cli-cache" WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1
timeout 280 "/usr/bin/php${PHP_VERSION}" -d memory_limit=256M /usr/local/bin/wp \
    --path="$DOC_ROOT" --quiet --no-color cron event run --due-now >> "${SITE_DIR}/logs/wp-cron.log" 2>&1 || true
EOF
chmod 755 "${FLYNE_DIR}/bin/flyne-wp-cron"

# THE ONLY THING THE API MAY RUN AS ROOT.
# Fixed allowlist of actions -> root-owned scripts. Arguments are validated
# again inside every script (domain regex, version allowlist, etc.).
cat > "${FLYNE_DIR}/bin/flyne-agent" << 'EOF'
#!/bin/bash
set -euo pipefail
umask 027
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C.UTF-8 LANG=C.UTF-8

deny() { printf '{"success":false,"error":"%s"}\n' "$1"; exit 1; }

[[ $EUID -eq 0 ]] || deny "agent must run as root"
ACTION="${1:-}"; shift || true

case "$ACTION" in
    create-site|delete-site|render-site|php-switch|php-restart|sftp-enable|sftp-disable|\
    cache-purge|wp-cli|ssl-issue|ssl-status|backup-create|backup-list|backup-restore|\
    backup-delete|site-suspend|site-unsuspend|site-limits|site-inspect|system-check) ;;
    *) deny "Unknown agent action" ;;
esac

SCRIPT="/opt/flyne/scripts/${ACTION}.sh"
[[ -f "$SCRIPT" ]] || deny "Action script missing"
# refuse to run anything that is not root-owned and non-writable by others
MODE=$(stat -c '%a' "$SCRIPT"); OWNER=$(stat -c '%U' "$SCRIPT")
[[ "$OWNER" == "root" ]] || deny "Action script has wrong owner"
(( (8#$MODE & 8#022) == 0 )) || deny "Action script is group/world writable"

# hard cap on argument count / size so a bug upstream cannot turn into a DoS
[[ $# -le 64 ]] || deny "Too many arguments"
for a in "$@"; do [[ ${#a} -le 8192 ]] || deny "Argument too long"; done

exec /bin/bash "$SCRIPT" "$@"
EOF
chmod 755 "${FLYNE_DIR}/bin/flyne-agent"
chown root:root "${FLYNE_DIR}"/bin/*

#===============================================================================
# 9. NGINX (performance + security baseline, WordPress page cache plumbing)
#===============================================================================
log "Configuring Nginx..."

cat > /etc/nginx/nginx.conf << 'NGINXCONF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 100000;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 8192;
    multi_accept on;
    use epoll;
}

http {
    # --- core / transport ---
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30s;
    keepalive_requests 1000;
    reset_timedout_connection on;
    client_body_timeout 20s;
    client_header_timeout 20s;
    send_timeout 30s;
    client_max_body_size 64m;
    client_body_buffer_size 128k;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 16k;
    types_hash_max_size 4096;
    server_names_hash_bucket_size 128;
    server_names_hash_max_size 8192;
    server_tokens off;
    etag on;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    open_file_cache max=50000 inactive=60s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # --- logging ---
    log_format flyne '$remote_addr - $remote_user [$time_local] "$request" '
                     '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                     'rt=$request_time urt=$upstream_response_time cache=$upstream_cache_status';
    access_log /var/log/nginx/access.log flyne buffer=32k flush=5s;
    error_log /var/log/nginx/error.log warn;

    # --- compression ---
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/x-javascript
               application/json application/ld+json application/xml application/rss+xml application/atom+xml
               image/svg+xml font/ttf font/otf application/vnd.ms-fontobject application/wasm;
    include /etc/nginx/conf.d/*.conf;

    # --- TLS ---
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_session_timeout 1d;
    ssl_session_cache shared:FLYNE_SSL:50m;
    ssl_session_tickets off;

    # --- FastCGI page cache (zones are per site, see /etc/nginx/flyne-cache) ---
    # no $scheme: port 80 only redirects once TLS exists, and purge requests may arrive over http
    fastcgi_cache_key "$request_method$host$request_uri";
    fastcgi_cache_lock on;
    fastcgi_cache_lock_timeout 5s;
    fastcgi_cache_use_stale error timeout updating invalid_header http_500 http_502 http_503 http_504;
    fastcgi_cache_background_update on;
    fastcgi_cache_methods GET HEAD;
    fastcgi_ignore_headers Cache-Control Expires;
    fastcgi_hide_header X-Powered-By;
    include /etc/nginx/flyne-cache/*.conf;

    # Requests that must never be served from the page cache
    map $request_method $flyne_skip_method { default 1; GET 0; HEAD 0; }
    map $request_uri $flyne_skip_uri {
        default 0;
        ~*^/wp-admin/                                  1;
        ~*^/wp-login\.php                               1;
        ~*^/xmlrpc\.php                                 1;
        ~*^/wp-json/                                    1;
        ~*^/wp-cron\.php                                1;
        ~*^/wp-comments-post\.php                       1;
        ~*^/(?:cart|checkout|my-account|addons|wc-api|edd-api)(?:/|\?|$) 1;
        ~*/feed/?(?:\?|$)                               1;
    }
    map $args $flyne_skip_args {
        default 0;
        ~*(?:^|&)(?:s|p|page_id|preview|preview_id|customize_changeset_uuid|customize_theme|add-to-cart|wc-api|nonce|_wpnonce|nocache|nocache_reload)= 1;
    }
    map $http_cookie $flyne_skip_cookie {
        default 0;
        ~*wordpress_logged_in_        1;
        ~*wordpress_sec_              1;
        ~*wp-postpass_                1;
        ~*wordpress_no_cache          1;
        ~*comment_author_             1;
        ~*woocommerce_items_in_cart   1;
        ~*woocommerce_cart_hash       1;
        ~*wp_woocommerce_session_     1;
        ~*edd_items_in_cart           1;
    }
    map "$flyne_skip_method$flyne_skip_uri$flyne_skip_args$flyne_skip_cookie" $flyne_skip_cache {
        default 1;
        "0000"  0;
    }

    # --- abuse limits (per client IP, shared zones) ---
    limit_req_zone  $binary_remote_addr zone=flyne_login:16m  rate=10r/m;
    limit_req_zone  $binary_remote_addr zone=flyne_xmlrpc:16m rate=30r/m;
    limit_req_zone  $binary_remote_addr zone=flyne_php:32m    rate=20r/s;
    limit_req_zone  $binary_remote_addr zone=flyne_api:16m    rate=30r/s;
    limit_conn_zone $binary_remote_addr zone=flyne_conn:16m;
    limit_req_status 429;
    limit_conn_status 429;
    limit_req_log_level warn;

    include /etc/nginx/snippets/flyne-cloudflare.conf;
    include /etc/nginx/flyne-sites/*.conf;
}
NGINXCONF

if [[ $NGX_BROTLI -eq 1 ]]; then
cat > /etc/nginx/conf.d/flyne-brotli.conf << 'BR'
brotli on;
brotli_comp_level 5;
brotli_min_length 1024;
brotli_static on;
brotli_types text/plain text/css text/xml text/javascript application/javascript application/json
             application/ld+json application/xml application/rss+xml application/atom+xml image/svg+xml
             font/ttf font/otf application/vnd.ms-fontobject application/wasm;
BR
fi

# --- snippets -----------------------------------------------------------------
cat > /etc/nginx/snippets/flyne-acme.conf << 'SNIP'
location ^~ /.well-known/acme-challenge/ {
    root /var/www/acme;
    default_type "text/plain";
    allow all;
    access_log off;
}
SNIP

# Security headers live at server level ONLY (nginx add_header is not inherited
# into locations that declare their own add_header, so locations never do).
cat > /etc/nginx/snippets/flyne-headers.conf << 'SNIP'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Flyne-Cache $upstream_cache_status always;
SNIP

cat > /etc/nginx/snippets/flyne-hsts.conf << 'SNIP'
add_header Strict-Transport-Security "max-age=31536000" always;
SNIP

cat > /etc/nginx/snippets/flyne-php.conf << 'SNIP'
include fastcgi_params;
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
fastcgi_param HTTP_PROXY "";
fastcgi_index index.php;
fastcgi_intercept_errors off;
fastcgi_connect_timeout 10s;
fastcgi_send_timeout 300s;
fastcgi_read_timeout 300s;
fastcgi_buffer_size 64k;
fastcgi_buffers 32 32k;
fastcgi_busy_buffers_size 128k;
fastcgi_temp_file_write_size 256k;
SNIP

cat > /etc/nginx/snippets/flyne-wp-hardening.conf << 'SNIP'
# dotfiles (except ACME), backups, dumps, configs
location ~ /\.(?!well-known/) { deny all; }
location ~* \.(?:bak|conf|cfg|dist|ini|log|orig|psd|sh|sql|sw[op]|env|lock|md5|sha1)$ { deny all; }
# never execute PHP from writable / static locations
location ~* ^/wp-content/(?:uploads|files|cache|upgrade|backups?)/.*\.(?:php|phtml|phar|php[0-9])$ { deny all; }
location ~* ^/wp-includes/(?!js/tinymce/wp-tinymce\.php$|ms-files\.php$).*\.php$ { deny all; }
location ~* ^/(?:wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt|wp-content/debug\.log)$ { deny all; }
location ~* ^/wp-admin/(?:install|setup-config)\.php$ { deny all; }
SNIP

cat > /etc/nginx/snippets/flyne-static.conf << 'SNIP'
location ~* \.(?:css|js|mjs|map)$                          { expires 1y; access_log off; try_files $uri =404; }
location ~* \.(?:jpe?g|gif|png|webp|avif|ico|svg|bmp)$     { expires 1y; access_log off; try_files $uri =404; }
location ~* \.(?:woff2?|ttf|otf|eot)$                      { expires 1y; access_log off; try_files $uri =404; }
location ~* \.(?:mp4|webm|ogg|mp3|m4a|pdf|zip|gz|tgz)$     { expires 30d; access_log off; try_files $uri =404; }
location = /favicon.ico { access_log off; log_not_found off; expires 1y; }
location = /robots.txt  { access_log off; log_not_found off; try_files $uri /index.php?$args; }
SNIP

cat > /etc/nginx/snippets/flyne-cloudflare.conf << 'SNIP'
# Trust CF-Connecting-IP only from Cloudflare's published ranges.
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;
real_ip_header CF-Connecting-IP;
SNIP

# --- default catch-all: unknown hosts get nothing (and never another site's cert) ---
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
    -subj "/CN=${SERVER_HOSTNAME}" \
    -keyout "${FLYNE_ETC}/ssl/default.key" -out "${FLYNE_ETC}/ssl/default.crt" >/dev/null 2>&1
chmod 600 "${FLYNE_ETC}/ssl/default.key"

cat > /etc/nginx/flyne-sites/000-default.conf << 'DEFAULTCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    include snippets/flyne-acme.conf;
    location / { return 444; }
}
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    ssl_certificate     /etc/flyne/ssl/default.crt;
    ssl_certificate_key /etc/flyne/ssl/default.key;
    return 444;
}
DEFAULTCONF

rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx base config test failed"
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx || error "Nginx failed to start"

#===============================================================================
# 10. CONTROL-PLANE API (own FPM master, own user, secrets in a root-owned file)
#===============================================================================
log "Configuring control plane API..."

cat > "${FLYNE_ETC}/api/php-fpm.conf" << 'APIFPM'
[global]
pid = /run/flyne-api/php-fpm.pid
error_log = /var/log/flyne/api-fpm.log
log_level = notice
daemonize = no
systemd_interval = 10
emergency_restart_threshold = 5
emergency_restart_interval = 1m
process_control_timeout = 10s

[api]
user = flyne-api
group = flyne-api
listen = /run/flyne-api/php.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 12
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
pm.max_requests = 500
request_terminate_timeout = 900s
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
security.limit_extensions = .php
chdir = /opt/flyne/api
env[PATH] = /usr/local/bin:/usr/bin:/bin
php_admin_value[open_basedir] = /opt/flyne/api/:/etc/flyne/api/:/var/log/flyne/:/run/flyne-php/:/run/mysqld/:/proc/meminfo:/proc/loadavg:/proc/uptime:/proc/cpuinfo:/tmp/
php_admin_value[disable_functions] = exec,system,passthru,shell_exec,popen,pcntl_exec,pcntl_fork,dl,putenv,ini_alter
php_admin_value[error_log] = /var/log/flyne/api.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_flag[expose_php] = off
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 900
php_admin_value[post_max_size] = 8M
php_admin_value[upload_max_filesize] = 2M
php_admin_value[opcache.memory_consumption] = 64
APIFPM
chmod 600 "${FLYNE_ETC}/api/php-fpm.conf"

INSTALLED_PHP=""
for V in $PHP_VERSIONS; do [[ -x "/usr/sbin/php-fpm${V}" ]] && INSTALLED_PHP="${INSTALLED_PHP}'${V}',"; done

ALLOWED_IPS_PHP=""
IFS=',' read -ra _IPS <<< "${API_ALLOWED_IPS// /}"
for ip in "${_IPS[@]}"; do
    [[ -z "$ip" ]] && continue
    [[ "$ip" =~ ^[0-9a-fA-F.:/]+$ ]] || error "Invalid API allowed IP/CIDR: $ip"
    ALLOWED_IPS_PHP="${ALLOWED_IPS_PHP}'${ip}',"
done

cat > "${FLYNE_ETC}/api/config.php" << CONFIGPHP
<?php
// Flyne Engine control plane configuration. root:flyne-api 0640 - never web-served.
return [
    'api_secret'   => '${API_SECRET}',
    'db_dsn'       => 'mysql:host=localhost;dbname=flyne_engine;charset=utf8mb4',
    'db_user'      => 'flyne_api',
    'db_pass'      => '${DB_API_PASS}',
    'require_tls'  => false,
    'allowed_ips'  => [${ALLOWED_IPS_PHP}],
    'server_ip'    => '${SERVER_IP}',
    'hostname'     => '${SERVER_HOSTNAME}',
    'panel_domain' => '${PANEL_DOMAIN}',
    'pma_domain'   => '${PMA_DOMAIN}',
    'php_versions' => [${INSTALLED_PHP}],
    'default_php'  => '${API_PHP}',
];
CONFIGPHP
chown root:flyne-api "${FLYNE_ETC}/api/config.php"; chmod 640 "${FLYNE_ETC}/api/config.php"

# The API source (index.php) ships next to this installer.
INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${INSTALLER_DIR}/index.php" ]]; then
    cp "${INSTALLER_DIR}/index.php" "${FLYNE_DIR}/api/index.php"
else
    warn "index.php not found next to install.sh - copy it to ${FLYNE_DIR}/api/index.php afterwards"
fi
chown -R root:flyne-api "${FLYNE_DIR}/api"; chmod 750 "${FLYNE_DIR}/api"; chmod 640 "${FLYNE_DIR}/api/"*.php 2>/dev/null || true
touch "${LOG_DIR}/api-fpm.log"; chmod 640 "${LOG_DIR}/api-fpm.log"

systemctl daemon-reload
systemctl enable --now flyne-api-fpm.service || error "API PHP-FPM failed to start"

#===============================================================================
# 11. PHPMYADMIN (optional; own user, own FPM master)
#===============================================================================
if [[ $PMA_ENABLED -eq 1 ]]; then
    log "Configuring phpMyAdmin..."
    PMA_BLOWFISH=$(gen_secret 48)
    cat > /usr/share/phpmyadmin/config.inc.php << PMAEOF
<?php
\$cfg['blowfish_secret'] = '${PMA_BLOWFISH}';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['auth_type'] = 'cookie';
\$cfg['Servers'][1]['compress'] = false;
\$cfg['Servers'][1]['AllowNoPassword'] = false;
\$cfg['Servers'][1]['AllowRoot'] = false;
\$cfg['Servers'][1]['hide_db'] = '^(mysql|information_schema|performance_schema|sys|flyne_engine)\$';
\$cfg['TempDir'] = '/var/lib/flyne/pma-tmp';
\$cfg['LoginCookieValidity'] = 1800;
\$cfg['LoginCookieStore'] = 0;
\$cfg['AuthLog'] = 'syslog';
\$cfg['ShowPhpInfo'] = false;
\$cfg['ShowServerInfo'] = false;
\$cfg['VersionCheck'] = false;
\$cfg['AllowArbitraryServer'] = false;
\$cfg['ForceSSL'] = true;
\$cfg['CaptchaLoginPublicKey'] = '';
PMAEOF
    # static assets must be readable by nginx; only the config stays private to the PMA user
    chown -R root:root /usr/share/phpmyadmin
    find /usr/share/phpmyadmin -type d -exec chmod 755 {} +
    find /usr/share/phpmyadmin -type f -exec chmod 644 {} +
    chown root:flyne-pma /usr/share/phpmyadmin/config.inc.php
    chmod 640 /usr/share/phpmyadmin/config.inc.php

    cat > "${FLYNE_ETC}/pma-php-fpm.conf" << 'PMAFPM'
[global]
pid = /run/flyne-pma/php-fpm.pid
error_log = /var/log/flyne/pma-fpm.log
daemonize = no
systemd_interval = 10
emergency_restart_threshold = 5
emergency_restart_interval = 1m

[pma]
user = flyne-pma
group = flyne-pma
listen = /run/flyne-pma/php.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 20s
pm.max_requests = 500
request_terminate_timeout = 120s
catch_workers_output = yes
clear_env = yes
security.limit_extensions = .php
php_admin_value[open_basedir] = /usr/share/phpmyadmin/:/var/lib/flyne/pma-tmp/:/tmp/
php_admin_value[disable_functions] = exec,system,passthru,shell_exec,popen,proc_open,pcntl_exec,pcntl_fork,dl,putenv
php_admin_value[upload_tmp_dir] = /var/lib/flyne/pma-tmp
php_admin_value[session.save_path] = /var/lib/flyne/pma-tmp
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_secure] = 1
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 120
php_admin_value[upload_max_filesize] = 64M
php_admin_value[post_max_size] = 64M
php_admin_flag[expose_php] = off
php_admin_flag[display_errors] = off
PMAFPM
    chmod 600 "${FLYNE_ETC}/pma-php-fpm.conf"
    touch "${LOG_DIR}/pma-fpm.log"; chmod 640 "${LOG_DIR}/pma-fpm.log"
    systemctl daemon-reload
    systemctl enable --now flyne-pma-fpm.service || warn "phpMyAdmin PHP-FPM failed to start"
fi

#===============================================================================
# 12. TEMPLATES + GLOBAL CONFIG
#===============================================================================
log "Writing templates and global configuration..."

cat > "${FLYNE_DIR}/templates/suspended.html" << 'HTML'
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site Suspended</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.c{text-align:center;padding:2rem;max-width:32rem}h1{font-size:1.75rem;margin:0 0 .5rem}p{color:#94a3b8;line-height:1.5}</style></head>
<body><div class="c"><h1>This site is temporarily unavailable</h1><p>The hosting account for this website has been suspended. If you are the site owner, please contact your hosting provider.</p></div></body></html>
HTML

cat > "${FLYNE_ETC}/flyne.conf" << CONFEOF
# Flyne Engine global configuration (root only). Sourced by agent scripts.
FLYNE_VERSION="5.0"
INSTALLED_AT="$(date -u +%FT%TZ)"
PANEL_DOMAIN="${PANEL_DOMAIN}"
PMA_DOMAIN="${PMA_DOMAIN}"
PMA_ENABLED="${PMA_ENABLED}"
SERVER_HOSTNAME="${SERVER_HOSTNAME}"
SERVER_IP="${SERVER_IP}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
API_SECRET="${API_SECRET}"
DB_API_PASS="${DB_API_PASS}"
DEFAULT_PHP="${API_PHP}"
NGX_PURGE="${NGX_PURGE}"
NGX_BROTLI="${NGX_BROTLI}"
TOTAL_RAM="${TOTAL_RAM}"
CPU_CORES="${CPU_CORES}"

# --- operator tunables ---
BACKUP_RETENTION_DAYS="14"
BACKUP_REMOTE=""            # optional rclone remote, e.g. "s3:flyne-backups/wp1" (rclone must be installed)
QUOTA_ENFORCE="notify"      # notify | suspend   (what happens when a site exceeds disk_quota_mb)
DEFAULT_PLAN_CPU="200"      # CPUQuota % (200 = two cores)
DEFAULT_PLAN_MEM_MB="1024"
DEFAULT_PLAN_CHILDREN="5"
DEFAULT_PLAN_PHP_MEM_MB="256"
DEFAULT_PLAN_REDIS_MB="64"
DEFAULT_PLAN_DISK_MB="10240"
DEFAULT_PLAN_DB_CONN="30"
CONFEOF
chmod 600 "${FLYNE_ETC}/flyne.conf"

#===============================================================================
# 13. AGENT SCRIPT LIBRARY (/opt/flyne/scripts/lib.sh)
#===============================================================================
log "Installing agent scripts..."

cat > "${FLYNE_DIR}/scripts/lib.sh" << 'LIBEOF'
#!/bin/bash
# Flyne Engine - shared library sourced by every agent script.
# Scripts always run as root (via /opt/flyne/bin/flyne-agent, cron or the CLI).
# Contract: exactly one JSON line on the caller's stdout; everything else -> agent.log
set -euo pipefail
umask 027
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C.UTF-8 LANG=C.UTF-8 DEBIAN_FRONTEND=noninteractive

FLYNE_DIR=/opt/flyne
FLYNE_ETC=/etc/flyne
SITES_DIR=/var/www/sites
SITES_ETC=${FLYNE_ETC}/sites
BACKUP_DIR=/var/lib/flyne/backups
ACME_DIR=/var/www/acme
NGX_SITES=/etc/nginx/flyne-sites
NGX_CACHE_ZONES=/etc/nginx/flyne-cache
NGX_CACHE_DIR=/var/cache/nginx/fastcgi
LOG_DIR=/var/log/flyne
AGENT_LOG=${LOG_DIR}/agent.log
CP_DB=flyne_engine
PHP_VERSIONS_ALLOWED="7.4 8.0 8.1 8.2 8.3 8.4"
SCRIPT_NAME="$(basename "${BASH_SOURCE[1]:-$0}" .sh)"

[[ $EUID -eq 0 ]] || { echo '{"success":false,"error":"must run as root"}'; exit 1; }
# shellcheck disable=SC1091
source "${FLYNE_ETC}/flyne.conf"

# fd 3 = the caller's stdout (JSON result only). fd 1/2 -> agent log.
exec 3>&1
exec 1>>"$AGENT_LOG" 2>&1
JSON_EMITTED=0

log()      { printf '[%s] [%s] %s\n' "$(date '+%F %T')" "$SCRIPT_NAME" "$*"; }
json_out() { printf '%s\n' "$1" >&3; JSON_EMITTED=1; }

fail() {   # fail <message> [exit-code]
    trap - ERR
    log "FAIL: $1"
    json_out "$(jq -cn --arg e "$1" '{success:false,error:$e}')"
    exit "${2:-1}"
}
ok() {     # ok [json-object] [message]
    local data="${1:-}" msg="${2:-OK}"
    [[ -z "$data" ]] && data='{}'
    json_out "$(jq -cn --argjson d "$data" --arg m "$msg" '{success:true,message:$m,data:$d}')"
    exit 0
}
on_err() { fail "Internal error in ${SCRIPT_NAME} at line $1 (details in ${AGENT_LOG})"; }
# Whatever happens, the caller always receives exactly one JSON line.
on_exit() {
    local rc=$?
    if [[ $JSON_EMITTED -eq 0 ]]; then
        printf '{"success":false,"error":"%s exited unexpectedly (code %s), see %s"}\n' "$SCRIPT_NAME" "$rc" "$AGENT_LOG" >&3
    fi
}
set -E   # ERR trap must also fire inside functions
trap 'on_err $LINENO' ERR
trap on_exit EXIT

#--- validation ----------------------------------------------------------------
valid_domain() {
    local d="$1"
    [[ ${#d} -ge 4 && ${#d} -le 253 ]] || return 1
    [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$ ]] || return 1
    return 0
}
require_domain() {
    DOMAIN="${1:-}"; DOMAIN="${DOMAIN,,}"
    valid_domain "$DOMAIN" || fail "Invalid domain name"
}
valid_php_format() { [[ "$1" =~ ^[0-9]\.[0-9]$ ]] && [[ " $PHP_VERSIONS_ALLOWED " == *" $1 "* ]]; }
php_installed()    { [[ -x "/usr/sbin/php-fpm$1" && -x "/usr/bin/php$1" ]]; }
is_int()           { [[ "$1" =~ ^[0-9]{1,9}$ ]]; }
rand_alnum()       { head -c 4096 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$1"; }

#--- database (control plane, as MariaDB root via unix_socket) -----------------
sql_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"; }
db()      { mysql --batch --raw --skip-column-names --default-character-set=utf8mb4 "$CP_DB" -e "$1"; }
site_id() { db "SELECT id FROM sites WHERE domain='$(sql_esc "$DOMAIN")'"; }
log_activity() {   # log_activity <action> <details-json> [site_id]
    local sid="${3:-}"; [[ -z "$sid" ]] && sid="NULL"
    db "INSERT INTO activity_logs (site_id, action, details, ip_address) VALUES (${sid}, '$(sql_esc "$1")', '$(sql_esc "$2")', 'agent')" || true
}

#--- site identity / paths -----------------------------------------------------
site_hash() { printf '%s' "$1" | sha1sum | cut -c1-12; }
site_paths() {
    SITE_HASH=$(site_hash "$DOMAIN")
    SITE_ETC="${SITES_ETC}/${DOMAIN}"
    SITE_ENV="${SITE_ETC}/site.env"
    SITE_DIR="${SITES_DIR}/${DOMAIN}"
    DOC_ROOT="${SITE_DIR}/public"
    LOGS_DIR="${SITE_DIR}/logs"
    TMP_DIR="${SITE_DIR}/tmp"
    UNIT_INST=$(systemd-escape "$DOMAIN")
    PHP_UNIT="flyne-php@${UNIT_INST}.service"
    REDIS_UNIT="flyne-redis@${UNIT_INST}.service"
    PHP_SOCK="/run/flyne-php/${DOMAIN}/php.sock"
    REDIS_SOCK="/run/flyne-redis/${DOMAIN}/redis.sock"
    CACHE_ZONE="flyne_${SITE_HASH}"
    CACHE_PATH="${NGX_CACHE_DIR}/${DOMAIN}"
    CRON_FILE="/etc/cron.d/flyne-site-${SITE_HASH}"
    NGX_CONF="${NGX_SITES}/${DOMAIN}.conf"
    NGX_ZONE_CONF="${NGX_CACHE_ZONES}/${DOMAIN}.conf"
    SITE_BACKUP_DIR="${BACKUP_DIR}/${DOMAIN}"
}

# load_site <domain>: validates the name, loads site.env, verifies every value.
load_site() {
    require_domain "$1"
    site_paths
    [[ -f "$SITE_ENV" ]] || fail "Site not found: ${DOMAIN}"
    # defaults for keys introduced after a site was created
    PHP_PM=ondemand; PHP_OPCACHE_MB=128; PHP_UPLOAD_MB=128; PHP_MAX_EXECUTION=300; PHP_ALLOW_EXEC=0
    XMLRPC=off; CACHE_ENABLED=1; CACHE_TTL=3600; SSL=0; SUSPENDED=0
    # shellcheck disable=SC1090
    source "$SITE_ENV"
    [[ "${SITE_USER:-}" =~ ^site_[a-f0-9]{10}$ ]] || fail "Corrupt site.env (SITE_USER) for ${DOMAIN}"
    valid_php_format "${PHP_VERSION:-}" || fail "Corrupt site.env (PHP_VERSION) for ${DOMAIN}"
    local v
    for v in PHP_MAX_CHILDREN PHP_MEMORY_LIMIT_MB PHP_OPCACHE_MB PHP_UPLOAD_MB PHP_MAX_EXECUTION \
             CPU_QUOTA MEMORY_MAX_MB REDIS_MAX_MB DISK_QUOTA_MB DB_MAX_CONN CACHE_TTL; do
        is_int "${!v:-x}" || fail "Corrupt site.env (${v}) for ${DOMAIN}"
    done
    [[ "$PHP_PM" =~ ^(ondemand|dynamic|static)$ ]] || fail "Corrupt site.env (PHP_PM)"
    [[ "$PHP_ALLOW_EXEC" =~ ^[01]$ && "$CACHE_ENABLED" =~ ^[01]$ && "$SSL" =~ ^[01]$ && "$SUSPENDED" =~ ^[01]$ ]] || fail "Corrupt site.env (flags)"
    [[ "$XMLRPC" =~ ^(on|off)$ ]] || fail "Corrupt site.env (XMLRPC)"
    id "$SITE_USER" >/dev/null 2>&1 || fail "System user ${SITE_USER} for ${DOMAIN} is missing"
}

write_site_env() {
    mkdir -p "$SITE_ETC"
    chown root:"$SITE_USER" "$SITE_ETC"; chmod 750 "$SITE_ETC"
    cat > "${SITE_ENV}.tmp" << EOF
# Flyne site runtime configuration - managed by Flyne. Edit through the API / CLI only.
DOMAIN=${DOMAIN}
SITE_USER=${SITE_USER}
SITE_HASH=${SITE_HASH}
PHP_VERSION=${PHP_VERSION}
PHP_PM=${PHP_PM}
PHP_MAX_CHILDREN=${PHP_MAX_CHILDREN}
PHP_MEMORY_LIMIT_MB=${PHP_MEMORY_LIMIT_MB}
PHP_OPCACHE_MB=${PHP_OPCACHE_MB}
PHP_UPLOAD_MB=${PHP_UPLOAD_MB}
PHP_MAX_EXECUTION=${PHP_MAX_EXECUTION}
PHP_ALLOW_EXEC=${PHP_ALLOW_EXEC}
CPU_QUOTA=${CPU_QUOTA}
MEMORY_MAX_MB=${MEMORY_MAX_MB}
REDIS_MAX_MB=${REDIS_MAX_MB}
DISK_QUOTA_MB=${DISK_QUOTA_MB}
DB_MAX_CONN=${DB_MAX_CONN}
XMLRPC=${XMLRPC}
CACHE_ENABLED=${CACHE_ENABLED}
CACHE_TTL=${CACHE_TTL}
SSL=${SSL}
SUSPENDED=${SUSPENDED}
EOF
    chown root:"$SITE_USER" "${SITE_ENV}.tmp"; chmod 640 "${SITE_ENV}.tmp"
    mv -f "${SITE_ENV}.tmp" "$SITE_ENV"
}

#--- renderers -----------------------------------------------------------------
render_fpm_conf() {
    local disable="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork,pcntl_alarm,pcntl_signal,dl,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_seteuid,posix_setegid,socket_create_listen,socket_listen,ini_alter"
    [[ "$PHP_ALLOW_EXEC" == "1" ]] && disable="pcntl_exec,pcntl_fork,dl,posix_setuid,posix_setgid,posix_seteuid,posix_setegid,ini_alter"
    local pm_block
    case "$PHP_PM" in
        ondemand) pm_block="pm = ondemand
pm.process_idle_timeout = 30s" ;;
        dynamic)
            local start=$(( PHP_MAX_CHILDREN / 4 )); (( start < 1 )) && start=1
            local minsp=$start
            local maxsp=$(( PHP_MAX_CHILDREN / 2 )); (( maxsp < minsp )) && maxsp=$minsp
            pm_block="pm = dynamic
pm.start_servers = ${start}
pm.min_spare_servers = ${minsp}
pm.max_spare_servers = ${maxsp}" ;;
        static)   pm_block="pm = static" ;;
    esac
    cat > "${SITE_ETC}/php-fpm.conf" << EOF
; Flyne per-site PHP-FPM master - managed by render-site, do not edit.
[global]
pid = /run/flyne-php/${DOMAIN}/php-fpm.pid
error_log = ${LOGS_DIR}/php-fpm.log
log_level = notice
daemonize = no
systemd_interval = 10
emergency_restart_threshold = 10
emergency_restart_interval = 1m
process_control_timeout = 10s
rlimit_files = 65535
rlimit_core = 0

[site]
user = ${SITE_USER}
group = ${SITE_USER}
listen = ${PHP_SOCK}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
listen.backlog = 1024
${pm_block}
pm.max_children = ${PHP_MAX_CHILDREN}
pm.max_requests = 500
pm.status_path = /flyne-fpm-status
ping.path = /flyne-fpm-ping
request_terminate_timeout = ${PHP_MAX_EXECUTION}s
request_slowlog_timeout = 10s
slowlog = ${LOGS_DIR}/php-slow.log
catch_workers_output = yes
decorate_workers_output = no
clear_env = yes
security.limit_extensions = .php
chdir = ${DOC_ROOT}
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMPDIR] = ${TMP_DIR}
env[TMP] = ${TMP_DIR}
env[TEMP] = ${TMP_DIR}
php_admin_value[open_basedir] = ${SITE_DIR}/:/usr/share/php/:/dev/urandom:/proc/cpuinfo:/run/mysqld/:/run/flyne-redis/${DOMAIN}/
php_admin_value[upload_tmp_dir] = ${TMP_DIR}
php_admin_value[sys_temp_dir] = ${TMP_DIR}
php_admin_value[session.save_path] = ${TMP_DIR}/sessions
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on
php_admin_flag[display_errors] = off
php_admin_value[memory_limit] = ${PHP_MEMORY_LIMIT_MB}M
php_admin_value[upload_max_filesize] = ${PHP_UPLOAD_MB}M
php_admin_value[post_max_size] = ${PHP_UPLOAD_MB}M
php_admin_value[max_execution_time] = ${PHP_MAX_EXECUTION}
php_admin_value[max_input_time] = ${PHP_MAX_EXECUTION}
php_admin_value[disable_functions] = ${disable}
php_admin_flag[allow_url_include] = off
php_admin_flag[expose_php] = off
php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f wordpress@${DOMAIN}
EOF
    chown root:root "${SITE_ETC}/php-fpm.conf"; chmod 600 "${SITE_ETC}/php-fpm.conf"
}

render_redis_conf() {
    cat > "${SITE_ETC}/redis.conf" << EOF
# Flyne per-site Redis - managed by render-site, do not edit.
port 0
unixsocket ${REDIS_SOCK}
unixsocketperm 600
daemonize no
supervised systemd
pidfile ""
dir /run/flyne-redis/${DOMAIN}
logfile ""
loglevel notice
databases 1
save ""
appendonly no
maxmemory ${REDIS_MAX_MB}mb
maxmemory-policy allkeys-lru
maxclients 256
timeout 0
tcp-keepalive 300
protected-mode yes
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
hz 10
EOF
    chown root:"$SITE_USER" "${SITE_ETC}/redis.conf"; chmod 640 "${SITE_ETC}/redis.conf"
}

render_systemd() {
    local d high tasks
    high=$(( MEMORY_MAX_MB * 90 / 100 ))
    tasks=$(( PHP_MAX_CHILDREN * 4 + 32 ))
    d="/etc/systemd/system/${PHP_UNIT}.d"; mkdir -p "$d"
    cat > "${d}/flyne.conf" << EOF
# managed by Flyne render-site
[Service]
CPUQuota=${CPU_QUOTA}%
MemoryHigh=${high}M
MemoryMax=${MEMORY_MAX_MB}M
TasksMax=${tasks}
EOF
    d="/etc/systemd/system/${REDIS_UNIT}.d"; mkdir -p "$d"
    cat > "${d}/flyne.conf" << EOF
# managed by Flyne render-site
[Service]
User=${SITE_USER}
Group=${SITE_USER}
MemoryMax=$(( REDIS_MAX_MB + 48 ))M
EOF
    systemctl daemon-reload
}

render_cron() {
    if [[ "$SUSPENDED" == "1" ]]; then rm -f "$CRON_FILE"; return 0; fi
    cat > "$CRON_FILE" << EOF
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=""
*/5 * * * * ${SITE_USER} /opt/flyne/bin/flyne-wp-cron ${DOMAIN}
EOF
    chmod 644 "$CRON_FILE"
}

# Writes the nginx vhost. Rolls back and fails if the resulting config does not pass nginx -t,
# so a single site can never leave nginx in an unreloadable state.
render_nginx_apply() {
    local names="$DOMAIN"
    [[ "$DOMAIN" != www.* ]] && names="${DOMAIN} www.${DOMAIN}"
    local cert="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" key="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    local has_ssl=0; [[ "$SSL" == "1" && -s "$cert" && -s "$key" ]] && has_ssl=1
    local purge_block="" cache_block="" xmlrpc_block body

    if [[ "$CACHE_ENABLED" == "1" && "$SUSPENDED" != "1" ]]; then
        printf 'fastcgi_cache_path %s levels=1:2 keys_zone=%s:16m max_size=1g inactive=7d use_temp_path=off;\n' \
            "$CACHE_PATH" "$CACHE_ZONE" > "$NGX_ZONE_CONF"
        mkdir -p "$CACHE_PATH"; chown www-data:www-data "$CACHE_PATH"; chmod 700 "$CACHE_PATH"
        cache_block="        fastcgi_cache ${CACHE_ZONE};
        fastcgi_cache_valid 200 301 302 ${CACHE_TTL}s;
        fastcgi_cache_valid 404 60s;
        fastcgi_cache_bypass \$flyne_skip_cache;
        fastcgi_no_cache \$flyne_skip_cache;"
        if [[ "${NGX_PURGE:-0}" == "1" ]]; then
            purge_block="    location ~ ^/purge(/.*) {
        allow 127.0.0.1; allow ::1; allow ${SERVER_IP}; deny all;
        fastcgi_cache_purge ${CACHE_ZONE} \"\$request_method\$host\$1\";
    }"
        fi
    else
        rm -f "$NGX_ZONE_CONF"
    fi

    if [[ "$XMLRPC" == "on" ]]; then
        xmlrpc_block="        limit_req zone=flyne_xmlrpc burst=10 nodelay;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${PHP_SOCK};"
    else
        xmlrpc_block="        return 403;"
    fi

    if [[ "$SUSPENDED" == "1" ]]; then
        body="    root /opt/flyne/templates;
    access_log ${LOGS_DIR}/access.log flyne buffer=16k flush=5s;
    error_log ${LOGS_DIR}/error.log warn;
    include snippets/flyne-acme.conf;
    error_page 503 /suspended.html;
    location = /suspended.html { internal; }
    location / { return 503; }"
    else
        body="    root ${DOC_ROOT};
    index index.php index.html;
    access_log ${LOGS_DIR}/access.log flyne buffer=16k flush=5s;
    error_log ${LOGS_DIR}/error.log warn;
    client_max_body_size ${PHP_UPLOAD_MB}m;
    limit_conn flyne_conn 64;

    include snippets/flyne-acme.conf;
    include snippets/flyne-headers.conf;
    include snippets/flyne-wp-hardening.conf;
    include snippets/flyne-static.conf;

    location = /wp-login.php {
        limit_req zone=flyne_login burst=5 nodelay;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
    }
    location = /xmlrpc.php {
${xmlrpc_block}
    }
    location = /flyne-fpm-status {
        allow 127.0.0.1; allow ::1; deny all;
        access_log off;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
    }
    location = /flyne-fpm-ping {
        allow 127.0.0.1; allow ::1; deny all;
        access_log off;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
    }
${purge_block}
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \\.php\$ {
        try_files \$uri =404;
        limit_req zone=flyne_php burst=100 nodelay;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
${cache_block}
    }"
    fi

    local tmp="${NGX_CONF}.tmp" bak="${NGX_CONF}.rollback"
    {
        echo "# managed by Flyne render-site - DO NOT EDIT (regenerated automatically)"
        echo "server {"
        echo "    listen 80;"
        echo "    listen [::]:80;"
        echo "    server_name ${names};"
        if (( has_ssl )); then
            echo "    include snippets/flyne-acme.conf;"
            [[ -n "$purge_block" ]] && echo "$purge_block"
            echo "    location / { return 301 https://\$host\$request_uri; }"
        else
            echo "$body"
        fi
        echo "}"
        if (( has_ssl )); then
            echo "server {"
            echo "    listen 443 ssl http2;"
            echo "    listen [::]:443 ssl http2;"
            echo "    server_name ${names};"
            echo "    ssl_certificate ${cert};"
            echo "    ssl_certificate_key ${key};"
            echo "    include snippets/flyne-hsts.conf;"
            echo "$body"
            echo "}"
        fi
    } > "$tmp"

    [[ -f "$NGX_CONF" ]] && cp -f "$NGX_CONF" "$bak"
    mv -f "$tmp" "$NGX_CONF"
    if ! nginx -t; then
        log "nginx -t failed after rendering ${DOMAIN}; rolling back"
        if [[ -f "$bak" ]]; then mv -f "$bak" "$NGX_CONF"; else rm -f "$NGX_CONF"; fi
        nginx -t || log "nginx config STILL broken after rollback - manual attention required"
        return 1
    fi
    rm -f "$bak"
    systemctl reload nginx
}

render_all() { render_fpm_conf; render_redis_conf; render_systemd; render_cron; render_nginx_apply; }

#--- service control -----------------------------------------------------------
php_test_config()     { "/usr/sbin/php-fpm${PHP_VERSION}" -t --fpm-config "${SITE_ETC}/php-fpm.conf"; }
wait_for_socket()     { local i; for i in $(seq 1 75); do [[ -S "$1" ]] && return 0; sleep 0.2; done; return 1; }
php_service_restart() {
    systemctl restart "$PHP_UNIT" || return 1
    wait_for_socket "$PHP_SOCK" && systemctl is-active --quiet "$PHP_UNIT"
}
redis_service_restart() {
    systemctl restart "$REDIS_UNIT" || return 1
    wait_for_socket "$REDIS_SOCK"
}
unit_journal_tail()   { journalctl -u "$1" -n "${2:-15}" --no-pager 2>/dev/null | tail -n "${2:-15}" | tr '\n' ' ' | head -c 1500; }

#--- WP-CLI as the site user with the site's own PHP ---------------------------
wp_run() {
    runuser -u "$SITE_USER" -- env -i \
        HOME="$SITE_DIR" PATH=/usr/local/bin:/usr/bin:/bin TMPDIR="$TMP_DIR" LC_ALL=C.UTF-8 \
        WP_CLI_CACHE_DIR="${TMP_DIR}/wp-cli-cache" WP_CLI_PACKAGES_DIR="${TMP_DIR}/wp-cli-packages" \
        WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1 \
        timeout 900 "/usr/bin/php${PHP_VERSION}" -d memory_limit=512M -d max_execution_time=0 \
        /usr/local/bin/wp --path="$DOC_ROOT" --no-color "$@"
}

#--- misc ----------------------------------------------------------------------
dir_size_mb() { du -sm "$1" 2>/dev/null | cut -f1 || echo 0; }
db_size_mb()  { mysql -N -e "SELECT IFNULL(ROUND(SUM(data_length+index_length)/1048576),0) FROM information_schema.tables WHERE table_schema='$(sql_esc "$1")'" 2>/dev/null || echo 0; }
LIBEOF

#===============================================================================
# 14. SITE LIFECYCLE SCRIPTS
#===============================================================================

# ==================== CREATE SITE ====================
cat > "${FLYNE_DIR}/scripts/create-site.sh" << 'SCRIPT'
#!/bin/bash
# create-site.sh <domain> [php_version] [admin_email] [title] [admin_user] [plan]
source /opt/flyne/scripts/lib.sh
require_domain "${1:-}"
PHP_VERSION="${2:-$DEFAULT_PHP}"
ADMIN_MAIL="${3:-$ADMIN_EMAIL}"
TITLE="${4:-$DOMAIN}"
ADMIN_USER="${5:-admin}"
PLAN="${6:-standard}"

valid_php_format "$PHP_VERSION" || fail "Invalid PHP version. Allowed: ${PHP_VERSIONS_ALLOWED}"
php_installed "$PHP_VERSION"    || fail "PHP ${PHP_VERSION} is not installed on this server"
[[ "$ADMIN_MAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[a-zA-Z]{2,}$ ]] || fail "Invalid admin email"
[[ "$ADMIN_USER" =~ ^[a-zA-Z0-9._@-]{1,60}$ ]] || fail "Invalid admin username"
[[ ${#TITLE} -le 200 ]] || fail "Site title too long"
[[ "$PLAN" =~ ^[a-z0-9_-]{1,32}$ ]] || fail "Invalid plan name"
for reserved in "$PANEL_DOMAIN" "$PMA_DOMAIN" "$SERVER_HOSTNAME"; do
    [[ -n "$reserved" && "$DOMAIN" == "$reserved" ]] && fail "Domain is reserved by the platform"
done

site_paths
[[ -n "$(site_id)" ]] && fail "Site already exists"
[[ -e "$SITE_ENV" || -e "$SITE_DIR" ]] && fail "Site directory or config already exists on disk"
SITE_USER="site_${SITE_HASH:0:10}"
id "$SITE_USER" >/dev/null 2>&1 && fail "System user ${SITE_USER} already exists"

# plan defaults (adjustable later via site-limits)
PHP_PM=ondemand; PHP_MAX_CHILDREN=$DEFAULT_PLAN_CHILDREN; PHP_MEMORY_LIMIT_MB=$DEFAULT_PLAN_PHP_MEM_MB
PHP_OPCACHE_MB=128; PHP_UPLOAD_MB=128; PHP_MAX_EXECUTION=300; PHP_ALLOW_EXEC=0
CPU_QUOTA=$DEFAULT_PLAN_CPU; MEMORY_MAX_MB=$DEFAULT_PLAN_MEM_MB; REDIS_MAX_MB=$DEFAULT_PLAN_REDIS_MB
DISK_QUOTA_MB=$DEFAULT_PLAN_DISK_MB; DB_MAX_CONN=$DEFAULT_PLAN_DB_CONN
XMLRPC=off; CACHE_ENABLED=1; CACHE_TTL=3600; SSL=0; SUSPENDED=0

SAFE=$(printf '%s' "$DOMAIN" | tr '.-' '__' | cut -c1-40)
DB_NAME="wp_${SAFE}"
DB_USER="u_${SITE_HASH:0:10}"
DB_PASS=$(rand_alnum 32)
WP_ADMIN_PASS=$(rand_alnum 20)

log "=== creating ${DOMAIN} (php ${PHP_VERSION}, user ${SITE_USER}, db ${DB_NAME})"

cleanup_on_failure() {
    log "cleaning up partial site ${DOMAIN}"
    systemctl disable --now "$PHP_UNIT" "$REDIS_UNIT" >/dev/null 2>&1 || true
    rm -rf "/etc/systemd/system/${PHP_UNIT}.d" "/etc/systemd/system/${REDIS_UNIT}.d"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f "$NGX_CONF" "$NGX_ZONE_CONF" "$CRON_FILE"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    mysql -e "DROP DATABASE IF EXISTS \`${DB_NAME}\`; DROP USER IF EXISTS '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;" >/dev/null 2>&1 || true
    gpasswd -d www-data "$SITE_USER" >/dev/null 2>&1 || true
    pkill -9 -u "$SITE_USER" >/dev/null 2>&1 || true
    userdel "$SITE_USER" >/dev/null 2>&1 || true
    groupdel "$SITE_USER" >/dev/null 2>&1 || true
    rm -rf "$SITE_DIR" "$SITE_ETC" "$CACHE_PATH"
    db "DELETE FROM sites WHERE domain='$(sql_esc "$DOMAIN")'" >/dev/null 2>&1 || true
}
abort() { cleanup_on_failure; fail "$1"; }
trap 'cleanup_on_failure; on_err $LINENO' ERR

# 0. reserve the name in the control plane immediately (prevents double creation)
db "INSERT INTO sites (domain, site_user, site_hash, php_version, status, db_name, db_user, db_pass,
        wp_admin_user, wp_admin_email, plan, cpu_quota, memory_max_mb, php_max_children,
        php_memory_limit_mb, redis_max_mb, disk_quota_mb, db_max_connections)
    VALUES ('$(sql_esc "$DOMAIN")', '${SITE_USER}', '${SITE_HASH}', '${PHP_VERSION}', 'creating',
        '${DB_NAME}', '${DB_USER}', '$(sql_esc "$DB_PASS")', '$(sql_esc "$ADMIN_USER")',
        '$(sql_esc "$ADMIN_MAIL")', '${PLAN}', ${CPU_QUOTA}, ${MEMORY_MAX_MB}, ${PHP_MAX_CHILDREN},
        ${PHP_MEMORY_LIMIT_MB}, ${REDIS_MAX_MB}, ${DISK_QUOTA_MB}, ${DB_MAX_CONN})"
SID=$(site_id)

# 1. dedicated user + group; nginx (www-data) joins the site group for read access
groupadd "$SITE_USER"
useradd -M -d "$SITE_DIR" -s /usr/sbin/nologin -g "$SITE_USER" -G flyne-sites -c "Flyne site ${DOMAIN}" "$SITE_USER"
usermod -aG "$SITE_USER" www-data

# 2. directory layout (home is root-owned 0750 so it doubles as the SFTP chroot)
mkdir -p "$DOC_ROOT" "$LOGS_DIR" "${TMP_DIR}/sessions" "${TMP_DIR}/wp-cli-cache" "${TMP_DIR}/wp-cli-packages"
chown root:"$SITE_USER" "$SITE_DIR"; chmod 750 "$SITE_DIR"
chown -R "$SITE_USER:$SITE_USER" "$DOC_ROOT" "$TMP_DIR"
chmod 2750 "$DOC_ROOT"; chmod 2750 "$TMP_DIR"; chmod 700 "${TMP_DIR}/sessions" "${TMP_DIR}/wp-cli-cache" "${TMP_DIR}/wp-cli-packages"
chown root:"$SITE_USER" "$LOGS_DIR"; chmod 2750 "$LOGS_DIR"
touch "${LOGS_DIR}/access.log" "${LOGS_DIR}/error.log" "${LOGS_DIR}/php-fpm.log"
chown root:"$SITE_USER" "${LOGS_DIR}/access.log" "${LOGS_DIR}/error.log" "${LOGS_DIR}/php-fpm.log"
touch "${LOGS_DIR}/php-error.log" "${LOGS_DIR}/php-slow.log" "${LOGS_DIR}/wp-cron.log"
chown "$SITE_USER:$SITE_USER" "${LOGS_DIR}/php-error.log" "${LOGS_DIR}/php-slow.log" "${LOGS_DIR}/wp-cron.log"
chmod 640 "${LOGS_DIR}"/*.log

# 3. database + least-privilege user with a connection cap
mysql << SQL
CREATE DATABASE \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}' WITH MAX_USER_CONNECTIONS ${DB_MAX_CONN};
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# 4. runtime config, own PHP-FPM + Redis services, nginx vhost
write_site_env
render_fpm_conf; render_redis_conf; render_systemd; render_cron
php_test_config || abort "Generated PHP-FPM configuration failed validation"
systemctl enable "$REDIS_UNIT" "$PHP_UNIT" >/dev/null 2>&1
redis_service_restart || log "warning: redis did not start for ${DOMAIN}: $(unit_journal_tail "$REDIS_UNIT")"
php_service_restart   || abort "PHP-FPM failed to start: $(unit_journal_tail "$PHP_UNIT")"
render_nginx_apply    || abort "nginx rejected the generated vhost"

# 5. WordPress (all as the site user, with the site's own PHP)
wp_run core download --locale=en_US || abort "Failed to download WordPress (no network?)"

SALTS=$(for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
    printf "define('%s', '%s');\n" "$k" "$(rand_alnum 64)"; done)
cat > "${DOC_ROOT}/wp-config.php" << EOF
<?php
/** Flyne-managed WordPress configuration for ${DOMAIN} */
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_PASS}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

${SALTS}
\$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_ENVIRONMENT_TYPE', 'production');
define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', 'minor');
define('WP_MEMORY_LIMIT', '${PHP_MEMORY_LIMIT_MB}M');
define('WP_MAX_MEMORY_LIMIT', '${PHP_MEMORY_LIMIT_MB}M');
define('FS_METHOD', 'direct');
define('FS_CHMOD_DIR', 02750);
define('FS_CHMOD_FILE', 0640);
define('DISABLE_WP_CRON', true);
define('WP_POST_REVISIONS', 20);
define('EMPTY_TRASH_DAYS', 30);
define('IMAGE_EDIT_OVERWRITE', true);

/* Object cache: this site's own Redis instance (unix socket, no shared password) */
define('WP_CACHE', true);
define('WP_REDIS_SCHEME', 'unix');
define('WP_REDIS_PATH', '${REDIS_SOCK}');
define('WP_REDIS_DATABASE', 0);
define('WP_REDIS_PREFIX', '${SITE_HASH}:');
define('WP_REDIS_TIMEOUT', 1);
define('WP_REDIS_READ_TIMEOUT', 1);
define('WP_REDIS_DISABLE_BANNERS', true);

/* That's all, stop editing! Happy publishing. */
if (!defined('ABSPATH')) { define('ABSPATH', __DIR__ . '/'); }
require_once ABSPATH . 'wp-settings.php';
EOF
chown "$SITE_USER:$SITE_USER" "${DOC_ROOT}/wp-config.php"; chmod 600 "${DOC_ROOT}/wp-config.php"

printf '%s\n' "$WP_ADMIN_PASS" | wp_run core install --url="http://${DOMAIN}" --title="$TITLE" \
    --admin_user="$ADMIN_USER" --admin_email="$ADMIN_MAIL" --prompt=admin_password --skip-email \
    || abort "WordPress installation failed"

wp_run rewrite structure '/%postname%/' >/dev/null 2>&1 || true
wp_run plugin delete hello >/dev/null 2>&1 || true
if wp_run plugin install redis-cache --activate >/dev/null 2>&1; then
    wp_run redis enable >/dev/null 2>&1 || log "redis object cache drop-in could not be enabled"
else
    log "redis-cache plugin could not be installed (offline?) - object cache inactive"
fi
if [[ "${NGX_PURGE:-0}" == "1" ]]; then
    if wp_run plugin install nginx-helper --activate >/dev/null 2>&1; then
        wp_run option update rt_wp_nginx_helper_options \
          '{"enable_purge":"1","cache_method":"enable_fastcgi","purge_method":"get_request","purge_homepage_on_edit":"1","purge_homepage_on_del":"1","purge_archive_on_edit":"1","purge_archive_on_del":"1","purge_archive_on_new_comment":"0","purge_archive_on_deleted_comment":"0","purge_page_on_mod":"1","purge_page_on_new_comment":"1","purge_page_on_deleted_comment":"1","log_level":"NONE","log_filesize":"5","redis_hostname":"127.0.0.1","redis_port":"6379","redis_prefix":"nginx-cache:","purge_url":""}' \
          --format=json >/dev/null 2>&1 || true
    fi
fi

# 6. lock down permissions (dirs 2750, files 640, wp-config 600 - nothing world-readable)
chown -R "$SITE_USER:$SITE_USER" "$DOC_ROOT"
find "$DOC_ROOT" -type d -exec chmod 2750 {} +
find "$DOC_ROOT" -type f -exec chmod 640 {} +
chmod 600 "${DOC_ROOT}/wp-config.php"

# 7. activate
db "UPDATE sites SET status='active' WHERE id=${SID}"
log_activity site_created "{\"domain\":\"${DOMAIN}\",\"php\":\"${PHP_VERSION}\"}" "$SID"
systemctl reload fail2ban >/dev/null 2>&1 || true

# 8. TLS in the background (checks DNS first; re-run via ssl-issue any time)
systemd-run --quiet --no-block --collect --unit="flyne-ssl-${SITE_HASH}-$(date +%s)" \
    /opt/flyne/scripts/ssl-issue.sh "$DOMAIN" >/dev/null 2>&1 || log "could not schedule background TLS issuance"

trap - ERR
log "=== created ${DOMAIN}"
ok "$(jq -cn --arg d "$DOMAIN" --arg u "$ADMIN_USER" --arg p "$WP_ADMIN_PASS" --arg e "$ADMIN_MAIL" \
        --arg php "$PHP_VERSION" --arg su "$SITE_USER" --arg dbn "$DB_NAME" --arg dbu "$DB_USER" --arg dbp "$DB_PASS" \
    '{domain:$d, url:("http://"+$d), admin_url:("http://"+$d+"/wp-admin/"), admin_user:$u,
      admin_password:$p, admin_pass:$p, admin_email:$e, php_version:$php, site_user:$su,
      db_name:$dbn, db_user:$dbu, db_pass:$dbp, ssl:"pending"}')" "Site created successfully"
SCRIPT

# ==================== DELETE SITE ====================
cat > "${FLYNE_DIR}/scripts/delete-site.sh" << 'SCRIPT'
#!/bin/bash
# delete-site.sh <domain> [--keep-backups] [--final-backup]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
KEEP_BACKUPS=0; FINAL_BACKUP=0
for a in "${@:2}"; do
    case "$a" in
        --keep-backups) KEEP_BACKUPS=1 ;;
        --final-backup) FINAL_BACKUP=1 ;;
        *) fail "Unknown option: $a" ;;
    esac
done
SID=$(site_id)
log "=== deleting ${DOMAIN} (keep_backups=${KEEP_BACKUPS}, final_backup=${FINAL_BACKUP})"
[[ -n "$SID" ]] && db "UPDATE sites SET status='deleting' WHERE id=${SID}"

if [[ $FINAL_BACKUP -eq 1 ]]; then
    /bin/bash /opt/flyne/scripts/backup-create.sh "$DOMAIN" full final-before-delete >/dev/null 2>&1 || log "final backup FAILED"
    KEEP_BACKUPS=1
fi

# services + configs
systemctl disable --now "$PHP_UNIT" "$REDIS_UNIT" >/dev/null 2>&1 || true
rm -rf "/etc/systemd/system/${PHP_UNIT}.d" "/etc/systemd/system/${REDIS_UNIT}.d"
systemctl daemon-reload
systemctl reset-failed "$PHP_UNIT" "$REDIS_UNIT" >/dev/null 2>&1 || true
rm -f "$NGX_CONF" "$NGX_ZONE_CONF" "$CRON_FILE"
if nginx -t; then systemctl reload nginx; else log "nginx -t failed after removing ${DOMAIN} - check /etc/nginx/flyne-sites"; fi
rm -rf "$CACHE_PATH"
certbot delete --cert-name "$DOMAIN" --non-interactive >/dev/null 2>&1 || true

# database
if [[ -n "$SID" ]]; then
    DBN=$(db "SELECT IFNULL(db_name,'') FROM sites WHERE id=${SID}")
    DBU=$(db "SELECT IFNULL(db_user,'') FROM sites WHERE id=${SID}")
    [[ "$DBN" =~ ^wp_[a-z0-9_]+$ ]] && mysql -e "DROP DATABASE IF EXISTS \`${DBN}\`;"
    [[ "$DBU" =~ ^u_[a-f0-9]+$ ]]   && mysql -e "DROP USER IF EXISTS '${DBU}'@'localhost'; FLUSH PRIVILEGES;"
fi

# system user
gpasswd -d "$SITE_USER" sftpusers >/dev/null 2>&1 || true
gpasswd -d www-data "$SITE_USER" >/dev/null 2>&1 || true
pkill -TERM -u "$SITE_USER" >/dev/null 2>&1 || true; sleep 1
pkill -KILL -u "$SITE_USER" >/dev/null 2>&1 || true
userdel "$SITE_USER" >/dev/null 2>&1 || true
groupdel "$SITE_USER" >/dev/null 2>&1 || true

# files (path is re-derived from the validated domain, never from user input)
[[ "$SITE_DIR" == "${SITES_DIR}/${DOMAIN}" ]] && rm -rf "$SITE_DIR"
rm -rf "$SITE_ETC"
[[ $KEEP_BACKUPS -eq 0 ]] && rm -rf "$SITE_BACKUP_DIR"

[[ -n "$SID" ]] && db "DELETE FROM sites WHERE id=${SID}"
log_activity site_deleted "{\"domain\":\"${DOMAIN}\",\"backups_kept\":${KEEP_BACKUPS}}"
systemctl reload fail2ban >/dev/null 2>&1 || true
log "=== deleted ${DOMAIN}"
ok '{}' "Site and all associated data deleted"
SCRIPT

# ==================== RENDER SITE (idempotent regeneration of all configs) ====================
cat > "${FLYNE_DIR}/scripts/render-site.sh" << 'SCRIPT'
#!/bin/bash
# render-site.sh <domain> [--restart]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
RESTART=0; [[ "${2:-}" == "--restart" ]] && RESTART=1
render_fpm_conf; render_redis_conf; render_systemd; render_cron
php_test_config || fail "Generated PHP-FPM configuration failed validation"
if [[ "$SUSPENDED" == "1" ]]; then
    systemctl disable --now "$PHP_UNIT" "$REDIS_UNIT" >/dev/null 2>&1 || true
else
    systemctl enable "$REDIS_UNIT" "$PHP_UNIT" >/dev/null 2>&1
    if [[ $RESTART -eq 1 ]] || ! systemctl is-active --quiet "$PHP_UNIT"; then
        redis_service_restart || log "warning: redis restart failed: $(unit_journal_tail "$REDIS_UNIT")"
        php_service_restart   || fail "PHP-FPM failed to start: $(unit_journal_tail "$PHP_UNIT")"
    fi
fi
render_nginx_apply || fail "nginx rejected the generated vhost (rolled back)"
ok "$(jq -cn --arg d "$DOMAIN" --arg s "$SUSPENDED" '{domain:$d, suspended:($s=="1")}')" "Site configuration regenerated"
SCRIPT

# ==================== PHP SWITCH ====================
# Only THIS site's FPM service is touched. Config is tested before restart and
# rolled back automatically if the new version does not come up.
cat > "${FLYNE_DIR}/scripts/php-switch.sh" << 'SCRIPT'
#!/bin/bash
# php-switch.sh <domain> <version>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
NEW="${2:-}"
valid_php_format "$NEW" || fail "Invalid PHP version. Allowed: ${PHP_VERSIONS_ALLOWED}"
php_installed "$NEW"    || fail "PHP ${NEW} is not installed on this server"
[[ "$SUSPENDED" == "1" ]] && fail "Site is suspended"
OLD="$PHP_VERSION"
if [[ "$OLD" == "$NEW" ]]; then
    ok "$(jq -cn --arg v "$NEW" '{old_version:$v, new_version:$v}')" "Site already runs PHP ${NEW}"
fi
log "=== ${DOMAIN}: PHP ${OLD} -> ${NEW}"

rollback() {
    mv -f "${SITE_ENV}.prev" "$SITE_ENV" 2>/dev/null || true
    PHP_VERSION="$OLD"; render_fpm_conf
    php_service_restart || log "ROLLBACK FAILED for ${DOMAIN}: $(unit_journal_tail "$PHP_UNIT")"
}
cp -f "$SITE_ENV" "${SITE_ENV}.prev"
PHP_VERSION="$NEW"; write_site_env; render_fpm_conf

if ! php_test_config; then
    log "php-fpm${NEW} -t rejected the pool config; rolling back"
    rollback
    fail "PHP ${NEW} rejected the generated pool configuration; site remains on PHP ${OLD}"
fi
if ! php_service_restart; then
    ERR=$(unit_journal_tail "$PHP_UNIT")
    log "PHP ${NEW} failed to start (${ERR}); rolling back"
    rollback
    fail "PHP ${NEW} failed to start, site was rolled back to PHP ${OLD}: ${ERR}"
fi
rm -f "${SITE_ENV}.prev"
db "UPDATE sites SET php_version='${NEW}' WHERE domain='$(sql_esc "$DOMAIN")'"
[[ -d "$CACHE_PATH" ]] && find "$CACHE_PATH" -mindepth 1 -delete 2>/dev/null || true
log_activity php_switched "{\"domain\":\"${DOMAIN}\",\"old\":\"${OLD}\",\"new\":\"${NEW}\"}" "$(site_id)"
log "=== ${DOMAIN}: now on PHP ${NEW}"
ok "$(jq -cn --arg o "$OLD" --arg n "$NEW" '{old_version:$o, new_version:$n}')" "PHP switched from ${OLD} to ${NEW}"
SCRIPT

# ==================== PHP RESTART / OPCACHE RESET ====================
cat > "${FLYNE_DIR}/scripts/php-restart.sh" << 'SCRIPT'
#!/bin/bash
# php-restart.sh <domain> [--hard]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
[[ "$SUSPENDED" == "1" ]] && fail "Site is suspended"
if [[ "${2:-}" == "--hard" ]]; then
    php_service_restart || fail "PHP-FPM failed to restart: $(unit_journal_tail "$PHP_UNIT")"
    MODE="restart"
else
    systemctl reload "$PHP_UNIT" || fail "PHP-FPM reload failed: $(unit_journal_tail "$PHP_UNIT")"
    MODE="reload"
fi
ok "$(jq -cn --arg m "$MODE" '{mode:$m}')" "PHP-FPM ${MODE} completed (opcache cleared)"
SCRIPT

# ==================== SFTP ENABLE / RESET PASSWORD ====================
cat > "${FLYNE_DIR}/scripts/sftp-enable.sh" << 'SCRIPT'
#!/bin/bash
# sftp-enable.sh <domain> [never|<N>h|<N>d]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
EXPIRE="${2:-never}"
[[ "$SUSPENDED" == "1" ]] && fail "Site is suspended"
if [[ "$EXPIRE" == "never" ]]; then
    EXP_SQL="NULL"
elif [[ "$EXPIRE" =~ ^([0-9]{1,4})(h|d)$ ]]; then
    N="${BASH_REMATCH[1]}"; U="${BASH_REMATCH[2]}"
    [[ "$U" == "h" ]] && EXP_SQL="DATE_ADD(NOW(), INTERVAL ${N} HOUR)" || EXP_SQL="DATE_ADD(NOW(), INTERVAL ${N} DAY)"
else
    fail "Invalid expiry. Use: never, 1h, 24h, 7d, 30d"
fi
PASS=$(rand_alnum 24)
printf '%s:%s\n' "$SITE_USER" "$PASS" | chpasswd
usermod -aG sftpusers "$SITE_USER"
SID=$(site_id)
db "INSERT INTO sftp_access (site_id, sftp_user, is_enabled, expires_at) VALUES (${SID}, '${SITE_USER}', 1, ${EXP_SQL})
    ON DUPLICATE KEY UPDATE sftp_user=VALUES(sftp_user), is_enabled=1, expires_at=VALUES(expires_at)"
EXPIRES=$(db "SELECT IFNULL(expires_at,'') FROM sftp_access WHERE site_id=${SID}")
log_activity sftp_enabled "{\"expire\":\"${EXPIRE}\"}" "$SID"
ok "$(jq -cn --arg u "$SITE_USER" --arg p "$PASS" --arg h "$SERVER_IP" --arg hn "$SERVER_HOSTNAME" --arg e "$EXPIRES" \
    '{username:$u, password:$p, host:$h, hostname:$hn, port:22, path:"/public", expires_at:(if $e=="" then null else $e end)}')" \
    "SFTP access enabled"
SCRIPT

# ==================== SFTP DISABLE ====================
cat > "${FLYNE_DIR}/scripts/sftp-disable.sh" << 'SCRIPT'
#!/bin/bash
# sftp-disable.sh <domain>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
usermod -L "$SITE_USER" >/dev/null 2>&1 || true
gpasswd -d "$SITE_USER" sftpusers >/dev/null 2>&1 || true
pkill -KILL -u "$SITE_USER" sshd >/dev/null 2>&1 || true
SID=$(site_id)
db "UPDATE sftp_access SET is_enabled=0 WHERE site_id=${SID}"
log_activity sftp_disabled "{}" "$SID"
ok '{}' "SFTP access disabled"
SCRIPT

# ==================== SFTP EXPIRY (cron) ====================
cat > "${FLYNE_DIR}/scripts/sftp-expire.sh" << 'SCRIPT'
#!/bin/bash
source /opt/flyne/scripts/lib.sh
N=0
while read -r d; do
    [[ -z "$d" ]] && continue
    /bin/bash /opt/flyne/scripts/sftp-disable.sh "$d" >/dev/null 2>&1 && N=$((N+1)) || true
done < <(db "SELECT s.domain FROM sftp_access a JOIN sites s ON s.id=a.site_id WHERE a.is_enabled=1 AND a.expires_at IS NOT NULL AND a.expires_at < NOW()")
ok "$(jq -cn --argjson n "$N" '{expired:$n}')"
SCRIPT

# ==================== CACHE PURGE ====================
cat > "${FLYNE_DIR}/scripts/cache-purge.sh" << 'SCRIPT'
#!/bin/bash
# cache-purge.sh [domain]     (no domain = page cache of every site)
source /opt/flyne/scripts/lib.sh
if [[ -z "${1:-}" ]]; then
    N=0
    for d in "${NGX_CACHE_DIR}"/*/; do
        [[ -d "$d" ]] || continue
        find "$d" -mindepth 1 -delete 2>/dev/null || true
        N=$((N+1))
    done
    log_activity cache_purged_all "{\"sites\":${N}}"
    ok "$(jq -cn --argjson n "$N" '{sites:$n, page_cache:"purged"}')" "Page cache purged for all sites"
fi
load_site "$1"
[[ -d "$CACHE_PATH" ]] && find "$CACHE_PATH" -mindepth 1 -delete 2>/dev/null || true
OBJ="skipped"
if [[ "$SUSPENDED" != "1" && -f "${DOC_ROOT}/wp-config.php" ]]; then
    if wp_run cache flush >/dev/null 2>&1; then OBJ="flushed"; else OBJ="failed"; fi
fi
log_activity cache_purged "{}" "$(site_id)"
ok "$(jq -cn --arg o "$OBJ" '{page_cache:"purged", object_cache:$o}')" "Cache purged"
SCRIPT

# ==================== WP-CLI ====================
# Arguments arrive as a real argv (never a shell string). Code-execution and
# path-escape flags are refused here even if the API already refused them.
cat > "${FLYNE_DIR}/scripts/wp-cli.sh" << 'SCRIPT'
#!/bin/bash
# wp-cli.sh <domain> <wp arguments...>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"; shift
[[ $# -ge 1 ]] || fail "WP-CLI command required"
[[ -f "${DOC_ROOT}/wp-config.php" ]] || fail "WordPress is not installed for this site"
case "$1" in
    eval|eval-file|shell|package|cli|server|-*) fail "WP-CLI command '$1' is not permitted" ;;
esac
if [[ "$1" == "db" ]]; then
    case "${2:-}" in drop|reset|clean|create) fail "WP-CLI 'db ${2}' is not permitted" ;; esac
fi
for a in "$@"; do
    case "$a" in
        --require|--require=*|--exec|--exec=*|--ssh|--ssh=*|--http|--http=*|--path|--path=*|--config|--config=*|--prompt|--prompt=*)
            fail "WP-CLI flag '${a%%=*}' is not permitted" ;;
    esac
done
RC=0
OUT=$(wp_run "$@" 2>&1) || RC=$?
OUT=$(printf '%s' "$OUT" | head -c 2000000)
case "${2:-}" in
    list|get|status|version|check-update|is-installed|path|search|verify-checksums) ;;
    *) log_activity wp_cli "$(jq -cn --arg c "$*" '{command:$c}')" "$(site_id)" ;;
esac
json_out "$(jq -cn --arg out "$OUT" --argjson rc "$RC" '{success:($rc==0), exit_code:$rc, output:$out}')"
exit 0
SCRIPT

# ==================== SSL ISSUE (webroot; nginx config is never edited by certbot) ====================
cat > "${FLYNE_DIR}/scripts/ssl-issue.sh" << 'SCRIPT'
#!/bin/bash
# ssl-issue.sh <domain>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
[[ "$SUSPENDED" == "1" ]] && fail "Site is suspended"

resolve() { dig +short +time=3 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | head -5 || true; }
MAIN_IPS=$(resolve "$DOMAIN")
[[ -n "$MAIN_IPS" ]] || fail "DNS for ${DOMAIN} has no A record yet. Point it to ${SERVER_IP} and retry."
grep -qx "$SERVER_IP" <<< "$MAIN_IPS" || log "notice: ${DOMAIN} resolves to $(tr '\n' ',' <<< "$MAIN_IPS") not ${SERVER_IP} (CDN/proxy?) - attempting anyway"
NAMES=(-d "$DOMAIN")
if [[ "$DOMAIN" != www.* ]]; then
    WWW_IPS=$(resolve "www.${DOMAIN}")
    [[ -n "$WWW_IPS" ]] && NAMES+=(-d "www.${DOMAIN}")
fi

run_certbot() {
    certbot certonly --webroot -w "$ACME_DIR" "$@" --cert-name "$DOMAIN" \
        --non-interactive --agree-tos --email "$ADMIN_EMAIL" --no-eff-email \
        --keep-until-expiring --expand --preferred-challenges http \
        --deploy-hook /opt/flyne/scripts/ssl-deploy-hook.sh
}
log "requesting certificate for ${NAMES[*]}"
if ! run_certbot "${NAMES[@]}"; then
    if [[ ${#NAMES[@]} -gt 2 ]]; then
        log "issuance with www failed, retrying with ${DOMAIN} only"
        run_certbot -d "$DOMAIN" || fail "Certificate issuance failed for ${DOMAIN} (details in ${AGENT_LOG})"
    else
        fail "Certificate issuance failed for ${DOMAIN} (details in ${AGENT_LOG})"
    fi
fi

SSL=1; write_site_env
render_nginx_apply || fail "Certificate issued but nginx rejected the TLS vhost (rolled back)"
db "UPDATE sites SET ssl_enabled=1 WHERE domain='$(sql_esc "$DOMAIN")'"
if [[ -f "${DOC_ROOT}/wp-config.php" ]]; then
    wp_run option update home "https://${DOMAIN}" >/dev/null 2>&1 || true
    wp_run option update siteurl "https://${DOMAIN}" >/dev/null 2>&1 || true
    wp_run config set FORCE_SSL_ADMIN true --raw --type=constant >/dev/null 2>&1 || true
    wp_run cache flush >/dev/null 2>&1 || true
fi
[[ -d "$CACHE_PATH" ]] && find "$CACHE_PATH" -mindepth 1 -delete 2>/dev/null || true
EXP=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" 2>/dev/null | cut -d= -f2)
log_activity ssl_enabled "{\"domain\":\"${DOMAIN}\"}" "$(site_id)"
ok "$(jq -cn --arg d "$DOMAIN" --arg e "$EXP" '{domain:$d, ssl_enabled:true, expires_at:$e, url:("https://"+$d)}')" "TLS certificate installed"
SCRIPT

cat > "${FLYNE_DIR}/scripts/ssl-deploy-hook.sh" << 'SCRIPT'
#!/bin/bash
# certbot deploy hook (renewals): reload nginx only if the config is sane
nginx -t >/dev/null 2>&1 && systemctl reload nginx
exit 0
SCRIPT

# ==================== SSL STATUS ====================
cat > "${FLYNE_DIR}/scripts/ssl-status.sh" << 'SCRIPT'
#!/bin/bash
# ssl-status.sh <domain>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
EN=false; [[ "$SSL" == "1" ]] && EN=true
if [[ -s "$CERT" ]]; then
    EXP=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
    EXP_ISO=$(date -u -d "$EXP" +%FT%TZ)
    DAYS=$(( ( $(date -d "$EXP" +%s) - $(date +%s) ) / 86400 ))
    ISS=$(openssl x509 -issuer -noout -in "$CERT" | sed 's/^issuer=//')
    SANS=$(openssl x509 -noout -ext subjectAltName -in "$CERT" 2>/dev/null | grep -o 'DNS:[^,]*' | sed 's/DNS://' | tr '\n' ' ')
    ok "$(jq -cn --argjson en "$EN" --arg exp "$EXP_ISO" --argjson days "$DAYS" --arg iss "$ISS" --arg sans "$SANS" \
        '{ssl_enabled:$en, certificate:true, expires_at:$exp, days_left:$days, issuer:$iss, names:($sans|split(" ")|map(select(length>0)))}')"
fi
ok "$(jq -cn --argjson en "$EN" '{ssl_enabled:$en, certificate:false, expires_at:null, days_left:null}')"
SCRIPT

# ==================== BACKUP CREATE ====================
cat > "${FLYNE_DIR}/scripts/backup-create.sh" << 'SCRIPT'
#!/bin/bash
# backup-create.sh <domain> [full|files|database] [note]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
TYPE="${2:-full}"; NOTE="${3:-}"
[[ "$TYPE" =~ ^(full|files|database)$ ]] || fail "Invalid backup type (full|files|database)"
[[ ${#NOTE} -le 200 && "$NOTE" =~ ^[A-Za-z0-9._\ -]*$ ]] || fail "Invalid note"
SID=$(site_id); [[ -n "$SID" ]] || fail "Site is not registered"
DBN=$(db "SELECT IFNULL(db_name,'') FROM sites WHERE id=${SID}")
[[ "$TYPE" != "files" && ! "$DBN" =~ ^wp_[a-z0-9_]+$ ]] && fail "Site has no database registered"

mkdir -p "$SITE_BACKUP_DIR"; chmod 700 "$SITE_BACKUP_DIR"
TS=$(date -u +%Y%m%d-%H%M%S)
FILE="${SITE_BACKUP_DIR}/${DOMAIN}_${TYPE}_${TS}.tar.gz"
WORK=$(mktemp -d "${SITE_BACKUP_DIR}/.work.XXXXXX")
trap 'rm -rf "$WORK"; on_exit' EXIT
BID=$(db "INSERT INTO backups (site_id, type, status, note) VALUES (${SID}, '${TYPE}', 'running', '$(sql_esc "$NOTE")'); SELECT LAST_INSERT_ID();")
log "backup #${BID} ${TYPE} for ${DOMAIN} -> ${FILE}"

fail_backup() { db "UPDATE backups SET status='failed', completed_at=NOW() WHERE id=${BID}" || true; rm -f "$FILE"; fail "$1"; }

if [[ "$TYPE" != "files" ]]; then
    nice -n 10 ionice -c2 -n7 mysqldump --single-transaction --quick --routines --triggers --events \
        --default-character-set=utf8mb4 --skip-lock-tables "$DBN" > "${WORK}/database.sql" \
        || fail_backup "Database dump failed"
fi
printf 'domain=%s\ntype=%s\ncreated=%s\nphp=%s\ndb=%s\nsite_user=%s\n' \
    "$DOMAIN" "$TYPE" "$TS" "$PHP_VERSION" "$DBN" "$SITE_USER" > "${WORK}/flyne-backup.meta"
cp "$SITE_ENV" "${WORK}/site.env"

TAR_ARGS=(-C "$WORK" flyne-backup.meta site.env)
[[ "$TYPE" != "files" ]] && TAR_ARGS+=(database.sql)
if [[ "$TYPE" != "database" ]]; then
    TAR_ARGS+=(-C "$SITE_DIR" --exclude='public/wp-content/cache' --exclude='public/wp-content/upgrade' public)
fi
nice -n 10 ionice -c2 -n7 tar --warning=no-file-changed -I pigz -cf "$FILE" "${TAR_ARGS[@]}" || [[ $? -eq 1 ]] || fail_backup "Archive creation failed"
chmod 600 "$FILE"
SIZE=$(stat -c%s "$FILE")
db "UPDATE backups SET status='completed', file_path='$(sql_esc "$FILE")', file_size=${SIZE}, completed_at=NOW() WHERE id=${BID}"
if [[ -n "${BACKUP_REMOTE:-}" ]] && command -v rclone >/dev/null 2>&1; then
    rclone copy --quiet "$FILE" "${BACKUP_REMOTE}/${DOMAIN}/" || log "offsite copy failed for ${FILE}"
fi
log_activity backup_created "{\"backup_id\":${BID},\"type\":\"${TYPE}\",\"size\":${SIZE}}" "$SID"
ok "$(jq -cn --argjson id "$BID" --arg t "$TYPE" --arg f "$FILE" --argjson s "$SIZE" --arg ts "$TS" \
    '{backup_id:$id, type:$t, file:$f, size_bytes:$s, created:$ts}')" "Backup completed"
SCRIPT

# ==================== BACKUP LIST ====================
cat > "${FLYNE_DIR}/scripts/backup-list.sh" << 'SCRIPT'
#!/bin/bash
# backup-list.sh <domain>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
SID=$(site_id); [[ -n "$SID" ]] || fail "Site is not registered"
ROWS=$(db "SELECT JSON_ARRAYAGG(JSON_OBJECT('id',id,'type',type,'status',status,'size_bytes',file_size,'note',note,
        'created_at',DATE_FORMAT(created_at,'%Y-%m-%dT%H:%i:%sZ'),'completed_at',IFNULL(DATE_FORMAT(completed_at,'%Y-%m-%dT%H:%i:%sZ'),NULL),
        'present',IF(file_path IS NOT NULL,1,0))) FROM (SELECT * FROM backups WHERE site_id=${SID} ORDER BY id DESC LIMIT 200) b")
[[ -z "$ROWS" || "$ROWS" == "NULL" ]] && ROWS="[]"
ok "$(jq -cn --argjson b "$ROWS" '{backups:$b, count:($b|length)}')"
SCRIPT

# ==================== BACKUP RESTORE ====================
cat > "${FLYNE_DIR}/scripts/backup-restore.sh" << 'SCRIPT'
#!/bin/bash
# backup-restore.sh <domain> <backup_id> [full|files|database]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
BID="${2:-}"; WHAT="${3:-full}"
is_int "$BID" || fail "Invalid backup id"
[[ "$WHAT" =~ ^(full|files|database)$ ]] || fail "Invalid restore scope"
SID=$(site_id); [[ -n "$SID" ]] || fail "Site is not registered"
FILE=$(db "SELECT IFNULL(file_path,'') FROM backups WHERE id=${BID} AND site_id=${SID} AND status='completed'")
[[ -n "$FILE" && -f "$FILE" && "$FILE" == "${SITE_BACKUP_DIR}/"* ]] || fail "Backup not found for this site"
BTYPE=$(db "SELECT type FROM backups WHERE id=${BID}")
DBN=$(db "SELECT IFNULL(db_name,'') FROM sites WHERE id=${SID}")

WORK=$(mktemp -d "${SITE_BACKUP_DIR}/.restore.XXXXXX")
trap 'rm -rf "$WORK"; on_exit' EXIT
tar -I pigz -xf "$FILE" -C "$WORK" || fail "Could not extract backup archive"

RESTORED=()
if [[ "$WHAT" != "files" ]]; then
    [[ -f "${WORK}/database.sql" ]] || fail "Backup #${BID} (${BTYPE}) contains no database"
    [[ "$DBN" =~ ^wp_[a-z0-9_]+$ ]] || fail "Site has no database registered"
    /bin/bash /opt/flyne/scripts/backup-create.sh "$DOMAIN" database "pre-restore-${BID}" >/dev/null 2>&1 || log "warning: pre-restore snapshot failed"
    mysql "$DBN" < "${WORK}/database.sql" || fail "Database import failed"
    RESTORED+=("database")
fi
if [[ "$WHAT" != "database" ]]; then
    [[ -d "${WORK}/public" ]] || fail "Backup #${BID} (${BTYPE}) contains no files"
    # keep the live wp-config.php (credentials may have rotated since the backup)
    [[ -f "${DOC_ROOT}/wp-config.php" ]] && cp -p "${DOC_ROOT}/wp-config.php" "${WORK}/wp-config.live"
    rsync -a --delete --exclude='wp-content/cache' "${WORK}/public/" "${DOC_ROOT}/" || fail "File restore failed"
    [[ -f "${WORK}/wp-config.live" ]] && cp -p "${WORK}/wp-config.live" "${DOC_ROOT}/wp-config.php"
    chown -R "$SITE_USER:$SITE_USER" "$DOC_ROOT"
    find "$DOC_ROOT" -type d -exec chmod 2750 {} +
    find "$DOC_ROOT" -type f -exec chmod 640 {} +
    chmod 600 "${DOC_ROOT}/wp-config.php" 2>/dev/null || true
    RESTORED+=("files")
fi
[[ -d "$CACHE_PATH" ]] && find "$CACHE_PATH" -mindepth 1 -delete 2>/dev/null || true
[[ "$SUSPENDED" != "1" ]] && { wp_run cache flush >/dev/null 2>&1 || true; }
log_activity backup_restored "{\"backup_id\":${BID},\"scope\":\"${WHAT}\"}" "$SID"
ok "$(jq -cn --argjson id "$BID" --arg r "${RESTORED[*]}" '{backup_id:$id, restored:($r|split(" "))}')" "Backup restored"
SCRIPT

# ==================== BACKUP DELETE ====================
cat > "${FLYNE_DIR}/scripts/backup-delete.sh" << 'SCRIPT'
#!/bin/bash
# backup-delete.sh <domain> <backup_id>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
BID="${2:-}"; is_int "$BID" || fail "Invalid backup id"
SID=$(site_id); [[ -n "$SID" ]] || fail "Site is not registered"
FILE=$(db "SELECT IFNULL(file_path,'') FROM backups WHERE id=${BID} AND site_id=${SID}")
[[ -n "$FILE" || -n "$(db "SELECT id FROM backups WHERE id=${BID} AND site_id=${SID}")" ]] || fail "Backup not found"
[[ -n "$FILE" && "$FILE" == "${SITE_BACKUP_DIR}/"* ]] && rm -f "$FILE"
db "DELETE FROM backups WHERE id=${BID} AND site_id=${SID}"
ok "$(jq -cn --argjson id "$BID" '{backup_id:$id}')" "Backup deleted"
SCRIPT

# ==================== BACKUP ALL + PRUNE (cron) ====================
cat > "${FLYNE_DIR}/scripts/backup-all.sh" << 'SCRIPT'
#!/bin/bash
source /opt/flyne/scripts/lib.sh
OKN=0; FAILN=0
while read -r d; do
    [[ -z "$d" ]] && continue
    if /bin/bash /opt/flyne/scripts/backup-create.sh "$d" full nightly >/dev/null 2>&1; then OKN=$((OKN+1)); else FAILN=$((FAILN+1)); log "nightly backup FAILED for $d"; fi
done < <(db "SELECT domain FROM sites WHERE status IN ('active','suspended')")
# prune by retention
RET="${BACKUP_RETENTION_DAYS:-14}"; is_int "$RET" || RET=14
while IFS=$'\t' read -r bid fpath; do
    [[ -z "$bid" ]] && continue
    [[ -n "$fpath" && "$fpath" == "${BACKUP_DIR}/"* ]] && rm -f "$fpath"
    db "DELETE FROM backups WHERE id=${bid}"
done < <(db "SELECT id, IFNULL(file_path,'') FROM backups WHERE created_at < DATE_SUB(NOW(), INTERVAL ${RET} DAY) AND IFNULL(note,'') NOT LIKE 'final-%'")
find "$BACKUP_DIR" -mindepth 2 -type f -name '*.tar.gz' -mtime "+$((RET+7))" -delete 2>/dev/null || true
find "$BACKUP_DIR" -mindepth 1 -type d -name '.work.*' -mmin +720 -exec rm -rf {} + 2>/dev/null || true
ok "$(jq -cn --argjson o "$OKN" --argjson f "$FAILN" '{backed_up:$o, failed:$f}')"
SCRIPT

# ==================== SUSPEND / UNSUSPEND ====================
cat > "${FLYNE_DIR}/scripts/site-suspend.sh" << 'SCRIPT'
#!/bin/bash
# site-suspend.sh <domain> [reason]
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
REASON="${2:-manual}"; [[ ${#REASON} -le 200 ]] || fail "Reason too long"
[[ "$SUSPENDED" == "1" ]] && ok '{"suspended":true}' "Site is already suspended"
SUSPENDED=1; write_site_env
render_cron
render_nginx_apply || fail "nginx rejected the suspended vhost (rolled back)"
systemctl disable --now "$PHP_UNIT" "$REDIS_UNIT" >/dev/null 2>&1 || true
/bin/bash /opt/flyne/scripts/sftp-disable.sh "$DOMAIN" >/dev/null 2>&1 || true
pkill -KILL -u "$SITE_USER" >/dev/null 2>&1 || true
SID=$(site_id)
db "UPDATE sites SET status='suspended' WHERE id=${SID}"
log_activity site_suspended "{\"reason\":\"$(sql_esc "$REASON")\"}" "$SID"
ok '{"suspended":true}' "Site suspended"
SCRIPT

cat > "${FLYNE_DIR}/scripts/site-unsuspend.sh" << 'SCRIPT'
#!/bin/bash
# site-unsuspend.sh <domain>
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
[[ "$SUSPENDED" == "0" ]] && ok '{"suspended":false}' "Site is not suspended"
SUSPENDED=0; write_site_env
render_fpm_conf; render_redis_conf; render_systemd; render_cron
php_test_config || fail "PHP-FPM configuration failed validation"
systemctl enable "$REDIS_UNIT" "$PHP_UNIT" >/dev/null 2>&1
redis_service_restart || log "warning: redis failed to start: $(unit_journal_tail "$REDIS_UNIT")"
php_service_restart   || fail "PHP-FPM failed to start: $(unit_journal_tail "$PHP_UNIT")"
render_nginx_apply    || fail "nginx rejected the vhost (rolled back)"
SID=$(site_id)
db "UPDATE sites SET status='active' WHERE id=${SID}"
log_activity site_unsuspended "{}" "$SID"
ok '{"suspended":false}' "Site reactivated"
SCRIPT

# ==================== SITE LIMITS (plan / resource changes) ====================
cat > "${FLYNE_DIR}/scripts/site-limits.sh" << 'SCRIPT'
#!/bin/bash
# site-limits.sh <domain> [key=value ...]     (no pairs = show current limits)
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"; shift
show() {
    ok "$(jq -cn --argjson cpu "$CPU_QUOTA" --argjson mem "$MEMORY_MAX_MB" --argjson ch "$PHP_MAX_CHILDREN" \
        --argjson pm "$PHP_MEMORY_LIMIT_MB" --argjson opc "$PHP_OPCACHE_MB" --argjson up "$PHP_UPLOAD_MB" \
        --argjson ex "$PHP_MAX_EXECUTION" --arg pmm "$PHP_PM" --argjson ae "$PHP_ALLOW_EXEC" --argjson rd "$REDIS_MAX_MB" \
        --argjson dq "$DISK_QUOTA_MB" --argjson dc "$DB_MAX_CONN" --arg x "$XMLRPC" --argjson ce "$CACHE_ENABLED" --argjson ct "$CACHE_TTL" \
        '{cpu_quota:$cpu, memory_max_mb:$mem, php_max_children:$ch, php_memory_limit_mb:$pm, php_opcache_mb:$opc,
          php_upload_mb:$up, php_max_execution:$ex, php_pm:$pmm, php_allow_exec:($ae==1), redis_max_mb:$rd,
          disk_quota_mb:$dq, db_max_connections:$dc, xmlrpc:$x, cache_enabled:($ce==1), cache_ttl:$ct}')" "$1"
}
[[ $# -eq 0 ]] && show "Current limits"

set_int() { local var="$1" val="$2" min="$3" max="$4"; is_int "$val" || fail "$var must be a number"; (( val >= min && val <= max )) || fail "$var must be between $min and $max"; printf -v "$var" '%s' "$val"; }
for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    case "$k" in
        cpu_quota)            set_int CPU_QUOTA "$v" 10 3200 ;;
        memory_max_mb)        set_int MEMORY_MAX_MB "$v" 256 65536 ;;
        php_max_children)     set_int PHP_MAX_CHILDREN "$v" 1 128 ;;
        php_memory_limit_mb)  set_int PHP_MEMORY_LIMIT_MB "$v" 64 4096 ;;
        php_opcache_mb)       set_int PHP_OPCACHE_MB "$v" 32 1024 ;;
        php_upload_mb)        set_int PHP_UPLOAD_MB "$v" 2 4096 ;;
        php_max_execution)    set_int PHP_MAX_EXECUTION "$v" 30 3600 ;;
        redis_max_mb)         set_int REDIS_MAX_MB "$v" 16 4096 ;;
        disk_quota_mb)        set_int DISK_QUOTA_MB "$v" 100 10000000 ;;
        db_max_connections)   set_int DB_MAX_CONN "$v" 5 1000 ;;
        cache_ttl)            set_int CACHE_TTL "$v" 0 2592000 ;;
        php_pm)               [[ "$v" =~ ^(ondemand|dynamic|static)$ ]] || fail "php_pm must be ondemand|dynamic|static"; PHP_PM="$v" ;;
        php_allow_exec)       [[ "$v" =~ ^[01]$ ]] || fail "php_allow_exec must be 0|1"; PHP_ALLOW_EXEC="$v" ;;
        cache_enabled)        [[ "$v" =~ ^[01]$ ]] || fail "cache_enabled must be 0|1"; CACHE_ENABLED="$v" ;;
        xmlrpc)               [[ "$v" =~ ^(on|off)$ ]] || fail "xmlrpc must be on|off"; XMLRPC="$v" ;;
        *) fail "Unknown limit key: $k" ;;
    esac
done
(( PHP_MEMORY_LIMIT_MB * PHP_MAX_CHILDREN <= MEMORY_MAX_MB * 3 )) || fail "php_memory_limit_mb x php_max_children is far above memory_max_mb; raise memory_max_mb"

write_site_env
render_fpm_conf; render_redis_conf; render_systemd; render_cron
php_test_config || fail "PHP-FPM configuration failed validation"
SID=$(site_id)
DBU=$(db "SELECT IFNULL(db_user,'') FROM sites WHERE id=${SID}")
[[ "$DBU" =~ ^u_[a-f0-9]+$ ]] && mysql -e "ALTER USER '${DBU}'@'localhost' WITH MAX_USER_CONNECTIONS ${DB_MAX_CONN};" || true
if [[ "$SUSPENDED" != "1" ]]; then
    redis_service_restart || log "warning: redis restart failed: $(unit_journal_tail "$REDIS_UNIT")"
    php_service_restart   || fail "PHP-FPM failed to restart with the new limits: $(unit_journal_tail "$PHP_UNIT")"
fi
render_nginx_apply || fail "nginx rejected the vhost (rolled back)"
db "UPDATE sites SET cpu_quota=${CPU_QUOTA}, memory_max_mb=${MEMORY_MAX_MB}, php_max_children=${PHP_MAX_CHILDREN},
    php_memory_limit_mb=${PHP_MEMORY_LIMIT_MB}, redis_max_mb=${REDIS_MAX_MB}, disk_quota_mb=${DISK_QUOTA_MB},
    db_max_connections=${DB_MAX_CONN} WHERE id=${SID}"
log_activity site_limits_changed "$(jq -cn --arg a "$*" '{changes:$a}')" "$SID"
show "Limits applied"
SCRIPT

# ==================== SITE INSPECT (usage, logs, theme screenshots) ====================
cat > "${FLYNE_DIR}/scripts/site-inspect.sh" << 'SCRIPT'
#!/bin/bash
# site-inspect.sh <domain> disk-usage | logs <access|error|php-error|php-slow|wp-cron> [lines] | theme-screenshots
source /opt/flyne/scripts/lib.sh
load_site "${1:-}"
WHAT="${2:-disk-usage}"
case "$WHAT" in
    disk-usage)
        TOTAL=$(dir_size_mb "$SITE_DIR"); PUB=$(dir_size_mb "$DOC_ROOT"); LOGS=$(dir_size_mb "$LOGS_DIR"); TMP=$(dir_size_mb "$TMP_DIR")
        UPL=0; [[ -d "${DOC_ROOT}/wp-content/uploads" ]] && UPL=$(dir_size_mb "${DOC_ROOT}/wp-content/uploads")
        BK=0; [[ -d "$SITE_BACKUP_DIR" ]] && BK=$(dir_size_mb "$SITE_BACKUP_DIR")
        DBN=$(db "SELECT IFNULL(db_name,'') FROM sites WHERE domain='$(sql_esc "$DOMAIN")'")
        DBMB=0; [[ -n "$DBN" ]] && DBMB=$(db_size_mb "$DBN")
        db "UPDATE sites SET disk_used_mb=${TOTAL}, db_used_mb=${DBMB} WHERE domain='$(sql_esc "$DOMAIN")'" || true
        ok "$(jq -cn --argjson t "$TOTAL" --argjson p "$PUB" --argjson l "$LOGS" --argjson tm "$TMP" --argjson u "$UPL" \
              --argjson b "$BK" --argjson d "$DBMB" --argjson q "$DISK_QUOTA_MB" \
              '{total_mb:$t, quota_mb:$q, db_mb:$d, backups_mb:$b, breakdown:{public:$p, uploads:$u, logs:$l, tmp:$tm}}')" ;;
    logs)
        TYPE="${3:-error}"; LINES="${4:-100}"
        is_int "$LINES" || LINES=100; (( LINES > 2000 )) && LINES=2000; (( LINES < 1 )) && LINES=1
        case "$TYPE" in access|error|php-error|php-slow|php-fpm|wp-cron) ;; *) fail "Unknown log type" ;; esac
        F="${LOGS_DIR}/${TYPE}.log"
        [[ -f "$F" ]] || ok '{"lines":[]}'
        ok "$(tail -n "$LINES" "$F" | jq -Rn --arg t "$TYPE" '{type:$t, lines:[inputs]}')" ;;
    theme-screenshots)
        [[ -d "${DOC_ROOT}/wp-content/themes" ]] || ok '{"screenshots":{}}'
        SCHEME=http; [[ "$SSL" == "1" ]] && SCHEME=https
        ok "$(cd "${DOC_ROOT}/wp-content/themes" && for t in */; do t="${t%/}"; for e in png jpg jpeg gif webp; do
                if [[ -f "${t}/screenshot.${e}" ]]; then printf '%s\t%s://%s/wp-content/themes/%s/screenshot.%s\n' "$t" "$SCHEME" "$DOMAIN" "$t" "$e"; break; fi; done; done \
              | jq -Rn '{screenshots:([inputs|split("\t")|{key:.[0],value:.[1]}]|from_entries)}')" ;;
    *) fail "Unknown inspect action" ;;
esac
SCRIPT

# ==================== SYSTEM CHECK (privileged half of system_status) ====================
cat > "${FLYNE_DIR}/scripts/system-check.sh" << 'SCRIPT'
#!/bin/bash
source /opt/flyne/scripts/lib.sh
svc() { systemctl is-active --quiet "$1" && echo running || echo stopped; }
PHPV="{}"
for v in $PHP_VERSIONS_ALLOWED; do php_installed "$v" && PHPV=$(jq -cn --argjson p "$PHPV" --arg v "$v" '$p + {($v): "installed"}'); done
RUNNING=$(systemctl list-units --type=service --state=running --no-legend 'flyne-php@*' 2>/dev/null | wc -l)
FAILED=$(systemctl list-units --type=service --state=failed --no-legend 'flyne-php@*' 'flyne-redis@*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
NGX_OK=false; nginx -t >/dev/null 2>&1 && NGX_OK=true
BANNED_TOTAL=0
for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do
    n=$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:\s*//p' | head -1); is_int "${n:-x}" && BANNED_TOTAL=$((BANNED_TOTAL + n))
done
UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true)
CERT_TIMER=$(systemctl is-active certbot.timer 2>/dev/null || echo inactive)
SITES=$(db "SELECT JSON_OBJECTAGG(status, c) FROM (SELECT status, COUNT(*) c FROM sites GROUP BY status) s")
[[ -z "$SITES" || "$SITES" == "NULL" ]] && SITES="{}"
ok "$(jq -cn --arg ng "$(svc nginx)" --arg db "$(svc mariadb)" --arg api "$(svc flyne-api-fpm)" --arg f2b "$(svc fail2ban)" \
      --arg pf "$(svc postfix)" --argjson phpv "$PHPV" --argjson run "$RUNNING" --arg failed "$FAILED" --argjson ngx "$NGX_OK" \
      --argjson banned "$BANNED_TOTAL" --argjson upd "$UPDATES" --arg ct "$CERT_TIMER" --argjson sites "$SITES" \
      '{services:{nginx:$ng, mariadb:$db, "flyne-api":$api, fail2ban:$f2b, postfix:$pf}, php_versions:$phpv,
        site_services_running:$run, failed_units:($failed|split(" ")|map(select(length>0))), nginx_config_ok:$ngx,
        fail2ban_banned:$banned, pending_updates:$upd, certbot_timer:$ct, sites:$sites}')"
SCRIPT

# ==================== QUOTA CHECK (cron, hourly) ====================
cat > "${FLYNE_DIR}/scripts/quota-check.sh" << 'SCRIPT'
#!/bin/bash
source /opt/flyne/scripts/lib.sh
OVER=0; CHECKED=0
while IFS=$'\t' read -r d quota; do
    [[ -z "$d" ]] && continue
    CHECKED=$((CHECKED+1))
    /bin/bash /opt/flyne/scripts/site-inspect.sh "$d" disk-usage >/dev/null 2>&1 || continue
    used=$(db "SELECT disk_used_mb + db_used_mb FROM sites WHERE domain='$(sql_esc "$d")'")
    is_int "${used:-x}" || continue
    if (( used > quota )); then
        OVER=$((OVER+1))
        log "QUOTA EXCEEDED: ${d} uses ${used}MB of ${quota}MB"
        log_activity quota_exceeded "{\"used_mb\":${used},\"quota_mb\":${quota}}" "$(db "SELECT id FROM sites WHERE domain='$(sql_esc "$d")'")"
        if [[ "${QUOTA_ENFORCE:-notify}" == "suspend" ]]; then
            /bin/bash /opt/flyne/scripts/site-suspend.sh "$d" "disk quota exceeded" >/dev/null 2>&1 || true
        fi
    fi
done < <(db "SELECT domain, disk_quota_mb FROM sites WHERE status='active'")
ok "$(jq -cn --argjson c "$CHECKED" --argjson o "$OVER" '{checked:$c, over_quota:$o}')"
SCRIPT

# ==================== PANEL VHOST RENDER (API + phpMyAdmin) ====================
cat > "${FLYNE_DIR}/scripts/render-panel.sh" << 'SCRIPT'
#!/bin/bash
# render-panel.sh   - regenerates the API and phpMyAdmin vhosts (TLS if certificates exist)
source /opt/flyne/scripts/lib.sh
ALLOW=""
if [[ -f /etc/flyne/api/allowed-ips ]]; then
    while read -r ip; do [[ -n "$ip" ]] && ALLOW="${ALLOW}    allow ${ip};"$'\n'; done < /etc/flyne/api/allowed-ips
    [[ -n "$ALLOW" ]] && ALLOW="${ALLOW}    deny all;"$'\n'
fi
render_one() {   # render_one <domain> <root> <socket> <kind>
    local dom="$1" root="$2" sock="$3" kind="$4"
    local cert="/etc/letsencrypt/live/${dom}/fullchain.pem" key="/etc/letsencrypt/live/${dom}/privkey.pem"
    local body
    if [[ "$kind" == "api" ]]; then
        body="    root ${root};
    index index.php;
    access_log /var/log/nginx/panel-access.log flyne;
    error_log /var/log/nginx/panel-error.log warn;
    client_max_body_size 8m;
    include snippets/flyne-acme.conf;
${ALLOW}    location = /index.php {
        limit_req zone=flyne_api burst=60 nodelay;
        include snippets/flyne-php.conf;
        fastcgi_read_timeout 900s;
        fastcgi_send_timeout 900s;
        fastcgi_pass unix:${sock};
    }
    location / { rewrite ^ /index.php last; }"
    else
        body="    root ${root};
    index index.php;
    access_log /var/log/nginx/pma-access.log flyne;
    error_log /var/log/nginx/pma-error.log warn;
    client_max_body_size 64m;
    include snippets/flyne-acme.conf;
    include snippets/flyne-headers.conf;
    location ~ ^/(?:libraries|templates|setup|sql|vendor|test)/ { deny all; }
    location ~ /\\. { deny all; }
    location ~ \\.php\$ {
        try_files \$uri =404;
        include snippets/flyne-php.conf;
        fastcgi_pass unix:${sock};
    }
    location / { try_files \$uri \$uri/ /index.php?\$args; }"
    fi
    local out="${NGX_SITES}/00${5}-${kind}.conf"
    {
        echo "# managed by Flyne render-panel - DO NOT EDIT"
        echo "server {"; echo "    listen 80;"; echo "    listen [::]:80;"; echo "    server_name ${dom};"
        if [[ -s "$cert" && -s "$key" ]]; then
            echo "    include snippets/flyne-acme.conf;"
            echo "    location / { return 301 https://\$host\$request_uri; }"
            echo "}"
            echo "server {"; echo "    listen 443 ssl http2;"; echo "    listen [::]:443 ssl http2;"; echo "    server_name ${dom};"
            echo "    ssl_certificate ${cert};"; echo "    ssl_certificate_key ${key};"
            echo "    include snippets/flyne-hsts.conf;"
            echo "$body"; echo "}"
        else
            echo "$body"; echo "}"
        fi
    } > "$out"
}
render_one "$PANEL_DOMAIN" /opt/flyne/api /run/flyne-api/php.sock api 1
if [[ "${PMA_ENABLED:-0}" == "1" && -n "${PMA_DOMAIN:-}" ]]; then
    render_one "$PMA_DOMAIN" /usr/share/phpmyadmin /run/flyne-pma/php.sock pma 2
else
    rm -f "${NGX_SITES}/002-pma.conf"
fi
nginx -t || fail "nginx rejected the panel vhost"
systemctl reload nginx
# tell the API whether it may insist on TLS
TLS=false; [[ -s "/etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem" ]] && TLS=true
sed -i "s/'require_tls'\s*=>\s*\(true\|false\)/'require_tls'  => ${TLS}/" /etc/flyne/api/config.php
ok "$(jq -cn --argjson t "$TLS" '{panel_tls:$t}')" "Panel vhosts rendered"
SCRIPT

chown -R root:root "${FLYNE_DIR}/scripts"
chmod 750 "${FLYNE_DIR}/scripts"/*.sh
chmod 640 "${FLYNE_DIR}/scripts/lib.sh"

#===============================================================================
# 15. SUDOERS - the whole privilege boundary is this one line
#===============================================================================
log "Configuring sudo..."
cat > /etc/sudoers.d/flyne << 'SUDOERS'
# Flyne Engine: the API user may run exactly one root-owned dispatcher and nothing else.
Defaults:flyne-api !requiretty, env_reset, secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
flyne-api ALL=(root) NOPASSWD: /opt/flyne/bin/flyne-agent
SUDOERS
chmod 440 /etc/sudoers.d/flyne
visudo -cf /etc/sudoers.d/flyne || error "Sudoers syntax error"

#===============================================================================
# 16. SSH / SFTP (chrooted, SFTP-only site users)
#===============================================================================
log "Configuring SFTP..."
mkdir -p /etc/flyne/sftp-keys; chmod 755 /etc/flyne/sftp-keys
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-flyne.conf << 'SSHD'
# Flyne Engine global SSH hardening (admin login method is left untouched)
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
PermitEmptyPasswords no
SSHD
sed -i 's|^#\?Subsystem\s\+sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config
grep -q '^Subsystem sftp internal-sftp' /etc/ssh/sshd_config || echo 'Subsystem sftp internal-sftp' >> /etc/ssh/sshd_config
if ! grep -q "Match Group sftpusers" /etc/ssh/sshd_config; then
    cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Flyne Engine: SFTP-only site users, chrooted to their own site directory
Match Group sftpusers
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0027
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PasswordAuthentication yes
    PubkeyAuthentication yes
    AuthorizedKeysFile /etc/flyne/sftp-keys/%u
SSHCONF
fi
sshd -t || error "sshd configuration test failed"
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "SSH restart failed"

#===============================================================================
# 17. FIREWALL
#===============================================================================
log "Configuring firewall..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u)
[[ -z "$SSH_PORTS" ]] && SSH_PORTS=22
for p in $SSH_PORTS; do ufw limit "${p}/tcp" >/dev/null; done
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
log "  open: ssh(${SSH_PORTS// /,}) 80 443 - everything else denied"

#===============================================================================
# 18. FAIL2BAN
#===============================================================================
log "Configuring Fail2Ban..."
touch "${LOG_DIR}/sites-placeholder.log"; chmod 640 "${LOG_DIR}/sites-placeholder.log"

cat > /etc/fail2ban/filter.d/flyne-wp-login.conf << 'F2B'
[Definition]
failregex = ^<HOST> - \S+ \[[^\]]+\] "POST /wp-login\.php[^"]*" (?:200|403|429)
ignoreregex =
F2B
cat > /etc/fail2ban/filter.d/flyne-xmlrpc.conf << 'F2B'
[Definition]
failregex = ^<HOST> - \S+ \[[^\]]+\] "POST /xmlrpc\.php[^"]*" (?:200|403|405|429)
ignoreregex =
F2B
cat > /etc/fail2ban/filter.d/flyne-api.conf << 'F2B'
[Definition]
failregex = ^\S+ AUTH-FAIL ip=<HOST> reason=\S+$
ignoreregex =
F2B

PMA_JAIL=""
if [[ $PMA_ENABLED -eq 1 && -f /etc/fail2ban/filter.d/phpmyadmin-syslog.conf ]]; then
PMA_JAIL="
[phpmyadmin-syslog]
enabled = true
port = http,https
backend = systemd
maxretry = 6
findtime = 10m
bantime = 2h
"
fi

cat > /etc/fail2ban/jail.local << F2BJAIL
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w
ignoreip = 127.0.0.1/8 ::1 ${SERVER_IP}

[sshd]
enabled = true
maxretry = 4
bantime = 1d

[recidive]
enabled = true
bantime = 1w
findtime = 1d
maxretry = 3

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
          /var/www/sites/*/logs/error.log
maxretry = 20
findtime = 5m
bantime = 30m

[flyne-wp-login]
enabled = true
port = http,https
filter = flyne-wp-login
logpath = ${LOG_DIR}/sites-placeholder.log
          /var/www/sites/*/logs/access.log
maxretry = 8
findtime = 10m
bantime = 1h

[flyne-xmlrpc]
enabled = true
port = http,https
filter = flyne-xmlrpc
logpath = ${LOG_DIR}/sites-placeholder.log
          /var/www/sites/*/logs/access.log
maxretry = 15
findtime = 5m
bantime = 6h

[flyne-api]
enabled = true
port = http,https
filter = flyne-api
logpath = ${LOG_DIR}/auth.log
maxretry = 5
findtime = 15m
bantime = 1d
${PMA_JAIL}
F2BJAIL
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban || warn "Fail2ban restart failed - check: fail2ban-client -d"

#===============================================================================
# 19. KERNEL / LIMITS
#===============================================================================
log "Applying kernel tuning..."
modprobe tcp_bbr 2>/dev/null || true
cat > /etc/sysctl.d/99-flyne.conf << 'SYSCTL'
# --- network throughput ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.ip_local_port_range = 10240 65535
# --- network hardening ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# --- memory / fs ---
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.max_map_count = 262144
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.pid_max = 4194304
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
SYSCTL
sysctl --system >/dev/null 2>&1 || warn "Some sysctl parameters were not applied"

cat > /etc/security/limits.d/flyne.conf << 'LIMITS'
*        soft nofile 65535
*        hard nofile 65535
www-data soft nofile 100000
www-data hard nofile 100000
mysql    soft nofile 65535
mysql    hard nofile 65535
LIMITS

mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/flyne.conf << 'NR'
# never auto-restart services during apt runs; list them instead
$nrconf{restart} = 'l';
NR

#===============================================================================
# 20. LOGROTATE / CRON / AUTOMATIC SECURITY UPDATES
#===============================================================================
cat > /etc/logrotate.d/flyne << 'LOGROTATE'
/var/log/flyne/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 200M
}
/var/www/sites/*/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 200M
    dateext
}
LOGROTATE

cat > /etc/cron.d/flyne << 'CRONFILE'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=""
# nightly backups + retention pruning
15 2 * * *  root /opt/flyne/scripts/backup-all.sh >> /var/log/flyne/cron.log 2>&1
# hourly disk/db usage refresh + quota policy
25 * * * *  root /opt/flyne/scripts/quota-check.sh >> /var/log/flyne/cron.log 2>&1
# temporary SFTP access expiry
*/5 * * * * root /opt/flyne/scripts/sftp-expire.sh >> /var/log/flyne/cron.log 2>&1
CRONFILE
chmod 644 /etc/cron.d/flyne

mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/flyne-nginx-reload.sh << 'HOOK'
#!/bin/bash
nginx -t >/dev/null 2>&1 && systemctl reload nginx
exit 0
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/flyne-nginx-reload.sh
systemctl enable --now certbot.timer >/dev/null 2>&1 || warn "certbot.timer not available - add a cron entry for 'certbot renew'"

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT
cat > /etc/apt/apt.conf.d/52flyne-unattended << 'APT'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MinimalSteps "true";
APT

#===============================================================================
# 21. POSTFIX (send-only, loopback; optional authenticated relay)
#===============================================================================
log "Configuring outbound mail..."
postconf -e "myhostname = ${SERVER_HOSTNAME}" \
    "myorigin = /etc/mailname" \
    "inet_interfaces = loopback-only" \
    "inet_protocols = all" \
    "mydestination = \$myhostname, localhost.\$mydomain, localhost" \
    "mynetworks = 127.0.0.0/8 [::1]/128" \
    "smtpd_banner = \$myhostname ESMTP" \
    "disable_vrfy_command = yes" \
    "smtp_tls_security_level = may" \
    "smtp_tls_loglevel = 1" \
    "smtp_helo_name = ${SERVER_HOSTNAME}" \
    "message_size_limit = 26214400" \
    "recipient_delimiter = +" \
    "alias_maps = hash:/etc/aliases"
if [[ -n "$RELAY_HOST" ]]; then
    postconf -e "relayhost = [${RELAY_HOST}]:${RELAY_PORT}" \
        "smtp_sasl_auth_enable = yes" \
        "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" \
        "smtp_sasl_security_options = noanonymous" \
        "smtp_tls_security_level = encrypt"
    printf '[%s]:%s %s:%s\n' "$RELAY_HOST" "$RELAY_PORT" "$RELAY_USER" "$RELAY_PASS" > /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    log "  relaying through ${RELAY_HOST}:${RELAY_PORT}"
fi
grep -q "^root:" /etc/aliases 2>/dev/null && sed -i "s|^root:.*|root: ${ADMIN_EMAIL}|" /etc/aliases || echo "root: ${ADMIN_EMAIL}" >> /etc/aliases
newaliases 2>/dev/null || true
systemctl enable postfix >/dev/null 2>&1 || true
systemctl restart postfix || warn "Postfix restart failed"

#===============================================================================
# 22. CLI TOOL
#===============================================================================
log "Installing CLI..."
cat > /usr/local/bin/flyne << 'CLIEOF'
#!/bin/bash
# Flyne Engine CLI - thin wrapper around the root agent. Run as root.
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo flyne ..."; exit 1; }
source /etc/flyne/flyne.conf 2>/dev/null || { echo "Flyne is not installed"; exit 1; }
AGENT=/opt/flyne/bin/flyne-agent
pp() { jq . 2>/dev/null || cat; }
need() { [[ -n "${!1:-}" ]] || { echo "Usage: $2"; exit 1; }; }
CMD="${1:-}"; D="${2:-}"
case "$CMD" in
    status)
        echo "=== Flyne Engine v${FLYNE_VERSION} on ${SERVER_HOSTNAME} (${SERVER_IP}) ==="
        for svc in nginx mariadb flyne-api-fpm fail2ban postfix certbot.timer; do
            systemctl is-active --quiet "$svc" && echo "  $svc: running" || echo "  $svc: STOPPED"
        done
        [[ "$PMA_ENABLED" == "1" ]] && { systemctl is-active --quiet flyne-pma-fpm && echo "  flyne-pma-fpm: running" || echo "  flyne-pma-fpm: STOPPED"; }
        echo "  site PHP services running: $(systemctl list-units --type=service --state=running --no-legend 'flyne-php@*' | wc -l)"
        echo "  failed units: $(systemctl list-units --state=failed --no-legend 'flyne-*' | awk '{print $1}' | tr '\n' ' ')"
        echo "  PHP versions: $(for v in 7.4 8.0 8.1 8.2 8.3 8.4; do [[ -x /usr/sbin/php-fpm$v ]] && printf '%s ' "$v"; done)"
        mysql -e "SELECT status, COUNT(*) AS sites FROM flyne_engine.sites GROUP BY status" 2>/dev/null
        echo "  Panel API: https://${PANEL_DOMAIN}" ;;
    sites)
        mysql -e "SELECT domain, php_version, status, ssl_enabled AS ssl, plan, cpu_quota AS cpu, memory_max_mb AS mem_mb, disk_used_mb AS used_mb, disk_quota_mb AS quota_mb, created_at FROM flyne_engine.sites ORDER BY created_at DESC" ;;
    create)     need D "flyne create <domain> [php] [admin_email] [title] [admin_user] [plan]"; "$AGENT" create-site "${@:2}" | pp ;;
    delete)     need D "flyne delete <domain> [--keep-backups] [--final-backup]"
                read -rp "Delete ${D} and ALL its data? [y/N] " c; [[ "$c" == "y" ]] || exit 0
                "$AGENT" delete-site "${@:2}" | pp ;;
    php)        need D "flyne php <domain> <version>"; "$AGENT" php-switch "$D" "${3:-}" | pp ;;
    restart-php) need D "flyne restart-php <domain> [--hard]"; "$AGENT" php-restart "$D" "${3:-}" | pp ;;
    suspend)    need D "flyne suspend <domain> [reason]"; "$AGENT" site-suspend "$D" "${3:-manual}" | pp ;;
    unsuspend)  need D "flyne unsuspend <domain>"; "$AGENT" site-unsuspend "$D" | pp ;;
    limits)     need D "flyne limits <domain> [key=value ...]"; "$AGENT" site-limits "${@:2}" | pp ;;
    ssl)        need D "flyne ssl <domain>"; "$AGENT" ssl-issue "$D" | pp ;;
    ssl-status) need D "flyne ssl-status <domain>"; "$AGENT" ssl-status "$D" | pp ;;
    sftp)       need D "flyne sftp <domain> enable [never|24h|7d] | disable"
                case "${3:-}" in enable) "$AGENT" sftp-enable "$D" "${4:-never}" | pp ;; disable) "$AGENT" sftp-disable "$D" | pp ;; *) echo "flyne sftp <domain> enable|disable"; exit 1 ;; esac ;;
    backup)     need D "flyne backup <domain> [full|files|database] [note]"; "$AGENT" backup-create "$D" "${3:-full}" "${4:-cli}" | pp ;;
    backups)    need D "flyne backups <domain>"; "$AGENT" backup-list "$D" | pp ;;
    restore)    need D "flyne restore <domain> <backup_id> [full|files|database]"; "$AGENT" backup-restore "$D" "${3:-}" "${4:-full}" | pp ;;
    purge)      "$AGENT" cache-purge "${2:-}" | pp ;;
    wp)         need D "flyne wp <domain> <wp-cli args...>"; "$AGENT" wp-cli "${@:2}" | jq -r 'if .output then .output else (.error // .) end' ;;
    render)     need D "flyne render <domain> [--restart]"; "$AGENT" render-site "${@:2}" | pp ;;
    usage)      need D "flyne usage <domain>"; "$AGENT" site-inspect "$D" disk-usage | pp ;;
    logs)       if [[ -z "$D" ]]; then tail -n 50 -f /var/log/flyne/agent.log; else tail -n 50 -f "/var/www/sites/${D}/logs/"*.log; fi ;;
    panel-ssl)  NAMES=(-d "$PANEL_DOMAIN"); [[ "$PMA_ENABLED" == "1" && -n "$PMA_DOMAIN" ]] && NAMES+=(-d "$PMA_DOMAIN")
                certbot certonly --webroot -w /var/www/acme "${NAMES[@]}" --cert-name "$PANEL_DOMAIN" --non-interactive --agree-tos \
                    --email "$ADMIN_EMAIL" --no-eff-email --keep-until-expiring --expand || echo "certbot failed"
                /bin/bash /opt/flyne/scripts/render-panel.sh | pp ;;
    render-panel) /bin/bash /opt/flyne/scripts/render-panel.sh | pp ;;
    test)       curl -sk "https://${PANEL_DOMAIN}/?action=system_status" -H "Authorization: Bearer ${API_SECRET}" | pp ;;
    *)
        cat << 'HELP'
Flyne Engine CLI
  status                                   platform overview
  sites                                    list sites
  create <domain> [php] [email] [title] [admin_user] [plan]
  delete <domain> [--keep-backups] [--final-backup]
  php <domain> <version>                   switch PHP (tested, auto-rollback)
  restart-php <domain> [--hard]            reload/restart the site's PHP-FPM (opcache reset)
  suspend <domain> [reason] | unsuspend <domain>
  limits <domain> [key=value ...]          cpu_quota memory_max_mb php_max_children php_memory_limit_mb ...
  ssl <domain> | ssl-status <domain>
  sftp <domain> enable [expiry] | disable
  backup <domain> [type] | backups <domain> | restore <domain> <id> [scope]
  purge [domain]                           page + object cache
  wp <domain> <args...>                    WP-CLI as the site user
  render <domain> [--restart]              regenerate all configs for a site
  usage <domain> | logs [domain]
  panel-ssl | render-panel | test
HELP
        ;;
esac
CLIEOF
chmod 755 /usr/local/bin/flyne

#===============================================================================
# 23. PANEL TLS + VHOSTS
#===============================================================================
log "Rendering panel vhosts and requesting TLS..."
if [[ -n "$API_ALLOWED_IPS" ]]; then
    tr ',' '\n' <<< "${API_ALLOWED_IPS// /}" | grep -v '^$' > /etc/flyne/api/allowed-ips
    chmod 644 /etc/flyne/api/allowed-ips
fi
/bin/bash "${FLYNE_DIR}/scripts/render-panel.sh" >/dev/null || error "Panel vhost rendering failed"

PANEL_NAMES=(-d "$PANEL_DOMAIN")
PANEL_DNS=$(dig +short +time=3 +tries=1 A "$PANEL_DOMAIN" 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
if [[ $PMA_ENABLED -eq 1 ]]; then
    PMA_DNS=$(dig +short +time=3 +tries=1 A "$PMA_DOMAIN" 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)
    [[ -n "$PMA_DNS" ]] && PANEL_NAMES+=(-d "$PMA_DOMAIN") || warn "${PMA_DOMAIN} has no DNS record yet - run 'flyne panel-ssl' later"
fi
PANEL_TLS=0
if [[ -n "$PANEL_DNS" ]]; then
    if certbot certonly --webroot -w "$ACME_DIR" "${PANEL_NAMES[@]}" --cert-name "$PANEL_DOMAIN" \
        --non-interactive --agree-tos --email "$ADMIN_EMAIL" --no-eff-email --keep-until-expiring --expand >/dev/null 2>&1; then
        PANEL_TLS=1
    elif [[ ${#PANEL_NAMES[@]} -gt 2 ]] && certbot certonly --webroot -w "$ACME_DIR" -d "$PANEL_DOMAIN" --cert-name "$PANEL_DOMAIN" \
        --non-interactive --agree-tos --email "$ADMIN_EMAIL" --no-eff-email --keep-until-expiring >/dev/null 2>&1; then
        PANEL_TLS=1
        warn "TLS issued for ${PANEL_DOMAIN} only; run 'flyne panel-ssl' once ${PMA_DOMAIN} resolves"
    fi
fi
if [[ $PANEL_TLS -eq 1 ]]; then
    /bin/bash "${FLYNE_DIR}/scripts/render-panel.sh" >/dev/null || warn "Panel re-render failed"
    log "  panel TLS active - API now requires HTTPS"
else
    warn "Panel TLS not issued (DNS for ${PANEL_DOMAIN} must point to ${SERVER_IP}). API is reachable over HTTP until you run: flyne panel-ssl"
fi

#===============================================================================
# 24. CREDENTIALS + VERIFICATION
#===============================================================================
cat > /root/.flyne-credentials << CREDEOF
=== FLYNE ENGINE v5.0 ===
Generated:     $(date)
Panel API:     https://${PANEL_DOMAIN}
phpMyAdmin:    $([[ $PMA_ENABLED -eq 1 ]] && echo "https://${PMA_DOMAIN}" || echo "disabled")
Server IP:     ${SERVER_IP}
Hostname:      ${SERVER_HOSTNAME}
API Secret:    ${API_SECRET}
API DB user:   flyne_api / ${DB_API_PASS}   (flyne_engine only)
MariaDB root:  unix_socket auth (run 'mysql' as root, no password)
Admin Email:   ${ADMIN_EMAIL}
CLI:           flyne help
CREDEOF
chmod 600 /root/.flyne-credentials

log "Verifying installation..."
nginx -t >/dev/null 2>&1 || error "nginx config invalid"
systemctl is-active --quiet mariadb || error "MariaDB not running"
systemctl is-active --quiet flyne-api-fpm || error "API PHP-FPM not running"
systemctl is-active --quiet nginx || error "nginx not running"
mysql -e "SELECT 1" flyne_engine >/dev/null 2>&1 || error "control plane database unreachable"
API_CHECK=$(curl -s --max-time 15 -H "Host: ${PANEL_DOMAIN}" -H "Authorization: Bearer ${API_SECRET}" "http://127.0.0.1/?action=system_status" || true)
if [[ $PANEL_TLS -eq 1 ]]; then
    API_CHECK=$(curl -sk --max-time 15 --resolve "${PANEL_DOMAIN}:443:127.0.0.1" -H "Authorization: Bearer ${API_SECRET}" "https://${PANEL_DOMAIN}/?action=system_status" || true)
fi
if grep -q '"success":true' <<< "$API_CHECK"; then
    log "API responds correctly"
else
    warn "API self-test did not return success. Check /var/log/flyne/api.log and: journalctl -u flyne-api-fpm"
    warn "Response: $(head -c 300 <<< "$API_CHECK")"
fi
sudo -u flyne-api sudo -n /opt/flyne/bin/flyne-agent system-check >/dev/null 2>&1 && log "Agent dispatcher works" || warn "Agent dispatcher self-test failed (check /etc/sudoers.d/flyne)"

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   FLYNE ENGINE v5.0 INSTALLED${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "  Panel API:     ${CYAN}https://${PANEL_DOMAIN}${NC}   (Authorization: Bearer <secret>)"
[[ $PMA_ENABLED -eq 1 ]] && echo -e "  phpMyAdmin:    ${CYAN}https://${PMA_DOMAIN}${NC}"
echo -e "  Server IP:     ${CYAN}${SERVER_IP}${NC}"
echo -e "  Credentials:   ${CYAN}/root/.flyne-credentials${NC}"
echo ""
echo -e "${YELLOW}  API Secret:    ${API_SECRET}${NC}"
echo ""
echo -e "${BLUE}Quick start:${NC}"
echo "  flyne status"
echo "  flyne create example.com 8.4 owner@example.com \"My Site\" siteadmin"
echo "  flyne php example.com 8.3"
echo "  flyne limits example.com cpu_quota=400 memory_max_mb=2048 php_max_children=10"
echo "  flyne backup example.com"
echo ""
echo -e "${YELLOW}Notes:${NC}"
echo "  * Each site runs in its own PHP-FPM + Redis service with CPU/RAM limits (systemctl status 'flyne-php@*')."
echo "  * Point a site's DNS at ${SERVER_IP} before/after creation; TLS is issued automatically (or: flyne ssl <domain>)."
echo "  * Put Cloudflare (Full strict) in front of sites for DDoS protection and edge caching."
log "Installation complete!"
