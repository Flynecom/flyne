#!/bin/bash
#===============================================================================
# FLYNE ENGINE v4.0 - Production-Grade WordPress Hosting
# Fully tested and fixed version
# Ubuntu 22.04/24.04 | Per-site PHP isolation | FastCGI Cache | Redis
#===============================================================================

set -uo pipefail
trap 'echo -e "${RED}[ERROR]${NC} Script failed at line $LINENO"; exit 1' ERR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${GREEN}[FLYNE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    [[ "$ID" != "ubuntu" ]] && error "Only Ubuntu 22.04/24.04 supported"
else
    error "Cannot detect OS"
fi

clear
echo -e "${BLUE}"
cat << "EOF"
   _____ _                        _____            _            
  |  ___| |_   _ _ __   ___      | ____|_ __   __ _(_)_ __   ___ 
  | |_  | | | | | '_ \ / _ \_____|  _| | '_ \ / _` | | '_ \ / _ \
  |  _| | | |_| | | | |  __/_____| |___| | | | (_| | | | | |  __/
  |_|   |_|\__, |_| |_|\___|     |_____|_| |_|\__, |_|_| |_|\___|
           |___/                              |___/              
  Production-Grade WordPress Engine v4.0
EOF
echo -e "${NC}"

#===============================================================================
# CONFIGURATION
#===============================================================================
echo ""
echo -e "${CYAN}=== Configuration ===${NC}"
read -p "API Domain (e.g., api.flyne.ge): " API_DOMAIN
read -p "phpMyAdmin Domain (e.g., pma.flyne.ge): " PMA_DOMAIN
read -p "Admin Email (for SSL): " ADMIN_EMAIL

DEFAULT_API_SECRET=$(openssl rand -hex 32)
DEFAULT_MYSQL_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
DEFAULT_REDIS_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 24)

echo ""
echo -e "${YELLOW}Generated secure defaults (press Enter to use):${NC}"
read -p "API Secret [$DEFAULT_API_SECRET]: " API_SECRET
API_SECRET="${API_SECRET:-$DEFAULT_API_SECRET}"

read -sp "MySQL Admin Password [auto-generated]: " MYSQL_ADMIN_PASS
echo ""
MYSQL_ADMIN_PASS="${MYSQL_ADMIN_PASS:-$DEFAULT_MYSQL_PASS}"

read -sp "Redis Password [auto-generated]: " REDIS_PASS
echo ""
REDIS_PASS="${REDIS_PASS:-$DEFAULT_REDIS_PASS}"

[[ -z "$API_DOMAIN" ]] && error "API domain required"
[[ -z "$PMA_DOMAIN" ]] && error "PMA domain required"
[[ -z "$ADMIN_EMAIL" ]] && error "Admin email required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ characters"

TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
log "Detected ${TOTAL_RAM}MB RAM and ${CPU_CORES} CPU cores"

FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

log "Starting installation..."

#===============================================================================
# SYSTEM PACKAGES
#===============================================================================
log "Updating system..."
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y

log "Installing essential packages..."
apt install -y software-properties-common curl wget git unzip zip \
    nginx mariadb-server redis-server certbot python3-certbot-nginx \
    pwgen htop ncdu fail2ban ufw jq acl rsync pigz pv lsof

add-apt-repository -y ppa:ondrej/php
apt update

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    log "Installing PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline 2>/dev/null || warn "PHP $V: some packages unavailable"
done

log "Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

log "Installing phpMyAdmin..."
PMA_VERSION="5.2.1"
wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.zip" -O /tmp/pma.zip || warn "phpMyAdmin download failed"
if [[ -f /tmp/pma.zip ]]; then
    unzip -qo /tmp/pma.zip -d /usr/share/
    rm -rf /usr/share/phpmyadmin
    mv /usr/share/phpMyAdmin-${PMA_VERSION}-all-languages /usr/share/phpmyadmin
    rm /tmp/pma.zip
    PMA_BLOWFISH=$(openssl rand -base64 32)
    cat > /usr/share/phpmyadmin/config.inc.php << PMAEOF
<?php
\$cfg['blowfish_secret'] = '${PMA_BLOWFISH}';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['auth_type'] = 'cookie';
\$cfg['Servers'][1]['compress'] = false;
\$cfg['Servers'][1]['AllowNoPassword'] = false;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '/tmp';
PMAEOF
    chown -R www-data:www-data /usr/share/phpmyadmin
    mkdir -p /usr/share/phpmyadmin/tmp && chmod 777 /usr/share/phpmyadmin/tmp
    log "phpMyAdmin installed"
fi

#===============================================================================
# SYSTEM USERS & GROUPS
#===============================================================================
log "Creating system users and groups..."
groupadd -f siteusers

if ! id "flyne-agent" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /opt/flyne -c "Flyne Engine Agent" flyne-agent
fi
usermod -aG www-data flyne-agent

#===============================================================================
# DIRECTORY STRUCTURE
#===============================================================================
log "Creating directories..."
mkdir -p ${FLYNE_DIR}/{backups,scripts,ssl,run,templates,tmp}
mkdir -p ${SITES_DIR}
mkdir -p /var/log/flyne
mkdir -p /var/cache/nginx/fastcgi/{global,sites}
mkdir -p /var/cache/opcache
mkdir -p /run/php
mkdir -p /etc/nginx/{cache-zones,sites-flyne,snippets}

chown flyne-agent:flyne-agent ${FLYNE_DIR}
chown -R flyne-agent:flyne-agent ${FLYNE_DIR}/{backups,scripts,ssl,run,templates,tmp}
chown www-data:www-data ${SITES_DIR}
chmod 755 ${SITES_DIR}

# Log directory - flyne-agent owns it so scripts can write
chown -R flyne-agent:www-data /var/log/flyne
chmod 775 /var/log/flyne

chown -R www-data:www-data /var/cache/nginx
chmod 755 /var/cache/nginx/fastcgi /var/cache/nginx/fastcgi/global /var/cache/nginx/fastcgi/sites
chmod 1777 /var/cache/opcache

touch /var/log/flyne/{api.log,wp-cron.log,agent.log,site-creation.log}
chown flyne-agent:www-data /var/log/flyne/*.log
chmod 664 /var/log/flyne/*.log

#===============================================================================
# MARIADB CONFIGURATION
#===============================================================================
log "Configuring MariaDB..."

if [[ $TOTAL_RAM -gt 16384 ]]; then
    INNODB_BUFFER="8G"; INNODB_LOG="1G"; MAX_CONN=200
elif [[ $TOTAL_RAM -gt 8192 ]]; then
    INNODB_BUFFER="4G"; INNODB_LOG="512M"; MAX_CONN=150
elif [[ $TOTAL_RAM -gt 4096 ]]; then
    INNODB_BUFFER="2G"; INNODB_LOG="256M"; MAX_CONN=100
elif [[ $TOTAL_RAM -gt 2048 ]]; then
    INNODB_BUFFER="1G"; INNODB_LOG="128M"; MAX_CONN=75
else
    INNODB_BUFFER="512M"; INNODB_LOG="64M"; MAX_CONN=50
fi

cat > /etc/mysql/mariadb.conf.d/99-flyne.cnf << MYSQLEOF
[mysqld]
innodb_buffer_pool_size = ${INNODB_BUFFER}
innodb_log_file_size = ${INNODB_LOG}
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
max_connections = ${MAX_CONN}
query_cache_type = 0
skip-log-bin
skip-name-resolve
max_allowed_packet = 64M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
MYSQLEOF

systemctl restart mariadb || error "MariaDB failed to start"

log "Securing MariaDB..."
mysql << SQLEOF
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
DROP USER IF EXISTS 'flyne_admin'@'localhost';
CREATE USER 'flyne_admin'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'flyne_admin'@'localhost' WITH GRANT OPTION;
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
CREATE DATABASE IF NOT EXISTS flyne_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
FLUSH PRIVILEGES;
SQLEOF

log "MariaDB configured"

#===============================================================================
# REDIS CONFIGURATION
#===============================================================================
log "Configuring Redis..."

REDIS_MEM=$((TOTAL_RAM * 10 / 100))
[[ $REDIS_MEM -lt 128 ]] && REDIS_MEM=128
[[ $REDIS_MEM -gt 1024 ]] && REDIS_MEM=1024

cat > /etc/redis/redis.conf << REDISEOF
bind 127.0.0.1 ::1
port 6379
protected-mode yes
unixsocket /run/redis/redis-server.sock
unixsocketperm 777
requirepass ${REDIS_PASS}
maxmemory ${REDIS_MEM}mb
maxmemory-policy volatile-lru
save ""
appendonly no
databases 256
loglevel notice
logfile /var/log/redis/redis-server.log
REDISEOF

mkdir -p /run/redis
chown redis:redis /run/redis
chmod 755 /run/redis

systemctl restart redis-server || error "Redis failed to start"
sleep 2
[[ -S /run/redis/redis-server.sock ]] && log "Redis socket ready" || warn "Redis socket not found"

#===============================================================================
# PHP-FPM CONFIGURATION
#===============================================================================
log "Configuring PHP-FPM..."

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    if [[ -d "/etc/php/${V}" ]]; then
        cat > "/etc/php/${V}/fpm/conf.d/99-flyne.ini" << PHPINI
memory_limit = 256M
max_execution_time = 300
max_input_time = 300
max_input_vars = 5000
post_max_size = 128M
upload_max_filesize = 128M
display_errors = Off
log_errors = On
expose_php = Off
cgi.fix_pathinfo = 0
PHPINI

        cat > "/etc/php/${V}/fpm/conf.d/10-opcache.ini" << OPCACHE
[opcache]
opcache.enable = 1
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 32
opcache.max_accelerated_files = 50000
opcache.validate_timestamps = 1
opcache.revalidate_freq = 60
OPCACHE

        rm -f "/etc/php/${V}/fpm/pool.d/www.conf"
        
        cat > "/etc/php/${V}/fpm/pool.d/flyne-api.conf" << APIPOOL
[flyne-api]
user = www-data
group = www-data
listen = /run/php/php${V}-fpm-api.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
pm.max_requests = 1000
php_admin_value[open_basedir] = /opt/flyne:/var/www/sites:/tmp:/usr/share/php:/usr/local/bin
APIPOOL

        systemctl restart php${V}-fpm 2>/dev/null || warn "PHP $V FPM restart failed"
    fi
done

#===============================================================================
# NGINX CONFIGURATION
#===============================================================================
log "Configuring Nginx..."

cat > /etc/nginx/nginx.conf << 'NGINXCONF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 128M;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" cache:$upstream_cache_status';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types application/javascript application/json application/xml text/css text/plain text/xml image/svg+xml;

    fastcgi_cache_path /var/cache/nginx/fastcgi/global levels=1:2 keys_zone=FLAVOR_GLOBAL:64m max_size=1g inactive=7d;
    include /etc/nginx/cache-zones/*.conf;

    fastcgi_cache_key "$scheme$request_method$host$request_uri";

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;

    limit_req_zone $binary_remote_addr zone=api:20m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_conn_zone $binary_remote_addr zone=connlimit:20m;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-flyne/*.conf;
}
NGINXCONF

cat > /etc/nginx/snippets/wordpress-security.conf << 'WPSEC'
location ~ /\.(?!well-known) { deny all; }
location ~* /(?:uploads|files)/.*\.php$ { deny all; }
location ~ /wp-config\.php$ { deny all; }
location = /xmlrpc.php { deny all; }
location ~* ^/wp-content/(?:uploads|cache)/.*\.php$ { deny all; }
location ~* \.(bak|config|sql|ini|log|sh|swp)$ { deny all; }
WPSEC

cat > /etc/nginx/snippets/wordpress-static.conf << 'WPSTATIC'
location ~* \.(jpg|jpeg|png|gif|ico|webp|avif)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    try_files $uri =404;
}
location ~* \.(css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    try_files $uri =404;
}
location ~* \.(woff|woff2|ttf|otf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Access-Control-Allow-Origin "*";
    try_files $uri =404;
}
WPSTATIC

# API Nginx Configuration
cat > /etc/nginx/sites-flyne/000-api.conf << APICONF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};
    
    root ${FLYNE_DIR};
    index index.php;
    
    location ~ /\\.(?!well-known) { deny all; }
    location /backups { deny all; }
    location /scripts { deny all; }
    location /templates { deny all; }
    location ~ \\.conf\$ { deny all; }
    location /credentials.txt { deny all; }
    
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    
    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm-api.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_USER "flyne_admin";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ADMIN_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
        fastcgi_read_timeout 900;
        fastcgi_send_timeout 900;
        fastcgi_buffers 32 32k;
        fastcgi_buffer_size 64k;
    }
    
    limit_req zone=api burst=100 nodelay;
}
APICONF

# phpMyAdmin Nginx Configuration
cat > /etc/nginx/sites-flyne/001-pma.conf << PMACONF
server {
    listen 80;
    listen [::]:80;
    server_name ${PMA_DOMAIN};
    
    root /usr/share/phpmyadmin;
    index index.php;
    
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    
    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm-api.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\\. { deny all; }
}
PMACONF

rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx configuration test failed"
systemctl restart nginx || error "Nginx failed to start"

#===============================================================================
# SSH/SFTP CONFIGURATION
#===============================================================================
log "Configuring secure SFTP..."

sed -i 's|^Subsystem.*sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config 2>/dev/null || \
    echo "Subsystem sftp internal-sftp" >> /etc/ssh/sshd_config

if ! grep -q "Match Group siteusers" /etc/ssh/sshd_config; then
    cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Flyne SFTP Configuration
Match Group siteusers
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0002
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
    PermitTunnel no
    AllowAgentForwarding no
SSHCONF
fi

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "SSH restart failed"

#===============================================================================
# SSL CERTIFICATES
#===============================================================================
log "Attempting SSL certificates..."
certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN} --email ${ADMIN_EMAIL} --agree-tos --non-interactive --redirect 2>/dev/null || \
    warn "SSL setup skipped - ensure DNS is configured, then run: certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN}"

#===============================================================================
# DATABASE SCHEMA
#===============================================================================
log "Creating database schema..."
mysql -u flyne_admin -p"${MYSQL_ADMIN_PASS}" flyne_engine << 'DBSCHEMA'
CREATE TABLE IF NOT EXISTS sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    site_user VARCHAR(64) NOT NULL,
    db_name VARCHAR(64) NOT NULL,
    db_user VARCHAR(64) NOT NULL,
    db_pass VARCHAR(255) NOT NULL,
    php_version VARCHAR(10) DEFAULT '8.4',
    status ENUM('active','suspended','creating','deleting','error') DEFAULT 'creating',
    ssl_enabled TINYINT(1) DEFAULT 0,
    redis_db INT DEFAULT 1,
    wp_admin_user VARCHAR(64) DEFAULT 'admin',
    wp_admin_email VARCHAR(255),
    disk_quota_mb INT DEFAULT 10240,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sftp_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    sftp_user VARCHAR(64) NOT NULL UNIQUE,
    is_enabled TINYINT(1) DEFAULT 1,
    expires_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    INDEX idx_site (site_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    type ENUM('full','files','database') DEFAULT 'full',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    site_id INT,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_site (site_id),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
DBSCHEMA

log "Database schema created"

#===============================================================================
# CONFIGURATION FILE
#===============================================================================
log "Creating configuration file..."
cat > "${FLYNE_DIR}/flyne.conf" << CONFEOF
# Flyne Engine Configuration v4.0
# Generated: $(date)

API_DOMAIN="${API_DOMAIN}"
PMA_DOMAIN="${PMA_DOMAIN}"
API_SECRET="${API_SECRET}"
MYSQL_USER="flyne_admin"
MYSQL_PASS="${MYSQL_ADMIN_PASS}"
REDIS_PASS="${REDIS_PASS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
SITES_DIR="${SITES_DIR}"
FLYNE_DIR="${FLYNE_DIR}"
DEFAULT_PHP="8.4"
TOTAL_RAM="${TOTAL_RAM}"
CPU_CORES="${CPU_CORES}"
CONFEOF
chmod 640 "${FLYNE_DIR}/flyne.conf"
chown flyne-agent:www-data "${FLYNE_DIR}/flyne.conf"

#===============================================================================
# CREATE-SITE SCRIPT (with all sudo commands)
#===============================================================================
log "Creating site management scripts..."

cat > "${FLYNE_DIR}/scripts/create-site.sh" << 'CREATESITE'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
PHP_VERSION="${2:-8.4}"
ADMIN_EMAIL="${3:-admin@$1}"
SITE_TITLE="${4:-$1}"
ADMIN_USER="${5:-admin}"

LOG="/var/log/flyne/site-creation.log"
SITES_DIR="/var/www/sites"
FLYNE_DIR="/opt/flyne"

source ${FLYNE_DIR}/flyne.conf

exec 2>>"$LOG"
echo "[$(date)] ========== Creating site: $DOMAIN ==========" >> "$LOG"

if [[ ! "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$ ]]; then
    echo '{"success":false,"error":"Invalid domain format"}'
    exit 1
fi

SAFE_NAME=$(echo "$DOMAIN" | tr '.-' '__' | cut -c1-32)
SITE_USER="wp_${SAFE_NAME}"
DB_NAME="wp_${SAFE_NAME}"
DB_USER="db_${SAFE_NAME}"
DB_PASS=$(openssl rand -hex 16)
WP_PASS=$(openssl rand -hex 8)
REDIS_DB=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COALESCE(MAX(redis_db), 0) + 1 FROM flyne_engine.sites" 2>/dev/null || echo 1)

SITE_DIR="${SITES_DIR}/${DOMAIN}"
PUBLIC_DIR="${SITE_DIR}/public"
LOGS_DIR="${SITE_DIR}/logs"
TMP_DIR="${SITE_DIR}/tmp"

DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/site-${DOMAIN_HASH}.sock"

echo "[$(date)] Creating user: $SITE_USER" >> "$LOG"

sudo useradd -r -d "$SITE_DIR" -s /usr/sbin/nologin -g www-data "$SITE_USER" 2>>"$LOG" || {
    if id "$SITE_USER" &>/dev/null; then
        echo "[$(date)] User already exists, continuing..." >> "$LOG"
    else
        echo '{"success":false,"error":"Failed to create system user"}'
        exit 1
    fi
}

echo "[$(date)] Creating directories" >> "$LOG"

sudo mkdir -p "$PUBLIC_DIR" "$LOGS_DIR" "$TMP_DIR"
sudo chown root:root "$SITE_DIR"
sudo chmod 755 "$SITE_DIR"
sudo chown -R "${SITE_USER}:www-data" "$PUBLIC_DIR" "$LOGS_DIR" "$TMP_DIR"
sudo chmod 2775 "$PUBLIC_DIR"
sudo chmod 750 "$LOGS_DIR" "$TMP_DIR"

sudo touch "$LOGS_DIR"/{access.log,error.log,php-error.log,php-slow.log}
sudo chown "${SITE_USER}:www-data" "$LOGS_DIR"/*.log
sudo chmod 664 "$LOGS_DIR"/*.log

echo "[$(date)] Creating database: $DB_NAME" >> "$LOG"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" << SQLEOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '${DB_USER}'@'localhost';
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

echo "[$(date)] Creating PHP-FPM pool" >> "$LOG"

AVAILABLE_RAM=$((TOTAL_RAM * 50 / 100))
SITE_COUNT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites" 2>/dev/null || echo 1)
SITE_COUNT=$((SITE_COUNT + 1))
MAX_CHILDREN=$((AVAILABLE_RAM / 64 / SITE_COUNT))
[[ $MAX_CHILDREN -lt 4 ]] && MAX_CHILDREN=4
[[ $MAX_CHILDREN -gt 20 ]] && MAX_CHILDREN=20
START_SERVERS=$((MAX_CHILDREN / 4))
[[ $START_SERVERS -lt 1 ]] && START_SERVERS=1
MIN_SPARE=$((MAX_CHILDREN / 8))
[[ $MIN_SPARE -lt 1 ]] && MIN_SPARE=1
MAX_SPARE=$((MAX_CHILDREN / 2))
[[ $MAX_SPARE -lt 2 ]] && MAX_SPARE=2

cat > "/tmp/pool-${DOMAIN}.conf" << POOLEOF
[${DOMAIN}]
user = ${SITE_USER}
group = www-data
listen = ${SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = ${MAX_CHILDREN}
pm.start_servers = ${START_SERVERS}
pm.min_spare_servers = ${MIN_SPARE}
pm.max_spare_servers = ${MAX_SPARE}
pm.max_requests = 1000

request_terminate_timeout = 300s
slowlog = ${LOGS_DIR}/php-slow.log

php_admin_value[open_basedir] = ${SITE_DIR}:/tmp:/usr/share/php:/dev/urandom
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[memory_limit] = 256M
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on
php_admin_value[session.save_handler] = redis
php_admin_value[session.save_path] = "unix:///run/redis/redis-server.sock?auth=${REDIS_PASS}&database=${REDIS_DB}"
POOLEOF
sudo mv "/tmp/pool-${DOMAIN}.conf" "/etc/php/${PHP_VERSION}/fpm/pool.d/${DOMAIN}.conf"

echo "[$(date)] Creating Nginx config" >> "$LOG"

SAFE_ZONE=$(echo "$DOMAIN" | tr '.-' '__')
CACHE_DIR="/var/cache/nginx/fastcgi/sites/${DOMAIN}"
sudo mkdir -p "$CACHE_DIR"
sudo chown www-data:www-data "$CACHE_DIR"

cat > "/tmp/cache-${DOMAIN}.conf" << CACHEEOF
fastcgi_cache_path ${CACHE_DIR} levels=1:2 keys_zone=CACHE_${SAFE_ZONE}:32m max_size=512m inactive=7d use_temp_path=off;
CACHEEOF
sudo mv "/tmp/cache-${DOMAIN}.conf" "/etc/nginx/cache-zones/${DOMAIN}.conf"

cat > "/tmp/nginx-${DOMAIN}.conf" << NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    root ${PUBLIC_DIR};
    index index.php index.html;

    access_log ${LOGS_DIR}/access.log;
    error_log ${LOGS_DIR}/error.log;

    include snippets/wordpress-security.conf;
    include snippets/wordpress-static.conf;

    set \$skip_cache 0;
    if (\$request_method = POST) { set \$skip_cache 1; }
    if (\$request_uri ~* "/wp-admin/|/wp-login.php") { set \$skip_cache 1; }
    if (\$http_cookie ~* "wordpress_logged_in") { set \$skip_cache 1; }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:${SOCKET};
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;

        fastcgi_cache CACHE_${SAFE_ZONE};
        fastcgi_cache_valid 200 60m;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;

        add_header X-Cache \$upstream_cache_status;
    }
}
NGINXEOF
sudo mv "/tmp/nginx-${DOMAIN}.conf" "/etc/nginx/sites-flyne/${DOMAIN}.conf"

echo "[$(date)] Downloading WordPress" >> "$LOG"

cd "$PUBLIC_DIR"
sudo -u "$SITE_USER" wp core download --path="$PUBLIC_DIR" >> "$LOG" 2>&1 || {
    echo '{"success":false,"error":"Failed to download WordPress"}'
    exit 1
}

echo "[$(date)] Creating wp-config.php" >> "$LOG"

cat > "/tmp/wp-config-${DOMAIN}.php" << WPCONFIGEOF
<?php
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_PASS}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

define('AUTH_KEY',         '$(openssl rand -hex 32)');
define('SECURE_AUTH_KEY',  '$(openssl rand -hex 32)');
define('LOGGED_IN_KEY',    '$(openssl rand -hex 32)');
define('NONCE_KEY',        '$(openssl rand -hex 32)');
define('AUTH_SALT',        '$(openssl rand -hex 32)');
define('SECURE_AUTH_SALT', '$(openssl rand -hex 32)');
define('LOGGED_IN_SALT',   '$(openssl rand -hex 32)');
define('NONCE_SALT',       '$(openssl rand -hex 32)');

\$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('DISALLOW_FILE_EDIT', true);
define('WP_MEMORY_LIMIT', '256M');

define('WP_REDIS_SCHEME', 'unix');
define('WP_REDIS_PATH', '/run/redis/redis-server.sock');
define('WP_REDIS_PASSWORD', '${REDIS_PASS}');
define('WP_REDIS_DATABASE', ${REDIS_DB});
define('WP_REDIS_PREFIX', '${SAFE_NAME}:');

if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
WPCONFIGEOF

sudo mv "/tmp/wp-config-${DOMAIN}.php" "${PUBLIC_DIR}/wp-config.php"
sudo chown "${SITE_USER}:www-data" "${PUBLIC_DIR}/wp-config.php"
sudo chmod 640 "${PUBLIC_DIR}/wp-config.php"

echo "[$(date)] Installing WordPress" >> "$LOG"

cd "$PUBLIC_DIR"
sudo -u "$SITE_USER" wp core install \
    --path="$PUBLIC_DIR" \
    --url="http://${DOMAIN}" \
    --title="$SITE_TITLE" \
    --admin_user="$ADMIN_USER" \
    --admin_email="$ADMIN_EMAIL" \
    --admin_password="$WP_PASS" \
    --skip-email >> "$LOG" 2>&1 || {
    echo '{"success":false,"error":"WordPress installation failed"}'
    exit 1
}

sudo chown -R "${SITE_USER}:www-data" "$PUBLIC_DIR"
sudo find "$PUBLIC_DIR" -type d -exec chmod 2775 {} \;
sudo find "$PUBLIC_DIR" -type f -exec chmod 664 {} \;
sudo chmod 640 "${PUBLIC_DIR}/wp-config.php"

echo "[$(date)] Registering in database" >> "$LOG"

echo "$SOCKET" > "${FLYNE_DIR}/run/${DOMAIN}.sock"
echo "$PHP_VERSION" > "${FLYNE_DIR}/run/${DOMAIN}.php"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine << SQLEOF
INSERT INTO sites (domain, site_user, db_name, db_user, db_pass, php_version, status, redis_db, wp_admin_user, wp_admin_email)
VALUES ('${DOMAIN}', '${SITE_USER}', '${DB_NAME}', '${DB_USER}', '${DB_PASS}', '${PHP_VERSION}', 'active', ${REDIS_DB}, '${ADMIN_USER}', '${ADMIN_EMAIL}');
SQLEOF

echo "[$(date)] Site files created: $DOMAIN" >> "$LOG"

cat > "/tmp/post-install-${DOMAIN}.sh" << POSTEOF
#!/bin/bash
sleep 2
echo "[\$(date)] Running post-install for ${DOMAIN}" >> "$LOG"

sudo systemctl reload "php${PHP_VERSION}-fpm" >> "$LOG" 2>&1
echo "[\$(date)] PHP-FPM reloaded" >> "$LOG"

sudo nginx -t >> "$LOG" 2>&1 && sudo systemctl reload nginx >> "$LOG" 2>&1
echo "[\$(date)] Nginx reloaded" >> "$LOG"

sleep 3

echo "[\$(date)] Attempting SSL for ${DOMAIN}" >> "$LOG"
if sudo certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos --email "${ADMIN_EMAIL}" --redirect >> "$LOG" 2>&1; then
    mysql -u "${MYSQL_USER}" -p"${MYSQL_PASS}" -e "UPDATE flyne_engine.sites SET ssl_enabled=1 WHERE domain='${DOMAIN}'" >> "$LOG" 2>&1
    echo "[\$(date)] SSL enabled for ${DOMAIN}" >> "$LOG"

    cd "${PUBLIC_DIR}"
    sudo -u "${SITE_USER}" wp option update siteurl "https://${DOMAIN}" --path="${PUBLIC_DIR}" >> "$LOG" 2>&1
    sudo -u "${SITE_USER}" wp option update home "https://${DOMAIN}" --path="${PUBLIC_DIR}" >> "$LOG" 2>&1
    echo "[\$(date)] WordPress URLs updated to HTTPS" >> "$LOG"
else
    echo "[\$(date)] SSL failed for ${DOMAIN} (DNS not ready?)" >> "$LOG"
fi

echo "[\$(date)] Post-install complete for ${DOMAIN}" >> "$LOG"
rm -f "/tmp/post-install-${DOMAIN}.sh"
POSTEOF

chmod +x "/tmp/post-install-${DOMAIN}.sh"

nohup /tmp/post-install-${DOMAIN}.sh > /dev/null 2>&1 &
disown

echo "[$(date)] Post-install scheduled for $DOMAIN" >> "$LOG"

cat << JSONEOF
{
    "success": true,
    "data": {
        "domain": "${DOMAIN}",
        "url": "http://${DOMAIN}",
        "admin_url": "http://${DOMAIN}/wp-admin/",
        "admin_user": "${ADMIN_USER}",
        "admin_pass": "${WP_PASS}",
        "admin_email": "${ADMIN_EMAIL}",
        "db_name": "${DB_NAME}",
        "db_user": "${DB_USER}",
        "db_pass": "${DB_PASS}",
        "php_version": "${PHP_VERSION}",
        "redis_db": ${REDIS_DB},
        "ssl_enabled": 0
    }
}
JSONEOF

exit 0
CREATESITE
chmod +x "${FLYNE_DIR}/scripts/create-site.sh"

#===============================================================================
# DELETE-SITE SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/delete-site.sh" << 'DELETESITE'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

source ${FLYNE_DIR}/flyne.conf

LOG="/var/log/flyne/site-creation.log"
echo "[$(date)] Deleting site: $DOMAIN" >> "$LOG"

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT site_user, db_name, db_user, php_version FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)

if [[ -z "$SITE_INFO" ]]; then
    echo '{"success":false,"error":"Site not found"}'
    exit 1
fi

read SITE_USER DB_NAME DB_USER PHP_VERSION <<< "$SITE_INFO"

SFTP_USER=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT sa.sftp_user FROM sftp_access sa JOIN sites s ON sa.site_id=s.id WHERE s.domain='${DOMAIN}'" 2>/dev/null || true)
if [[ -n "$SFTP_USER" ]]; then
    sudo userdel "$SFTP_USER" 2>/dev/null || true
fi

sudo userdel "$SITE_USER" 2>/dev/null || true

sudo rm -rf "${SITES_DIR}/${DOMAIN}"
sudo rm -f "/etc/nginx/sites-flyne/${DOMAIN}.conf"
sudo rm -f "/etc/nginx/cache-zones/${DOMAIN}.conf"
sudo rm -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${DOMAIN}.conf"
sudo rm -rf "/var/cache/nginx/fastcgi/sites/${DOMAIN}"
rm -f "${FLYNE_DIR}/run/${DOMAIN}.sock"
rm -f "${FLYNE_DIR}/run/${DOMAIN}.php"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" << SQLEOF
DROP DATABASE IF EXISTS \`${DB_NAME}\`;
DROP USER IF EXISTS '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "DELETE FROM flyne_engine.sites WHERE domain='${DOMAIN}'"

sudo systemctl reload "php${PHP_VERSION}-fpm" 2>/dev/null || true
sudo nginx -t && sudo systemctl reload nginx

echo "[$(date)] Site deleted: $DOMAIN" >> "$LOG"
echo '{"success":true,"message":"Site deleted successfully"}'
DELETESITE
chmod +x "${FLYNE_DIR}/scripts/delete-site.sh"

#===============================================================================
# PHP-SWITCH SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/php-switch.sh" << 'PHPSWITCH'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
NEW_VERSION="$2"
FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

source ${FLYNE_DIR}/flyne.conf

ALLOWED="7.4 8.0 8.1 8.2 8.3 8.4"
if [[ ! " $ALLOWED " =~ " $NEW_VERSION " ]]; then
    echo '{"success":false,"error":"Invalid PHP version"}'
    exit 1
fi

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT site_user, php_version, redis_db FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)

if [[ -z "$SITE_INFO" ]]; then
    echo '{"success":false,"error":"Site not found"}'
    exit 1
fi

read SITE_USER OLD_VERSION REDIS_DB <<< "$SITE_INFO"

if [[ "$OLD_VERSION" == "$NEW_VERSION" ]]; then
    echo '{"success":true,"message":"Already on this version"}'
    exit 0
fi

SITE_DIR="${SITES_DIR}/${DOMAIN}"
LOGS_DIR="${SITE_DIR}/logs"
DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/site-${DOMAIN_HASH}.sock"

AVAILABLE_RAM=$((TOTAL_RAM * 50 / 100))
SITE_COUNT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites" 2>/dev/null || echo 1)
MAX_CHILDREN=$((AVAILABLE_RAM / 64 / SITE_COUNT))
[[ $MAX_CHILDREN -lt 4 ]] && MAX_CHILDREN=4
[[ $MAX_CHILDREN -gt 20 ]] && MAX_CHILDREN=20
START_SERVERS=$((MAX_CHILDREN / 4)); [[ $START_SERVERS -lt 1 ]] && START_SERVERS=1
MIN_SPARE=$((MAX_CHILDREN / 8)); [[ $MIN_SPARE -lt 1 ]] && MIN_SPARE=1
MAX_SPARE=$((MAX_CHILDREN / 2)); [[ $MAX_SPARE -lt 2 ]] && MAX_SPARE=2

cat > "/tmp/pool-${DOMAIN}.conf" << POOLEOF
[${DOMAIN}]
user = ${SITE_USER}
group = www-data
listen = ${SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = ${MAX_CHILDREN}
pm.start_servers = ${START_SERVERS}
pm.min_spare_servers = ${MIN_SPARE}
pm.max_spare_servers = ${MAX_SPARE}
pm.max_requests = 1000
php_admin_value[open_basedir] = ${SITE_DIR}:/tmp:/usr/share/php:/dev/urandom
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[memory_limit] = 256M
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on
php_admin_value[session.save_handler] = redis
php_admin_value[session.save_path] = "unix:///run/redis/redis-server.sock?auth=${REDIS_PASS}&database=${REDIS_DB}"
POOLEOF

sudo mv "/tmp/pool-${DOMAIN}.conf" "/etc/php/${NEW_VERSION}/fpm/pool.d/${DOMAIN}.conf"
sudo rm -f "/etc/php/${OLD_VERSION}/fpm/pool.d/${DOMAIN}.conf"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
    "UPDATE flyne_engine.sites SET php_version='${NEW_VERSION}' WHERE domain='${DOMAIN}'"

echo "$NEW_VERSION" > "${FLYNE_DIR}/run/${DOMAIN}.php"

sudo systemctl reload "php${NEW_VERSION}-fpm"
sudo systemctl reload "php${OLD_VERSION}-fpm" 2>/dev/null || true

echo "{\"success\":true,\"old_version\":\"${OLD_VERSION}\",\"new_version\":\"${NEW_VERSION}\"}"
PHPSWITCH
chmod +x "${FLYNE_DIR}/scripts/php-switch.sh"

#===============================================================================
# SFTP-ENABLE SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/sftp-enable.sh" << 'SFTPENABLE'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
EXPIRE="${2:-never}"
FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

source ${FLYNE_DIR}/flyne.conf

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)

if [[ -z "$SITE_INFO" ]]; then
    echo '{"success":false,"error":"Site not found"}'
    exit 1
fi

read SITE_ID SITE_USER <<< "$SITE_INFO"

SITE_DIR="${SITES_DIR}/${DOMAIN}"
SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.-' '__' | cut -c1-20)
SFTP_USER="sftp_${SAFE_DOMAIN}"
SFTP_PASS=$(openssl rand -hex 12)

case "$EXPIRE" in
    1h)  EXPIRES_AT=$(date -d '+1 hour' '+%Y-%m-%d %H:%M:%S') ;;
    24h) EXPIRES_AT=$(date -d '+24 hours' '+%Y-%m-%d %H:%M:%S') ;;
    7d)  EXPIRES_AT=$(date -d '+7 days' '+%Y-%m-%d %H:%M:%S') ;;
    30d) EXPIRES_AT=$(date -d '+30 days' '+%Y-%m-%d %H:%M:%S') ;;
    *)   EXPIRES_AT="NULL" ;;
esac

EXISTING=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT sftp_user FROM flyne_engine.sftp_access WHERE site_id=${SITE_ID}" 2>/dev/null || true)

if [[ -n "$EXISTING" ]]; then
    SFTP_USER="$EXISTING"
    sudo usermod -U "$SFTP_USER" 2>/dev/null || true
    echo "${SFTP_USER}:${SFTP_PASS}" | sudo chpasswd
    
    if [[ "$EXPIRES_AT" == "NULL" ]]; then
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
            "UPDATE flyne_engine.sftp_access SET is_enabled=1, expires_at=NULL WHERE site_id=${SITE_ID}"
    else
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
            "UPDATE flyne_engine.sftp_access SET is_enabled=1, expires_at='${EXPIRES_AT}' WHERE site_id=${SITE_ID}"
    fi
else
    sudo useradd -d "$SITE_DIR" -s /usr/sbin/nologin -g siteusers "$SFTP_USER"
    echo "${SFTP_USER}:${SFTP_PASS}" | sudo chpasswd
    sudo usermod -aG www-data "$SFTP_USER"
    
    sudo chown root:root "$SITE_DIR"
    sudo chmod 755 "$SITE_DIR"
    sudo setfacl -R -m u:${SFTP_USER}:rwx "${SITE_DIR}/public" 2>/dev/null || true
    
    if [[ "$EXPIRES_AT" == "NULL" ]]; then
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
            "INSERT INTO flyne_engine.sftp_access (site_id, sftp_user, is_enabled) VALUES (${SITE_ID}, '${SFTP_USER}', 1)"
    else
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
            "INSERT INTO flyne_engine.sftp_access (site_id, sftp_user, is_enabled, expires_at) VALUES (${SITE_ID}, '${SFTP_USER}', 1, '${EXPIRES_AT}')"
    fi
fi

HOSTNAME=$(hostname -f 2>/dev/null || hostname)

cat << JSONEOF
{
    "success": true,
    "data": {
        "host": "${HOSTNAME}",
        "port": 22,
        "username": "${SFTP_USER}",
        "password": "${SFTP_PASS}",
        "path": "/public",
        "expires_at": $([ "$EXPIRES_AT" == "NULL" ] && echo "null" || echo "\"${EXPIRES_AT}\"")
    }
}
JSONEOF
SFTPENABLE
chmod +x "${FLYNE_DIR}/scripts/sftp-enable.sh"

#===============================================================================
# SFTP-DISABLE SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/sftp-disable.sh" << 'SFTPDISABLE'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
FLYNE_DIR="/opt/flyne"

source ${FLYNE_DIR}/flyne.conf

SITE_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)

if [[ -z "$SITE_ID" ]]; then
    echo '{"success":false,"error":"Site not found"}'
    exit 1
fi

SFTP_USER=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT sftp_user FROM flyne_engine.sftp_access WHERE site_id=${SITE_ID}" 2>/dev/null)

if [[ -z "$SFTP_USER" ]]; then
    echo '{"success":false,"error":"SFTP not configured"}'
    exit 1
fi

sudo usermod -L "$SFTP_USER"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
    "UPDATE flyne_engine.sftp_access SET is_enabled=0 WHERE site_id=${SITE_ID}"

echo '{"success":true,"message":"SFTP access disabled"}'
SFTPDISABLE
chmod +x "${FLYNE_DIR}/scripts/sftp-disable.sh"

#===============================================================================
# CACHE-PURGE SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/cache-purge.sh" << 'CACHEPURGE'
#!/bin/bash
DOMAIN="$1"
FLYNE_DIR="/opt/flyne"

source ${FLYNE_DIR}/flyne.conf

if [[ -n "$DOMAIN" ]]; then
    REDIS_DB=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
        "SELECT redis_db FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)
    
    sudo rm -rf "/var/cache/nginx/fastcgi/sites/${DOMAIN}" 2>/dev/null
    sudo mkdir -p "/var/cache/nginx/fastcgi/sites/${DOMAIN}"
    sudo chown www-data:www-data "/var/cache/nginx/fastcgi/sites/${DOMAIN}"
    
    if [[ -n "$REDIS_DB" ]]; then
        redis-cli -s /run/redis/redis-server.sock -a "$REDIS_PASS" -n "$REDIS_DB" FLUSHDB 2>/dev/null
    fi
    
    echo "{\"success\":true,\"message\":\"Cache purged for ${DOMAIN}\"}"
else
    sudo find /var/cache/nginx/fastcgi -type f -delete 2>/dev/null
    echo '{"success":true,"message":"Global cache purged"}'
fi
CACHEPURGE
chmod +x "${FLYNE_DIR}/scripts/cache-purge.sh"

#===============================================================================
# WP-CLI SCRIPT
#===============================================================================
cat > "${FLYNE_DIR}/scripts/wp-cli.sh" << 'WPCLI'
#!/bin/bash
set -uo pipefail

DOMAIN="$1"
shift
COMMAND="$@"
FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

source ${FLYNE_DIR}/flyne.conf

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT site_user, php_version FROM flyne_engine.sites WHERE domain='${DOMAIN}'" 2>/dev/null)

if [[ -z "$SITE_INFO" ]]; then
    echo '{"success":false,"error":"Site not found"}'
    exit 1
fi

read SITE_USER PHP_VERSION <<< "$SITE_INFO"

PUBLIC_DIR="${SITES_DIR}/${DOMAIN}/public"

BLOCKED="eval eval-file shell db drop db reset"
for B in $BLOCKED; do
    if [[ "$COMMAND" == *"$B"* ]]; then
        echo "{\"success\":false,\"error\":\"Command blocked: $B\"}"
        exit 1
    fi
done

OUTPUT=$(sudo -u "$SITE_USER" /usr/bin/php${PHP_VERSION} /usr/local/bin/wp $COMMAND --path="$PUBLIC_DIR" 2>&1) || true
EXIT_CODE=$?

if [[ "$OUTPUT" == "["* ]] || [[ "$OUTPUT" == "{"* ]]; then
    echo "{\"success\":true,\"exit_code\":${EXIT_CODE},\"output\":${OUTPUT}}"
else
    ESCAPED=$(echo "$OUTPUT" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr '\n' ' ')
    echo "{\"success\":true,\"exit_code\":${EXIT_CODE},\"output\":\"${ESCAPED}\"}"
fi
WPCLI
chmod +x "${FLYNE_DIR}/scripts/wp-cli.sh"

# Set ownership for all scripts
chown -R flyne-agent:flyne-agent "${FLYNE_DIR}/scripts"

#===============================================================================
# SUDOERS CONFIGURATION - CRITICAL FOR API TO WORK
#===============================================================================
log "Configuring sudo permissions..."

cat > /etc/sudoers.d/flyne << 'SUDOERS'
# Flyne Engine Sudoers Configuration

# flyne-agent has full sudo (needed for site management)
flyne-agent ALL=(ALL) NOPASSWD: ALL

# www-data can run flyne scripts as flyne-agent
www-data ALL=(flyne-agent) NOPASSWD: /bin/bash /opt/flyne/scripts/*.sh *
SUDOERS
chmod 440 /etc/sudoers.d/flyne
visudo -cf /etc/sudoers.d/flyne || error "Sudoers syntax error"

#===============================================================================
# CRON JOBS
#===============================================================================
log "Setting up cron jobs..."

cat > /etc/cron.d/flyne << 'CRONFILE'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Clean old cache files
0 3 * * * root find /var/cache/nginx/fastcgi -type f -mtime +7 -delete 2>/dev/null

# Clean old backups
0 4 * * 0 root find /opt/flyne/backups -type f -mtime +30 -delete 2>/dev/null

# SSL renewal
0 */12 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"
CRONFILE
chmod 644 /etc/cron.d/flyne

#===============================================================================
# FAIL2BAN
#===============================================================================
log "Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.local << 'F2BJAIL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true

[wordpress]
enabled = true
filter = wordpress
logpath = /var/www/sites/*/logs/access.log
maxretry = 5
bantime = 3600
F2BJAIL

cat > /etc/fail2ban/filter.d/wordpress.conf << 'F2BFILTER'
[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php
            ^<HOST> .* "POST /xmlrpc\.php
ignoreregex =
F2BFILTER

systemctl enable fail2ban
systemctl restart fail2ban || warn "Fail2ban restart failed"

#===============================================================================
# FIREWALL
#===============================================================================
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

#===============================================================================
# KERNEL TUNING
#===============================================================================
log "Applying kernel optimizations..."
cat > /etc/sysctl.d/99-flyne.conf << 'SYSCTL'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
vm.swappiness = 10
fs.file-max = 2097152
SYSCTL
sysctl -p /etc/sysctl.d/99-flyne.conf 2>/dev/null || warn "Some sysctl params failed"

cat > /etc/security/limits.d/flyne.conf << 'LIMITS'
* soft nofile 65535
* hard nofile 65535
www-data soft nofile 65535
www-data hard nofile 65535
flyne-agent soft nofile 65535
flyne-agent hard nofile 65535
LIMITS

#===============================================================================
# LOGROTATE
#===============================================================================
cat > /etc/logrotate.d/flyne << 'LOGROTATE'
/var/log/flyne/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 664 flyne-agent www-data
}

/var/www/sites/*/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) 2>/dev/null || true
    endscript
}
LOGROTATE

#===============================================================================
# CLI TOOL
#===============================================================================
log "Installing CLI tool..."

cat > /usr/local/bin/flyne << 'CLIEOF'
#!/bin/bash
source /opt/flyne/flyne.conf 2>/dev/null || { echo "Flyne not configured"; exit 1; }

case "$1" in
    status)
        echo "=== Flyne Engine v4.0 Status ==="
        for svc in nginx mariadb redis-server; do
            systemctl is-active --quiet $svc && echo "$svc: Running" || echo "$svc: Stopped"
        done
        for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
            systemctl is-active --quiet php${v}-fpm 2>/dev/null && echo "PHP ${v}-FPM: Running"
        done
        SITE_COUNT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites WHERE status='active'" 2>/dev/null || echo 0)
        echo ""
        echo "Active Sites: ${SITE_COUNT}"
        echo "API: https://${API_DOMAIN}"
        ;;
    sites)
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "SELECT domain, php_version, status, ssl_enabled, created_at FROM flyne_engine.sites ORDER BY created_at DESC" 2>/dev/null
        ;;
    create)
        [[ -z "$2" ]] && { echo "Usage: flyne create domain.com [email]"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne/scripts/create-site.sh "$2" "8.4" "${3:-admin@$2}"
        ;;
    delete)
        [[ -z "$2" ]] && { echo "Usage: flyne delete domain.com"; exit 1; }
        read -p "Delete $2? [y/N] " confirm
        [[ "$confirm" != "y" ]] && exit 0
        sudo -u flyne-agent /bin/bash /opt/flyne/scripts/delete-site.sh "$2"
        ;;
    cache-clear)
        sudo -u flyne-agent /bin/bash /opt/flyne/scripts/cache-purge.sh "$2"
        ;;
    test)
        echo "Testing API..."
        curl -sk "https://${API_DOMAIN}/index.php?action=site_list" -H "Authorization: Bearer ${API_SECRET}" | jq . 2>/dev/null || echo "API test failed"
        ;;
    logs)
        [[ -z "$2" ]] && tail -f /var/log/flyne/*.log || tail -f /var/www/sites/$2/logs/*.log
        ;;
    *)
        echo "Flyne Engine CLI v4.0"
        echo ""
        echo "Commands:"
        echo "  status              System status"
        echo "  sites               List sites"
        echo "  create <domain>     Create WordPress site"
        echo "  delete <domain>     Delete site"
        echo "  cache-clear [site]  Clear cache"
        echo "  test                Test API"
        echo "  logs [domain]       View logs"
        ;;
esac
CLIEOF
chmod +x /usr/local/bin/flyne

#===============================================================================
# DOWNLOAD API FILE
#===============================================================================
log "Downloading API file..."
API_URL="https://raw.githubusercontent.com/Flynecom/flyne/main/index.php"

if curl -fsSL "$API_URL" -o "${FLYNE_DIR}/index.php"; then
    chown www-data:www-data "${FLYNE_DIR}/index.php"
    chmod 644 "${FLYNE_DIR}/index.php"
    log "API file downloaded successfully"
else
    warn "Failed to download API file from GitHub"
    warn "Please manually download index.php to ${FLYNE_DIR}/index.php"
fi

#===============================================================================
# SAVE CREDENTIALS
#===============================================================================
log "Saving credentials..."

cat > "${FLYNE_DIR}/credentials.txt" << CREDEOF
=== FLYNE ENGINE v4.0 CREDENTIALS ===
Generated: $(date)

API Domain:    https://${API_DOMAIN}
PMA Domain:    https://${PMA_DOMAIN}

API Secret:    ${API_SECRET}
MySQL User:    flyne_admin
MySQL Pass:    ${MYSQL_ADMIN_PASS}
Redis Pass:    ${REDIS_PASS}
Admin Email:   ${ADMIN_EMAIL}

CLI Commands:
  flyne status          - Check system status
  flyne sites           - List all sites
  flyne create domain   - Create WordPress site
  flyne delete domain   - Delete site
  flyne cache-clear     - Clear cache
  flyne test            - Test API

DELETE THIS FILE AFTER SAVING CREDENTIALS SECURELY!
CREDEOF
chmod 600 "${FLYNE_DIR}/credentials.txt"
chown flyne-agent:flyne-agent "${FLYNE_DIR}/credentials.txt"

#===============================================================================
# FINAL VERIFICATION
#===============================================================================
log "Verifying installation..."

nginx -t || error "Nginx config invalid"
systemctl is-active --quiet mariadb || error "MariaDB not running"
systemctl is-active --quiet redis-server || error "Redis not running"
systemctl is-active --quiet php8.4-fpm || error "PHP 8.4 FPM not running"
mysql -u flyne_admin -p"${MYSQL_ADMIN_PASS}" -e "SELECT 1" >/dev/null 2>&1 || error "MySQL connection failed"
redis-cli -s /run/redis/redis-server.sock -a "${REDIS_PASS}" PING >/dev/null 2>&1 || error "Redis connection failed"

log "All services verified!"

#===============================================================================
# FINAL OUTPUT
#===============================================================================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   FLYNE ENGINE v4.0 INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${BLUE}URLs:${NC}"
echo -e "  API:        ${CYAN}https://${API_DOMAIN}${NC}"
echo -e "  phpMyAdmin: ${CYAN}https://${PMA_DOMAIN}${NC}"
echo ""
echo -e "${RED}================================================================${NC}"
echo -e "${RED}   CREDENTIALS - SAVE SECURELY!${NC}"
echo -e "${RED}================================================================${NC}"
echo ""
echo -e "  API Secret:     ${YELLOW}${API_SECRET}${NC}"
echo -e "  MySQL User:     ${YELLOW}flyne_admin${NC}"
echo -e "  MySQL Pass:     ${YELLOW}${MYSQL_ADMIN_PASS}${NC}"
echo -e "  Redis Password: ${YELLOW}${REDIS_PASS}${NC}"
echo ""
echo -e "Credentials file: ${YELLOW}${FLYNE_DIR}/credentials.txt${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo "  flyne status          - Check system status"
echo "  flyne test            - Test API connection"
echo "  flyne create site.com - Create WordPress site"
echo ""
log "Installation complete!"