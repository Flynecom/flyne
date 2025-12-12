#!/bin/bash
#===============================================================================
# FLYNE ENGINE - High-Performance WordPress Hosting Platform
# Single-command installer for Ubuntu 22.04/24.04
# Optimized for speed, security, and user isolation
#===============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${GREEN}[FLYNE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    error "Cannot detect OS"
fi

[[ "$OS" != "ubuntu" ]] && error "Only Ubuntu 22.04/24.04 supported"

clear
echo -e "${BLUE}"
cat << "EOF"
   _____ _                        _____            _            
  |  ___| |_   _ _ __   ___      | ____|_ __   __ _(_)_ __   ___ 
  | |_  | | | | | '_ \ / _ \_____|  _| | '_ \ / _` | | '_ \ / _ \
  |  _| | | |_| | | | |  __/_____| |___| | | | (_| | | | | |  __/
  |_|   |_|\__, |_| |_|\___|     |_____|_| |_|\__, |_|_| |_|\___|
           |___/                              |___/              
  High-Performance WordPress Hosting Engine v2.0
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

# Generate secure defaults
DEFAULT_API_SECRET=$(openssl rand -hex 32)
DEFAULT_MYSQL_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
DEFAULT_REDIS_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 24)

echo ""
echo -e "${YELLOW}Generated secure defaults (press Enter to use):${NC}"
read -p "API Secret [$DEFAULT_API_SECRET]: " API_SECRET
API_SECRET=${API_SECRET:-$DEFAULT_API_SECRET}

read -sp "MySQL Root Password [$DEFAULT_MYSQL_PASS]: " MYSQL_ROOT_PASS
MYSQL_ROOT_PASS=${MYSQL_ROOT_PASS:-$DEFAULT_MYSQL_PASS}
echo ""

read -sp "Redis Password [$DEFAULT_REDIS_PASS]: " REDIS_PASS
REDIS_PASS=${REDIS_PASS:-$DEFAULT_REDIS_PASS}
echo ""

[[ -z "$API_DOMAIN" ]] && error "API domain required"
[[ -z "$PMA_DOMAIN" ]] && error "PMA domain required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ characters"

# Detect RAM for tuning
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
log "Detected ${TOTAL_RAM}MB RAM - will tune accordingly"

FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

log "Starting installation..."

#===============================================================================
# SYSTEM PACKAGES
#===============================================================================
log "Updating system..."
export DEBIAN_FRONTEND=noninteractive
apt update && apt upgrade -y

log "Installing packages..."
apt install -y software-properties-common curl wget git unzip zip \
    nginx mariadb-server redis-server certbot python3-certbot-nginx \
    pwgen htop ncdu fail2ban ufw jq acl rsync pigz pv \
    libpam-pwquality libpam-google-authenticator

# PHP repository
add-apt-repository -y ppa:ondrej/php
apt update

# Install all PHP versions with extensions
for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    log "Installing PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline php${V}-apcu 2>/dev/null || warn "PHP $V partially installed"
done

# WP-CLI
log "Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

# phpMyAdmin latest
log "Installing phpMyAdmin..."
PMA_VERSION="5.2.1"
wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.zip" -O /tmp/pma.zip
unzip -qo /tmp/pma.zip -d /usr/share/
rm -rf /usr/share/phpmyadmin
mv /usr/share/phpMyAdmin-${PMA_VERSION}-all-languages /usr/share/phpmyadmin
rm /tmp/pma.zip

# Configure phpMyAdmin
PMA_BLOWFISH=$(openssl rand -base64 32)
cat > /usr/share/phpmyadmin/config.inc.php << EOF
<?php
\$cfg['blowfish_secret'] = '${PMA_BLOWFISH}';
\$cfg['Servers'][1]['host'] = 'localhost';
\$cfg['Servers'][1]['auth_type'] = 'cookie';
\$cfg['Servers'][1]['compress'] = false;
\$cfg['Servers'][1]['AllowNoPassword'] = false;
\$cfg['UploadDir'] = '';
\$cfg['SaveDir'] = '';
\$cfg['TempDir'] = '/tmp';
\$cfg['MaxRows'] = 50;
\$cfg['SendErrorReports'] = 'never';
\$cfg['ShowDatabasesNavigationAsTree'] = true;
EOF
chown -R www-data:www-data /usr/share/phpmyadmin
mkdir -p /usr/share/phpmyadmin/tmp && chmod 777 /usr/share/phpmyadmin/tmp

#===============================================================================
# DIRECTORY STRUCTURE
#===============================================================================
log "Creating directories..."
mkdir -p $FLYNE_DIR/{backups,scripts,ssl}
mkdir -p $SITES_DIR
mkdir -p /var/log/flyne
mkdir -p /tmp/nginx-cache
mkdir -p /run/php

# Create siteusers group for SFTP
groupadd -f siteusers

chown www-data:www-data /var/log/flyne
chmod 750 /var/log/flyne

#===============================================================================
# MARIADB - OPTIMIZED
#===============================================================================
log "Configuring MariaDB..."

# Calculate buffer pool size (50% of RAM, max 4GB for single sites)
if [[ $TOTAL_RAM -gt 8192 ]]; then
    INNODB_BUFFER="4G"
    INNODB_LOG="512M"
    MAX_CONN=500
elif [[ $TOTAL_RAM -gt 4096 ]]; then
    INNODB_BUFFER="2G"
    INNODB_LOG="256M"
    MAX_CONN=300
elif [[ $TOTAL_RAM -gt 2048 ]]; then
    INNODB_BUFFER="1G"
    INNODB_LOG="128M"
    MAX_CONN=200
else
    INNODB_BUFFER="512M"
    INNODB_LOG="64M"
    MAX_CONN=100
fi

cat > /etc/mysql/mariadb.conf.d/99-flyne-optimized.cnf << EOF
[mysqld]
# === InnoDB Settings ===
innodb_buffer_pool_size = ${INNODB_BUFFER}
innodb_log_file_size = ${INNODB_LOG}
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_stats_on_metadata = 0
innodb_buffer_pool_instances = 4
innodb_read_io_threads = 4
innodb_write_io_threads = 4
innodb_io_capacity = 2000
innodb_io_capacity_max = 4000

# === Query Cache (MariaDB) ===
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 4M
query_cache_min_res_unit = 2K

# === Connection Settings ===
max_connections = ${MAX_CONN}
max_user_connections = 50
wait_timeout = 60
interactive_timeout = 60
thread_cache_size = 50

# === Buffer Settings ===
join_buffer_size = 4M
sort_buffer_size = 4M
read_buffer_size = 2M
read_rnd_buffer_size = 2M
tmp_table_size = 64M
max_heap_table_size = 64M

# === Logging ===
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 0

# === Security ===
skip-name-resolve
local_infile = 0
symbolic-links = 0
secure_file_priv = /tmp

# === Character Set ===
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF

systemctl restart mariadb

# Secure installation
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';"
mysql -u root -p"${MYSQL_ROOT_PASS}" << EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
CREATE DATABASE IF NOT EXISTS flyne_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
FLUSH PRIVILEGES;
EOF

#===============================================================================
# REDIS - OPTIMIZED
#===============================================================================
log "Configuring Redis..."

# Calculate Redis memory (10% of RAM)
REDIS_MEM=$((TOTAL_RAM / 10))
[[ $REDIS_MEM -lt 128 ]] && REDIS_MEM=128
[[ $REDIS_MEM -gt 1024 ]] && REDIS_MEM=1024

cat > /etc/redis/redis.conf << EOF
# Network
bind 127.0.0.1 ::1
port 6379
protected-mode yes
tcp-backlog 511
unixsocket /run/redis/redis-server.sock
unixsocketperm 770

# Security
requirepass ${REDIS_PASS}

# Memory
maxmemory ${REDIS_MEM}mb
maxmemory-policy allkeys-lru
maxmemory-samples 10

# Persistence (disabled for cache)
save ""
appendonly no

# Performance
tcp-keepalive 300
timeout 0
databases 100

# Snapshotting disabled for speed
stop-writes-on-bgsave-error no

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
EOF

usermod -aG redis www-data
systemctl restart redis-server

#===============================================================================
# PHP-FPM - OPTIMIZED FOR EACH VERSION
#===============================================================================
log "Optimizing PHP-FPM..."

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    if systemctl is-enabled php${V}-fpm &>/dev/null; then
        # Global PHP.ini optimizations
        PHP_INI="/etc/php/${V}/fpm/php.ini"
        if [[ -f "$PHP_INI" ]]; then
            sed -i 's/^memory_limit.*/memory_limit = 256M/' "$PHP_INI"
            sed -i 's/^upload_max_filesize.*/upload_max_filesize = 128M/' "$PHP_INI"
            sed -i 's/^post_max_size.*/post_max_size = 128M/' "$PHP_INI"
            sed -i 's/^max_execution_time.*/max_execution_time = 300/' "$PHP_INI"
            sed -i 's/^max_input_time.*/max_input_time = 300/' "$PHP_INI"
            sed -i 's/^max_input_vars.*/max_input_vars = 5000/' "$PHP_INI"
            sed -i 's/^;*realpath_cache_size.*/realpath_cache_size = 4096K/' "$PHP_INI"
            sed -i 's/^;*realpath_cache_ttl.*/realpath_cache_ttl = 600/' "$PHP_INI"
        fi

        # OPcache configuration
        OPCACHE_CONF="/etc/php/${V}/fpm/conf.d/10-opcache.ini"
        cat > "$OPCACHE_CONF" << 'OPCACHE'
[opcache]
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=256
opcache.interned_strings_buffer=32
opcache.max_accelerated_files=50000
opcache.max_wasted_percentage=10
opcache.revalidate_freq=2
opcache.fast_shutdown=1
opcache.save_comments=1
opcache.enable_file_override=1
opcache.validate_timestamps=1
opcache.huge_code_pages=0
opcache.jit_buffer_size=128M
opcache.jit=1255
OPCACHE

        # APCu configuration
        APCU_CONF="/etc/php/${V}/fpm/conf.d/20-apcu.ini"
        cat > "$APCU_CONF" << 'APCU'
[apcu]
extension=apcu.so
apc.enabled=1
apc.shm_size=64M
apc.ttl=7200
apc.gc_ttl=3600
apc.entries_hint=4096
apc.slam_defense=1
apc.enable_cli=0
APCU

        # Default pool optimization
        cat > "/etc/php/${V}/fpm/pool.d/www.conf" << POOL
[www]
user = www-data
group = www-data
listen = /run/php/php${V}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 20
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 6
pm.max_requests = 1000
pm.process_idle_timeout = 10s

request_terminate_timeout = 300
rlimit_files = 65535

php_admin_value[error_log] = /var/log/php${V}-fpm.log
php_admin_flag[log_errors] = on
POOL

        systemctl restart php${V}-fpm
    fi
done

#===============================================================================
# NGINX - HIGH PERFORMANCE
#===============================================================================
log "Configuring Nginx for high performance..."

# Determine worker processes
CPU_CORES=$(nproc)
WORKER_CONN=$((4096 * CPU_CORES))

cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections ${WORKER_CONN};
    multi_accept on;
    use epoll;
}

http {
    # === Basic Settings ===
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_tokens off;
    reset_timedout_connection on;

    # === MIME Types ===
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # === Buffer Settings ===
    client_body_buffer_size 128k;
    client_max_body_size 128M;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 32k;
    output_buffers 2 32k;
    postpone_output 1460;

    # === Timeouts ===
    client_body_timeout 30;
    client_header_timeout 30;
    send_timeout 30;
    proxy_connect_timeout 60;
    proxy_send_timeout 60;
    proxy_read_timeout 60;

    # === Logging ===
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" \$request_time \$upstream_response_time';
    
    access_log /var/log/nginx/access.log main buffer=16k flush=2m;
    error_log /var/log/nginx/error.log warn;

    # === Gzip Compression ===
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types
        application/atom+xml
        application/geo+json
        application/javascript
        application/x-javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rdf+xml
        application/rss+xml
        application/xhtml+xml
        application/xml
        font/eot
        font/otf
        font/ttf
        font/woff
        font/woff2
        image/svg+xml
        text/css
        text/javascript
        text/plain
        text/xml;

    # === Brotli (if available) ===
    # brotli on;
    # brotli_comp_level 6;
    # brotli_types text/plain text/css application/json application/javascript;

    # === FastCGI Cache ===
    fastcgi_cache_path /tmp/nginx-cache 
        levels=1:2 
        keys_zone=WORDPRESS:256m 
        max_size=4g 
        inactive=7d 
        use_temp_path=off;
    fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
    fastcgi_cache_use_stale error timeout updating http_500 http_503;
    fastcgi_cache_background_update on;
    fastcgi_cache_lock on;
    fastcgi_cache_lock_timeout 5s;
    fastcgi_cache_valid 200 301 302 1h;
    fastcgi_cache_valid 404 1m;
    fastcgi_ignore_headers Cache-Control Expires Set-Cookie;

    # === Open File Cache ===
    open_file_cache max=50000 inactive=60s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # === Security Headers ===
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # === Rate Limiting ===
    limit_req_zone \$binary_remote_addr zone=api:10m rate=100r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone \$binary_remote_addr zone=general:10m rate=50r/s;
    limit_conn_zone \$binary_remote_addr zone=connlimit:10m;

    # === SSL Settings ===
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    # === Upstream PHP ===
    upstream php84 {
        server unix:/run/php/php8.4-fpm.sock;
        keepalive 16;
    }

    # === Map for Cache Bypass ===
    map \$request_uri \$skip_cache {
        default 0;
        ~*/wp-admin 1;
        ~*/wp-login.php 1;
        ~*/xmlrpc.php 1;
        ~*sitemap 1;
        ~*/feed 1;
        ~*/cart 1;
        ~*/checkout 1;
        ~*/my-account 1;
    }

    map \$http_cookie \$skip_cache_cookie {
        default 0;
        ~*wordpress_logged_in 1;
        ~*wp-postpass 1;
        ~*woocommerce_cart_hash 1;
        ~*woocommerce_items_in_cart 1;
        ~*comment_author 1;
    }

    map \$request_method \$skip_cache_method {
        default 0;
        POST 1;
        PUT 1;
        DELETE 1;
    }

    # === Includes ===
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-flyne/*.conf;
}
EOF

mkdir -p /etc/nginx/sites-flyne
mkdir -p /etc/nginx/snippets

# WordPress security snippet
cat > /etc/nginx/snippets/wordpress-security.conf << 'EOF'
# Block access to sensitive files
location ~ /\.(?!well-known) { deny all; }
location ~* /(?:uploads|files)/.*\.php$ { deny all; }
location ~ /wp-config\.php$ { deny all; }
location ~ /readme\.html$ { deny all; }
location ~ /license\.txt$ { deny all; }
location ~ /xmlrpc\.php$ { deny all; }
location ~ /wp-trackback\.php$ { deny all; }

# Block PHP in uploads
location ~* /wp-content/uploads/.*\.php$ { deny all; }
location ~* /wp-includes/.*\.php$ { deny all; }
location ~* /wp-content/plugins/.*\.php$ {
    deny all;
}

# Block direct access to PHP files in certain directories
location ~* ^/wp-content/(?:uploads|cache|temp|backup)/.*\.php$ { deny all; }
EOF

# WordPress cache snippet
cat > /etc/nginx/snippets/wordpress-cache.conf << 'EOF'
# Static files caching
location ~* \.(jpg|jpeg|png|gif|ico|webp|avif)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Vary "Accept-Encoding";
    access_log off;
    log_not_found off;
    try_files $uri =404;
}

location ~* \.(css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
    try_files $uri =404;
}

location ~* \.(woff|woff2|ttf|otf|eot|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Access-Control-Allow-Origin "*";
    access_log off;
    try_files $uri =404;
}

location ~* \.(pdf|doc|docx|xls|xlsx|zip|rar|gz|tar)$ {
    expires 30d;
    add_header Cache-Control "public";
    try_files $uri =404;
}
EOF

# API config
cat > /etc/nginx/sites-flyne/api.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};
    root ${FLYNE_DIR};
    index index.php;
    
    # Security
    location ~ /\.(?!well-known) { deny all; }
    location /backups { deny all; }
    location /scripts { deny all; }
    location ~ \.conf$ { deny all; }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ROOT_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
        
        # Timeouts for long operations
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
    }
    
    limit_req zone=api burst=100 nodelay;
    limit_conn connlimit 50;
}
EOF

# phpMyAdmin config
cat > /etc/nginx/sites-flyne/pma.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${PMA_DOMAIN};
    root /usr/share/phpmyadmin;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\.(?!well-known) { deny all; }
    
    # Rate limit login attempts
    location ~ ^/index\.php\$ {
        limit_req zone=login burst=3 nodelay;
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

#===============================================================================
# SSH/SFTP CONFIGURATION - SECURE ISOLATION
#===============================================================================
log "Configuring secure SFTP..."

cat >> /etc/ssh/sshd_config << 'EOF'

# === Flyne SFTP Configuration ===
Match Group siteusers
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0022
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
    PermitTunnel no
    AllowAgentForwarding no
EOF

systemctl restart sshd

#===============================================================================
# SSL CERTIFICATES
#===============================================================================
log "Installing SSL certificates..."
certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN} --email ${ADMIN_EMAIL} --agree-tos --non-interactive --redirect || warn "SSL failed - check DNS and try: certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN}"

#===============================================================================
# DATABASE SCHEMA
#===============================================================================
log "Creating database schema..."
mysql -u root -p"${MYSQL_ROOT_PASS}" flyne_engine << 'DBSCHEMA'
-- Sites table
CREATE TABLE IF NOT EXISTS sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    user_name VARCHAR(64) NOT NULL,
    db_name VARCHAR(64) NOT NULL,
    db_user VARCHAR(64) NOT NULL,
    db_pass VARCHAR(255) NOT NULL,
    php_version VARCHAR(10) DEFAULT '8.4',
    status ENUM('active','suspended','creating','deleting') DEFAULT 'creating',
    ssl_enabled TINYINT(1) DEFAULT 0,
    redis_db INT DEFAULT 1,
    disk_quota INT DEFAULT 10240,
    bandwidth_quota BIGINT DEFAULT 107374182400,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_status (status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SFTP Access table
CREATE TABLE IF NOT EXISTS sftp_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    username VARCHAR(64) NOT NULL UNIQUE,
    is_enabled TINYINT(1) DEFAULT 1,
    expires_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    INDEX idx_site (site_id),
    INDEX idx_username (username),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backups table
CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    type ENUM('full','files','database') DEFAULT 'full',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    checksum VARCHAR(64),
    error_message TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    INDEX idx_site (site_id),
    INDEX idx_status (status),
    INDEX idx_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Activity logs
CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    site_id INT,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_site (site_id),
    INDEX idx_action (action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Cron jobs table
CREATE TABLE IF NOT EXISTS cron_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    command VARCHAR(500) NOT NULL,
    schedule VARCHAR(50) NOT NULL,
    is_enabled TINYINT(1) DEFAULT 1,
    last_run DATETIME,
    next_run DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
DBSCHEMA

#===============================================================================
# CONFIG FILE
#===============================================================================
log "Creating configuration..."
cat > ${FLYNE_DIR}/flyne.conf << EOF
# Flyne Engine Configuration
# Generated: $(date)

API_DOMAIN="${API_DOMAIN}"
PMA_DOMAIN="${PMA_DOMAIN}"
API_SECRET="${API_SECRET}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS}"
REDIS_PASS="${REDIS_PASS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
SITES_DIR="${SITES_DIR}"
FLYNE_DIR="${FLYNE_DIR}"
DEFAULT_PHP="8.4"
TOTAL_RAM="${TOTAL_RAM}"
EOF
chmod 600 ${FLYNE_DIR}/flyne.conf

#===============================================================================
# PHP VERSION SWITCH SCRIPT
#===============================================================================
log "Creating PHP switch script..."
cat > ${FLYNE_DIR}/scripts/php-switch.sh << 'PHPSWITCH'
#!/bin/bash
# Zero-Downtime PHP Version Switch

DOMAIN="$1"
OLD_VER="$2"
NEW_VER="$3"
LOG="/var/log/flyne/php-switch.log"
ALLOWED_VERSIONS="7.4 8.0 8.1 8.2 8.3 8.4"

[[ -z "$DOMAIN" || -z "$OLD_VER" || -z "$NEW_VER" ]] && exit 1

SYMLINK="/run/php/php-${DOMAIN}.sock"
OLD_VNUM="${OLD_VER//./}"
NEW_VNUM="${NEW_VER//./}"
OLD_SOCKET="/run/php/php-${DOMAIN}.php${OLD_VNUM}.sock"
NEW_SOCKET="/run/php/php-${DOMAIN}.php${NEW_VNUM}.sock"

echo "[$(date)] START: $DOMAIN $OLD_VER -> $NEW_VER" >> "$LOG"

sleep 0.5

# Update pool file socket path
POOL_FILE="/etc/php/${NEW_VER}/fpm/pool.d/${DOMAIN}.conf"
if [ -f "$POOL_FILE" ]; then
    sed -i "s|listen = .*sock|listen = ${NEW_SOCKET}|" "$POOL_FILE"
fi

# Reload new PHP version
systemctl reload "php${NEW_VER}-fpm" 2>/dev/null || systemctl restart "php${NEW_VER}-fpm"
sleep 1

# Wait for socket
WAIT=0
while [ ! -S "$NEW_SOCKET" ] && [ $WAIT -lt 30 ]; do
    sleep 0.2
    WAIT=$((WAIT + 1))
done

if [ ! -S "$NEW_SOCKET" ]; then
    systemctl restart "php${NEW_VER}-fpm"
    sleep 2
fi

# Atomic symlink switch
ln -sf "$NEW_SOCKET" "${SYMLINK}.tmp"
mv -f "${SYMLINK}.tmp" "$SYMLINK"

# Cleanup old pools
for v in $ALLOWED_VERSIONS; do
    if [ "$v" != "$NEW_VER" ]; then
        rm -f "/etc/php/${v}/fpm/pool.d/${DOMAIN}.conf" 2>/dev/null
        systemctl reload "php${v}-fpm" 2>/dev/null
    fi
done

rm -f "$OLD_SOCKET" 2>/dev/null

echo "[$(date)] DONE: $DOMAIN now on PHP $NEW_VER" >> "$LOG"
PHPSWITCH
chmod +x ${FLYNE_DIR}/scripts/php-switch.sh

# Symlink for compatibility
ln -sf ${FLYNE_DIR}/scripts/php-switch.sh /opt/flyne/php-switch.sh

#===============================================================================
# BACKUP SCRIPT
#===============================================================================
log "Creating backup script..."
cat > ${FLYNE_DIR}/scripts/backup.sh << 'BACKUP'
#!/bin/bash
DOMAIN="$1"
TYPE="${2:-full}"
BACKUP_DIR="/opt/flyne/backups"
SITES_DIR="/var/www/sites"
CONF="/opt/flyne/flyne.conf"

[[ -z "$DOMAIN" ]] && echo "Usage: $0 domain [full|files|database]" && exit 1
[[ ! -d "$SITES_DIR/$DOMAIN" ]] && echo "Site not found" && exit 1

source "$CONF"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SITE_DIR="$SITES_DIR/$DOMAIN"
BACKUP_FILE="${BACKUP_DIR}/${DOMAIN}_${TYPE}_${TIMESTAMP}"

# Get DB credentials from database
DB_INFO=$(mysql -u root -p"$MYSQL_ROOT_PASS" -N -e "SELECT db_name, db_user, db_pass FROM flyne_engine.sites WHERE domain='$DOMAIN'")
DB_NAME=$(echo "$DB_INFO" | awk '{print $1}')
DB_USER=$(echo "$DB_INFO" | awk '{print $2}')
DB_PASS=$(echo "$DB_INFO" | awk '{print $3}')

case "$TYPE" in
    full)
        mysqldump -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" > "/tmp/${DOMAIN}_db.sql"
        tar -czf "${BACKUP_FILE}.tar.gz" -C "$SITES_DIR" "$DOMAIN" -C /tmp "${DOMAIN}_db.sql"
        rm -f "/tmp/${DOMAIN}_db.sql"
        ;;
    files)
        tar -czf "${BACKUP_FILE}.tar.gz" -C "$SITES_DIR" "$DOMAIN"
        ;;
    database)
        mysqldump -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" | gzip > "${BACKUP_FILE}.sql.gz"
        ;;
esac

# Calculate size and checksum
SIZE=$(stat -f%z "${BACKUP_FILE}"* 2>/dev/null || stat -c%s "${BACKUP_FILE}"*)
CHECKSUM=$(sha256sum "${BACKUP_FILE}"* | awk '{print $1}')

echo "Backup completed: ${BACKUP_FILE}"
echo "Size: $SIZE bytes"
echo "Checksum: $CHECKSUM"
BACKUP
chmod +x ${FLYNE_DIR}/scripts/backup.sh

#===============================================================================
# SFTP EXPIRY CRON
#===============================================================================
log "Setting up cron jobs..."
cat > /etc/cron.d/flyne << EOF
# Flyne Engine Cron Jobs

# Expire SFTP access
*/5 * * * * root mysql -u root -p'${MYSQL_ROOT_PASS}' -e "SELECT username FROM flyne_engine.sftp_access WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_enabled = 1" -N 2>/dev/null | while read user; do usermod -L "\$user" 2>/dev/null && mysql -u root -p'${MYSQL_ROOT_PASS}' -e "UPDATE flyne_engine.sftp_access SET is_enabled=0 WHERE username='\$user'" 2>/dev/null; done

# Clean nginx cache older than 7 days
0 3 * * * root find /tmp/nginx-cache -type f -mtime +7 -delete 2>/dev/null

# Clean old backups (30 days)
0 4 * * 0 root find /opt/flyne/backups -type f -mtime +30 -delete 2>/dev/null

# Optimize databases weekly
0 5 * * 0 root mysqlcheck -u root -p'${MYSQL_ROOT_PASS}' --optimize --all-databases 2>/dev/null
EOF
chmod 644 /etc/cron.d/flyne

#===============================================================================
# SUDOERS
#===============================================================================
log "Setting up permissions..."
cat > /etc/sudoers.d/flyne << 'SUDOERS'
# Flyne Engine Sudoers

# User management
www-data ALL=(ALL) NOPASSWD: /usr/sbin/useradd *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/userdel *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/usermod *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd

# File operations
www-data ALL=(ALL) NOPASSWD: /bin/mkdir -p /var/www/sites/*
www-data ALL=(ALL) NOPASSWD: /bin/chown *
www-data ALL=(ALL) NOPASSWD: /bin/chmod *
www-data ALL=(ALL) NOPASSWD: /bin/rm -rf /var/www/sites/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/sites-flyne/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /etc/php/*/fpm/pool.d/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /run/php/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -rf /tmp/nginx-cache/*
www-data ALL=(ALL) NOPASSWD: /bin/touch *
www-data ALL=(ALL) NOPASSWD: /bin/ln *

# Rsync for backups
www-data ALL=(ALL) NOPASSWD: /usr/bin/rsync *

# Tar for backups
www-data ALL=(ALL) NOPASSWD: /bin/tar *

# SSL
www-data ALL=(ALL) NOPASSWD: /usr/bin/certbot *

# Services
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload php*-fpm
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart php*-fpm
www-data ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t

# Monitoring
www-data ALL=(ALL) NOPASSWD: /usr/bin/du -sm /var/www/sites/*
www-data ALL=(ALL) NOPASSWD: /usr/bin/du *

# MySQL
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysqldump *
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysql *

# WP-CLI (run as site users)
www-data ALL=(ALL) NOPASSWD: /usr/bin/sudo -u site_* /usr/bin/php* /usr/local/bin/wp *

# PHP switch script
www-data ALL=(ALL) NOPASSWD: /opt/flyne/scripts/php-switch.sh *
www-data ALL=(ALL) NOPASSWD: /opt/flyne/php-switch.sh *
SUDOERS
chmod 440 /etc/sudoers.d/flyne

#===============================================================================
# FAIL2BAN
#===============================================================================
log "Configuring Fail2Ban..."

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[wordpress-hard]
enabled = true
filter = wordpress-hard
logpath = /var/www/sites/*/logs/access.log
maxretry = 3
bantime = 86400
EOF

cat > /etc/fail2ban/filter.d/wordpress-hard.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php
            ^<HOST> .* "POST /xmlrpc\.php
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban

#===============================================================================
# FIREWALL
#===============================================================================
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

#===============================================================================
# CLI TOOL
#===============================================================================
log "Installing CLI tool..."
cat > /usr/local/bin/flyne << 'CLIFILE'
#!/bin/bash
source /opt/flyne/flyne.conf 2>/dev/null || { echo "Flyne not configured"; exit 1; }

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

case "$1" in
    status)
        echo -e "${BLUE}=== Flyne Engine Status ===${NC}"
        echo ""
        
        # Services
        for svc in nginx mariadb redis-server; do
            if systemctl is-active --quiet $svc; then
                echo -e "$svc: ${GREEN}✓ Running${NC}"
            else
                echo -e "$svc: ${RED}✗ Stopped${NC}"
            fi
        done
        
        # PHP versions
        for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
            if systemctl is-active --quiet php${v}-fpm 2>/dev/null; then
                echo -e "PHP ${v}: ${GREEN}✓ Running${NC}"
            fi
        done
        
        echo ""
        echo -e "Sites: ${YELLOW}$(mysql -u root -p"$MYSQL_ROOT_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites" 2>/dev/null || echo 0)${NC}"
        echo -e "API: ${BLUE}https://${API_DOMAIN}${NC}"
        echo -e "PMA: ${BLUE}https://${PMA_DOMAIN}${NC}"
        ;;
        
    sites)
        echo -e "${BLUE}=== Sites ===${NC}"
        mysql -u root -p"$MYSQL_ROOT_PASS" -e "SELECT domain, php_version, status, ssl_enabled, created_at FROM flyne_engine.sites" 2>/dev/null
        ;;
        
    create)
        [[ -z "$2" ]] && echo "Usage: flyne create domain.com [email]" && exit 1
        DOMAIN="$2"
        EMAIL="${3:-admin@$DOMAIN}"
        echo -e "Creating site ${YELLOW}$DOMAIN${NC}..."
        curl -s -X POST "https://${API_DOMAIN}/index.php" \
            -H "Authorization: Bearer ${API_SECRET}" \
            -d "action=create_site&domain=$DOMAIN&admin_email=$EMAIL" | jq .
        ;;
        
    delete)
        [[ -z "$2" ]] && echo "Usage: flyne delete domain.com" && exit 1
        read -p "Are you sure you want to delete $2? [y/N] " confirm
        [[ "$confirm" != "y" ]] && exit 0
        curl -s -X POST "https://${API_DOMAIN}/index.php" \
            -H "Authorization: Bearer ${API_SECRET}" \
            -d "action=delete_site&domain=$2" | jq .
        ;;
        
    backup)
        [[ -z "$2" ]] && echo "Usage: flyne backup domain.com [full|files|database]" && exit 1
        /opt/flyne/scripts/backup.sh "$2" "${3:-full}"
        ;;
        
    test)
        echo "Testing API connection..."
        curl -s -H "Authorization: Bearer ${API_SECRET}" \
            "https://${API_DOMAIN}/index.php?action=site_list" | jq .
        ;;
        
    logs)
        if [[ -z "$2" ]]; then
            tail -f /var/log/flyne/api.log
        else
            tail -f /var/www/sites/$2/logs/*.log
        fi
        ;;
        
    *)
        echo -e "${BLUE}Flyne Engine CLI${NC}"
        echo ""
        echo "Usage: flyne <command> [options]"
        echo ""
        echo "Commands:"
        echo "  status              Show system status"
        echo "  sites               List all sites"
        echo "  create <domain>     Create new WordPress site"
        echo "  delete <domain>     Delete a site"
        echo "  backup <domain>     Backup a site"
        echo "  test                Test API connection"
        echo "  logs [domain]       View logs"
        ;;
esac
CLIFILE
chmod +x /usr/local/bin/flyne

#===============================================================================
# LOGROTATE
#===============================================================================
log "Configuring log rotation..."
cat > /etc/logrotate.d/flyne << 'EOF'
/var/log/flyne/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 www-data www-data
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
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid)
    endscript
}
EOF

#===============================================================================
# KERNEL TUNING
#===============================================================================
log "Applying kernel optimizations..."
cat > /etc/sysctl.d/99-flyne.conf << 'EOF'
# Network performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535

# Memory
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5

# File descriptors
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
sysctl -p /etc/sysctl.d/99-flyne.conf 2>/dev/null

# Increase file limits
cat > /etc/security/limits.d/flyne.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
www-data soft nofile 65535
www-data hard nofile 65535
EOF

#===============================================================================
# FINAL VERIFICATION
#===============================================================================
log "Verifying installation..."

# Test services
nginx -t || error "Nginx config test failed"
systemctl is-active --quiet mariadb || error "MariaDB not running"
systemctl is-active --quiet redis-server || error "Redis not running"
systemctl is-active --quiet php8.4-fpm || error "PHP-FPM not running"

# Test database connection
mysql -u root -p"${MYSQL_ROOT_PASS}" -e "SELECT 1" &>/dev/null || error "MySQL connection failed"

#===============================================================================
# OUTPUT SUMMARY
#===============================================================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   FLYNE ENGINE INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Structure:${NC}"
echo -e "  ${FLYNE_DIR}/"
echo -e "  ├── index.php      ✓ Downloaded"
echo -e "  ├── flyne.conf     ✓ Created"
echo -e "  ├── scripts/       ✓ Created"
echo -e "  │   ├── php-switch.sh"
echo -e "  │   └── backup.sh"
echo -e "  └── backups/       ✓ Created"
echo ""
echo -e "${BLUE}URLs:${NC}"
echo -e "  API:        ${CYAN}https://${API_DOMAIN}${NC}"
echo -e "  phpMyAdmin: ${CYAN}https://${PMA_DOMAIN}${NC}"
echo ""
echo -e "${BLUE}Credentials:${NC}"
echo -e "  API Secret:     ${YELLOW}${API_SECRET}${NC}"
echo -e "  MySQL Root:     ${YELLOW}${MYSQL_ROOT_PASS}${NC}"
echo -e "  Redis Password: ${YELLOW}${REDIS_PASS}${NC}"
echo ""
echo -e "${BLUE}Performance:${NC}"
echo -e "  RAM Detected:   ${TOTAL_RAM}MB"
echo -e "  InnoDB Buffer:  ${INNODB_BUFFER}"
echo -e "  Redis Memory:   ${REDIS_MEM}MB"
echo -e "  CPU Cores:      ${CPU_CORES}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo -e "  1. Test the API:"
echo -e "     ${CYAN}flyne test${NC}"
echo -e "  2. Create your first site:"
echo -e "     ${CYAN}flyne create example.com${NC}"
echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}   SAVE THESE CREDENTIALS SECURELY!${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Download index.php automatically
log "Downloading API file..."
wget -qO ${FLYNE_DIR}/index.php https://raw.githubusercontent.com/Flynecom/flyne/main/index.php
chown www-data:www-data ${FLYNE_DIR}/index.php
chmod 644 ${FLYNE_DIR}/index.php

if [[ -f "${FLYNE_DIR}/index.php" ]]; then
    log "API file downloaded successfully!"
else
    warn "Failed to download index.php - download manually from GitHub"
fi

# Save credentials to file
cat > ${FLYNE_DIR}/credentials.txt << EOF
=== FLYNE ENGINE CREDENTIALS ===
Generated: $(date)

API Domain:    https://${API_DOMAIN}
PMA Domain:    https://${PMA_DOMAIN}

API Secret:    ${API_SECRET}
MySQL Root:    ${MYSQL_ROOT_PASS}
Redis Pass:    ${REDIS_PASS}
Admin Email:   ${ADMIN_EMAIL}

DELETE THIS FILE AFTER SAVING CREDENTIALS!
EOF
chmod 600 ${FLYNE_DIR}/credentials.txt

echo -e "Credentials saved to: ${YELLOW}${FLYNE_DIR}/credentials.txt${NC}"
echo -e "${RED}Delete this file after saving credentials securely!${NC}"
echo ""