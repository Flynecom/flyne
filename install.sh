#!/bin/bash
#===============================================================================
# FLYNE ENGINE v2.5 - Ultra High-Performance WordPress Hosting
# Production-ready installer for Ubuntu 22.04/24.04
# Optimized for speed: FastCGI Cache, Redis, OPcache JIT, HTTP/2
#===============================================================================

# Don't exit on errors - handle them gracefully
set +e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

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
  Ultra High-Performance WordPress Engine v2.5
  FastCGI Cache | Redis Object Cache | OPcache JIT | HTTP/2
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

read -sp "MySQL Root Password [auto-generated]: " MYSQL_ROOT_PASS
MYSQL_ROOT_PASS=${MYSQL_ROOT_PASS:-$DEFAULT_MYSQL_PASS}
echo ""

read -sp "Redis Password [auto-generated]: " REDIS_PASS
REDIS_PASS=${REDIS_PASS:-$DEFAULT_REDIS_PASS}
echo ""

[[ -z "$API_DOMAIN" ]] && error "API domain required"
[[ -z "$PMA_DOMAIN" ]] && error "PMA domain required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ characters"

# Detect system resources
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
    pwgen htop ncdu fail2ban ufw jq acl rsync pigz pv lsof \
    libpam-pwquality imagemagick webp graphicsmagick

# PHP repository
log "Adding PHP repository..."
add-apt-repository -y ppa:ondrej/php
apt update

# Install PHP versions with all extensions
for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    log "Installing PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline php${V}-apcu php${V}-igbinary \
        php${V}-msgpack 2>/dev/null || warn "PHP $V partially installed"
done

# WP-CLI
log "Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

# phpMyAdmin latest
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
\$cfg['MaxRows'] = 100;
\$cfg['SendErrorReports'] = 'never';
PMAEOF
    chown -R www-data:www-data /usr/share/phpmyadmin
    mkdir -p /usr/share/phpmyadmin/tmp && chmod 777 /usr/share/phpmyadmin/tmp
fi

#===============================================================================
# DIRECTORY STRUCTURE
#===============================================================================
log "Creating directories..."
mkdir -p $FLYNE_DIR/{backups,scripts,ssl}
mkdir -p $SITES_DIR
mkdir -p /var/log/flyne
mkdir -p /var/cache/nginx/fastcgi
mkdir -p /run/php

# Create siteusers group for SFTP
groupadd -f siteusers

chown www-data:www-data /var/log/flyne /var/cache/nginx/fastcgi
chmod 750 /var/log/flyne
chmod 755 /var/cache/nginx/fastcgi

# Create API log file
touch /var/log/flyne/api.log
chown www-data:www-data /var/log/flyne/api.log

#===============================================================================
# MARIADB - MAXIMUM PERFORMANCE
#===============================================================================
log "Configuring MariaDB for maximum performance..."

# Calculate optimal settings based on RAM
if [[ $TOTAL_RAM -gt 16384 ]]; then
    INNODB_BUFFER="8G"
    INNODB_LOG="1G"
    INNODB_INSTANCES=8
    MAX_CONN=800
    QUERY_CACHE="256M"
elif [[ $TOTAL_RAM -gt 8192 ]]; then
    INNODB_BUFFER="4G"
    INNODB_LOG="512M"
    INNODB_INSTANCES=4
    MAX_CONN=500
    QUERY_CACHE="128M"
elif [[ $TOTAL_RAM -gt 4096 ]]; then
    INNODB_BUFFER="2G"
    INNODB_LOG="256M"
    INNODB_INSTANCES=4
    MAX_CONN=300
    QUERY_CACHE="64M"
elif [[ $TOTAL_RAM -gt 2048 ]]; then
    INNODB_BUFFER="1G"
    INNODB_LOG="128M"
    INNODB_INSTANCES=2
    MAX_CONN=200
    QUERY_CACHE="32M"
else
    INNODB_BUFFER="512M"
    INNODB_LOG="64M"
    INNODB_INSTANCES=1
    MAX_CONN=100
    QUERY_CACHE="16M"
fi

cat > /etc/mysql/mariadb.conf.d/99-flyne-performance.cnf << MYSQLEOF
[mysqld]
# === InnoDB Engine (Primary) ===
default_storage_engine = InnoDB
innodb_buffer_pool_size = ${INNODB_BUFFER}
innodb_buffer_pool_instances = ${INNODB_INSTANCES}
innodb_log_file_size = ${INNODB_LOG}
innodb_log_buffer_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_stats_on_metadata = 0
innodb_read_io_threads = ${CPU_CORES}
innodb_write_io_threads = ${CPU_CORES}
innodb_io_capacity = 4000
innodb_io_capacity_max = 8000
innodb_adaptive_flushing = 1
innodb_flush_neighbors = 0
innodb_purge_threads = 4
innodb_lru_scan_depth = 1024
innodb_change_buffering = all
innodb_buffer_pool_dump_at_shutdown = 1
innodb_buffer_pool_load_at_startup = 1

# === Query Cache ===
query_cache_type = 1
query_cache_size = ${QUERY_CACHE}
query_cache_limit = 4M
query_cache_min_res_unit = 2K

# === Connection & Thread Settings ===
max_connections = ${MAX_CONN}
max_user_connections = 100
wait_timeout = 60
interactive_timeout = 60
connect_timeout = 10
thread_cache_size = 100
thread_handling = pool-of-threads
thread_pool_size = ${CPU_CORES}
thread_pool_max_threads = 1000

# === Buffer Settings ===
join_buffer_size = 8M
sort_buffer_size = 4M
read_buffer_size = 4M
read_rnd_buffer_size = 8M
bulk_insert_buffer_size = 64M
tmp_table_size = 256M
max_heap_table_size = 256M
table_open_cache = 8000
table_definition_cache = 4000
open_files_limit = 65535

# === Binary Logging (disabled for performance) ===
skip-log-bin

# === Query Optimization ===
optimizer_search_depth = 0
optimizer_switch = 'index_merge=on,index_merge_union=on,index_merge_sort_union=on,index_merge_intersection=on'

# === Logging ===
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 0
log_slow_admin_statements = 0

# === Security ===
skip-name-resolve
local_infile = 0
symbolic-links = 0
secure_file_priv = /tmp

# === Network ===
max_allowed_packet = 256M
net_buffer_length = 32K

# === Character Set ===
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
init_connect = 'SET NAMES utf8mb4'

[mysqldump]
quick
quote-names
max_allowed_packet = 256M
MYSQLEOF

systemctl restart mariadb || warn "MariaDB restart failed"

# Secure installation
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';" 2>/dev/null || true
mysql -u root -p"${MYSQL_ROOT_PASS}" << SQLEOF 2>/dev/null
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
CREATE DATABASE IF NOT EXISTS flyne_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
FLUSH PRIVILEGES;
SQLEOF

#===============================================================================
# REDIS - OPTIMIZED FOR WORDPRESS OBJECT CACHE
#===============================================================================
log "Configuring Redis for object caching..."

# Calculate Redis memory (15% of RAM, min 128MB, max 2GB)
REDIS_MEM=$((TOTAL_RAM * 15 / 100))
[[ $REDIS_MEM -lt 128 ]] && REDIS_MEM=128
[[ $REDIS_MEM -gt 2048 ]] && REDIS_MEM=2048

cat > /etc/redis/redis.conf << REDISEOF
# Network
bind 127.0.0.1 ::1
port 6379
protected-mode yes
tcp-backlog 511
unixsocket /run/redis/redis-server.sock
unixsocketperm 770
timeout 0
tcp-keepalive 300

# Security
requirepass ${REDIS_PASS}

# Memory Management
maxmemory ${REDIS_MEM}mb
maxmemory-policy allkeys-lru
maxmemory-samples 10
activedefrag yes
active-defrag-ignore-bytes 100mb
active-defrag-threshold-lower 10
active-defrag-threshold-upper 30

# Persistence (disabled for cache performance)
save ""
appendonly no
stop-writes-on-bgsave-error no

# Performance
databases 256
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes
io-threads ${CPU_CORES}
io-threads-do-reads yes

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
REDISEOF

usermod -aG redis www-data
systemctl restart redis-server || warn "Redis restart failed"

#===============================================================================
# PHP-FPM - MAXIMUM PERFORMANCE WITH JIT
#===============================================================================
log "Configuring PHP-FPM for maximum performance..."

# Calculate PHP-FPM workers based on RAM
# Formula: (RAM - 1GB for system) / 50MB per process
PHP_MAX_CHILDREN=$(( (TOTAL_RAM - 1024) / 50 ))
[[ $PHP_MAX_CHILDREN -lt 10 ]] && PHP_MAX_CHILDREN=10
[[ $PHP_MAX_CHILDREN -gt 100 ]] && PHP_MAX_CHILDREN=100

PHP_START_SERVERS=$((PHP_MAX_CHILDREN / 4))
PHP_MIN_SPARE=$((PHP_MAX_CHILDREN / 8))
PHP_MAX_SPARE=$((PHP_MAX_CHILDREN / 2))

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    if systemctl is-enabled php${V}-fpm &>/dev/null; then
        log "Optimizing PHP $V..."
        
        # PHP.ini optimizations
        PHP_INI="/etc/php/${V}/fpm/php.ini"
        if [[ -f "$PHP_INI" ]]; then
            cat > "/etc/php/${V}/fpm/conf.d/99-flyne-performance.ini" << PHPINI
; Flyne Performance Settings
memory_limit = 512M
max_execution_time = 300
max_input_time = 300
max_input_vars = 10000
post_max_size = 256M
upload_max_filesize = 256M

; Realpath Cache (huge performance boost)
realpath_cache_size = 4096K
realpath_cache_ttl = 600

; Output Buffering
output_buffering = 4096
implicit_flush = Off

; Error Handling
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; Session
session.save_handler = redis
session.save_path = "tcp://127.0.0.1:6379?auth=${REDIS_PASS}"
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440

; Security
expose_php = Off
allow_url_fopen = On
allow_url_include = Off

; Performance
zlib.output_compression = On
zlib.output_compression_level = 4
PHPINI

            # OPcache configuration (with JIT for PHP 8+)
            cat > "/etc/php/${V}/fpm/conf.d/10-opcache.ini" << OPCACHE
[opcache]
opcache.enable = 1
opcache.enable_cli = 0
opcache.memory_consumption = 512
opcache.interned_strings_buffer = 64
opcache.max_accelerated_files = 100000
opcache.max_wasted_percentage = 5
opcache.revalidate_freq = 2
opcache.fast_shutdown = 1
opcache.save_comments = 1
opcache.enable_file_override = 1
opcache.validate_timestamps = 1
opcache.huge_code_pages = 1
opcache.file_cache = /tmp/opcache
opcache.file_cache_only = 0
opcache.file_cache_consistency_checks = 1
OPCACHE

            # Add JIT for PHP 8.0+
            if [[ "${V}" != "7.4" ]]; then
                cat >> "/etc/php/${V}/fpm/conf.d/10-opcache.ini" << OPCACHEJIT
; JIT Compilation (PHP 8+)
opcache.jit = 1255
opcache.jit_buffer_size = 256M
OPCACHEJIT
            fi

            # Create opcache file cache directory
            mkdir -p /tmp/opcache
            chmod 777 /tmp/opcache

            # APCu configuration
            cat > "/etc/php/${V}/fpm/conf.d/20-apcu.ini" << APCU
[apcu]
apc.enabled = 1
apc.shm_size = 128M
apc.ttl = 7200
apc.gc_ttl = 3600
apc.entries_hint = 4096
apc.slam_defense = 1
apc.enable_cli = 0
apc.serializer = igbinary
APCU
        fi

        # PHP-FPM Pool configuration
        cat > "/etc/php/${V}/fpm/pool.d/www.conf" << POOL
[www]
user = www-data
group = www-data
listen = /run/php/php${V}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
listen.backlog = 65535

; Process Manager - Dynamic for best balance
pm = dynamic
pm.max_children = ${PHP_MAX_CHILDREN}
pm.start_servers = ${PHP_START_SERVERS}
pm.min_spare_servers = ${PHP_MIN_SPARE}
pm.max_spare_servers = ${PHP_MAX_SPARE}
pm.max_requests = 2000
pm.process_idle_timeout = 10s

; Timeouts
request_terminate_timeout = 900
request_slowlog_timeout = 30s
slowlog = /var/log/php${V}-fpm-slow.log

; Resource Limits
rlimit_files = 65535
rlimit_core = 0

; Status
pm.status_path = /fpm-status
ping.path = /fpm-ping
ping.response = pong

; Logging
php_admin_value[error_log] = /var/log/php${V}-fpm-error.log
php_admin_flag[log_errors] = on
catch_workers_output = yes
decorate_workers_output = no

; Security
php_admin_value[disable_functions] = dl,exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec
php_admin_value[open_basedir] = /var/www:/tmp:/usr/share/php:/usr/share/phpmyadmin:/opt/flyne
POOL

        systemctl restart php${V}-fpm 2>/dev/null || warn "PHP $V FPM restart failed"
    fi
done

#===============================================================================
# NGINX - ULTRA HIGH PERFORMANCE WITH FASTCGI CACHE
#===============================================================================
log "Configuring Nginx for ultra high performance..."

WORKER_CONN=$((8192 * CPU_CORES))

cat > /etc/nginx/nginx.conf << 'NGINXCONF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

# Load dynamic modules
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections WORKER_CONN_PLACEHOLDER;
    multi_accept on;
    use epoll;
    accept_mutex off;
}

http {
    # === Basic Settings ===
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    server_tokens off;
    reset_timedout_connection on;
    client_body_timeout 30;
    client_header_timeout 30;
    send_timeout 60;

    # === Buffer Settings ===
    client_body_buffer_size 256k;
    client_max_body_size 256M;
    client_header_buffer_size 4k;
    large_client_header_buffers 8 32k;
    output_buffers 2 64k;
    postpone_output 1460;

    # === MIME Types ===
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # === Logging ===
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" $request_time $upstream_response_time '
                    '$upstream_cache_status';
    
    access_log /var/log/nginx/access.log main buffer=64k flush=5m;
    error_log /var/log/nginx/error.log warn;

    # === Gzip Compression ===
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_buffers 32 8k;
    gzip_http_version 1.1;
    gzip_disable "msie6";
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

    # === FastCGI Cache (THE KEY TO SPEED!) ===
    fastcgi_cache_path /var/cache/nginx/fastcgi 
        levels=1:2 
        keys_zone=FLAVOR:512m 
        max_size=10g 
        inactive=7d 
        use_temp_path=off;
    
    fastcgi_cache_key "$scheme$request_method$host$request_uri";
    fastcgi_cache_lock on;
    fastcgi_cache_lock_timeout 5s;
    fastcgi_cache_lock_age 5s;
    fastcgi_cache_use_stale error timeout updating http_500 http_503;
    fastcgi_cache_background_update on;
    fastcgi_cache_revalidate on;
    fastcgi_ignore_headers Cache-Control Expires Set-Cookie;

    # === Open File Cache ===
    open_file_cache max=100000 inactive=60s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # === SSL Settings ===
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_buffer_size 4k;

    # === Security Headers ===
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # === Rate Limiting ===
    limit_req_zone $binary_remote_addr zone=api:20m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=general:20m rate=100r/s;
    limit_conn_zone $binary_remote_addr zone=connlimit:20m;

    # === Proxy Settings ===
    proxy_connect_timeout 600;
    proxy_send_timeout 600;
    proxy_read_timeout 600;

    # === Upstream PHP ===
    upstream php84 {
        server unix:/run/php/php8.4-fpm.sock;
        keepalive 32;
    }

    # === Cache Bypass Maps ===
    map $request_method $skip_cache {
        default 0;
        POST 1;
        PUT 1;
        DELETE 1;
    }

    map $request_uri $skip_cache_uri {
        default 0;
        ~*/wp-admin 1;
        ~*/wp-login.php 1;
        ~*/wp-cron.php 1;
        ~*/xmlrpc.php 1;
        ~*sitemap 1;
        ~*/feed 1;
        ~*/cart 1;
        ~*/checkout 1;
        ~*/my-account 1;
        ~*/add-to-cart 1;
        ~*wc-ajax 1;
        ~*nocache 1;
    }

    map $http_cookie $skip_cache_cookie {
        default 0;
        ~*wordpress_logged_in 1;
        ~*wp-postpass 1;
        ~*woocommerce_cart_hash 1;
        ~*woocommerce_items_in_cart 1;
        ~*comment_author 1;
    }

    # === Includes ===
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-flyne/*.conf;
}
NGINXCONF

# Replace placeholder
sed -i "s/WORKER_CONN_PLACEHOLDER/${WORKER_CONN}/" /etc/nginx/nginx.conf

mkdir -p /etc/nginx/sites-flyne
mkdir -p /etc/nginx/snippets

# WordPress security snippet
cat > /etc/nginx/snippets/wordpress-security.conf << 'WPSEC'
# Block access to sensitive files
location ~ /\.(?!well-known) { deny all; }
location ~* /(?:uploads|files)/.*\.php$ { deny all; }
location ~ /wp-config\.php$ { deny all; }
location ~ /readme\.html$ { deny all; }
location ~ /license\.txt$ { deny all; }
location ~ /xmlrpc\.php$ { 
    deny all;
    access_log off;
    log_not_found off;
}

# Block PHP in sensitive directories
location ~* ^/wp-content/(?:uploads|cache|temp|backup)/.*\.php$ { deny all; }
location ~* ^/wp-includes/.*\.php$ { 
    deny all;
}

# Allow wp-includes for specific files
location ~* ^/wp-includes/js/tinymce/wp-tinymce\.php$ {
    fastcgi_pass unix:/run/php/php-$host.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

# Block access to hidden files
location ~ /\. { 
    deny all; 
    access_log off; 
    log_not_found off; 
}

# Block access to backup and source files
location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$ {
    deny all;
    access_log off;
    log_not_found off;
}
WPSEC

# WordPress cache snippet
cat > /etc/nginx/snippets/wordpress-cache.conf << 'WPCACHE'
# Static files - aggressive caching
location ~* \.(jpg|jpeg|png|gif|ico|webp|avif|heic)$ {
    expires max;
    add_header Cache-Control "public, immutable";
    add_header Vary "Accept-Encoding";
    access_log off;
    log_not_found off;
    try_files $uri =404;
}

location ~* \.(css|js)$ {
    expires max;
    add_header Cache-Control "public, immutable";
    access_log off;
    try_files $uri =404;
}

location ~* \.(woff|woff2|ttf|otf|eot)$ {
    expires max;
    add_header Cache-Control "public, immutable";
    add_header Access-Control-Allow-Origin "*";
    access_log off;
    try_files $uri =404;
}

location ~* \.(svg)$ {
    expires max;
    add_header Cache-Control "public, immutable";
    access_log off;
    try_files $uri =404;
}

location ~* \.(pdf|doc|docx|xls|xlsx|zip|rar|gz|tar|mp3|mp4|webm|ogg)$ {
    expires 30d;
    add_header Cache-Control "public";
    try_files $uri =404;
}

# HTML caching
location ~* \.(html|htm)$ {
    expires 1h;
    add_header Cache-Control "public, must-revalidate";
    try_files $uri =404;
}
WPCACHE

# WordPress FastCGI snippet
cat > /etc/nginx/snippets/wordpress-fastcgi.conf << 'WPFCGI'
# FastCGI cache settings for WordPress
set $skip_cache 0;

# POST requests bypass cache
if ($request_method = POST) {
    set $skip_cache 1;
}

# Query strings bypass cache
if ($query_string != "") {
    set $skip_cache 1;
}

# Specific URIs bypass cache
if ($request_uri ~* "/wp-admin/|/wp-json/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap(_index)?.xml|/cart.*|/checkout.*|/my-account.*") {
    set $skip_cache 1;
}

# Logged in users bypass cache
if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in|woocommerce_cart_hash|woocommerce_items_in_cart") {
    set $skip_cache 1;
}

# WooCommerce specific
if ($request_uri ~* "add_to_cart|/cart/|/checkout/|/my-account/|wc-ajax") {
    set $skip_cache 1;
}
WPFCGI

# API config with long timeouts
cat > /etc/nginx/sites-flyne/api.conf << APICONF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${API_DOMAIN};
    
    root ${FLYNE_DIR};
    index index.php;
    
    # Security
    location ~ /\.(?!well-known) { deny all; }
    location /backups { deny all; }
    location /scripts { deny all; }
    location ~ \.conf$ { deny all; }
    location /credentials.txt { deny all; }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ROOT_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
        
        # Long timeouts for site creation (critical!)
        fastcgi_read_timeout 900;
        fastcgi_send_timeout 900;
        fastcgi_connect_timeout 60;
        fastcgi_buffers 32 32k;
        fastcgi_buffer_size 64k;
        fastcgi_busy_buffers_size 64k;
    }
    
    limit_req zone=api burst=200 nodelay;
    limit_conn connlimit 100;
}
APICONF

# phpMyAdmin config
cat > /etc/nginx/sites-flyne/pma.conf << PMACONF
server {
    listen 80;
    listen [::]:80;
    server_name ${PMA_DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${PMA_DOMAIN};
    
    root /usr/share/phpmyadmin;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 300;
    }
    
    location ~ /\.(?!well-known) { deny all; }
    
    # Rate limit login attempts
    location ~ ^/index\.php$ {
        limit_req zone=login burst=5 nodelay;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
PMACONF

rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx || warn "Nginx restart failed"

#===============================================================================
# SSH/SFTP CONFIGURATION
#===============================================================================
log "Configuring secure SFTP..."

# Check if SFTP config already exists
if ! grep -q "Match Group siteusers" /etc/ssh/sshd_config; then
    cat >> /etc/ssh/sshd_config << 'SSHCONF'

# === Flyne SFTP Configuration ===
Match Group siteusers
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0022
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
    PermitTunnel no
    AllowAgentForwarding no
SSHCONF
fi

systemctl restart ssh || systemctl restart sshd || warn "SSH service restart failed"

#===============================================================================
# SSL CERTIFICATES
#===============================================================================
log "Installing SSL certificates..."
certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN} --email ${ADMIN_EMAIL} --agree-tos --non-interactive --redirect || {
    warn "SSL failed - you can run this later:"
    warn "  certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN}"
}

#===============================================================================
# DATABASE SCHEMA
#===============================================================================
log "Creating database schema..."
mysql -u root -p"${MYSQL_ROOT_PASS}" flyne_engine << 'DBSCHEMA'
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    type ENUM('full','files','database') DEFAULT 'full',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    checksum VARCHAR(64),
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

#===============================================================================
# CONFIG FILE
#===============================================================================
log "Creating configuration..."
cat > ${FLYNE_DIR}/flyne.conf << CONFEOF
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
CPU_CORES="${CPU_CORES}"
CONFEOF
chmod 600 ${FLYNE_DIR}/flyne.conf

#===============================================================================
# PHP VERSION SWITCH SCRIPT
#===============================================================================
log "Creating helper scripts..."
cat > ${FLYNE_DIR}/scripts/php-switch.sh << 'PHPSWITCH'
#!/bin/bash
DOMAIN="$1"
OLD_VER="$2"
NEW_VER="$3"
LOG="/var/log/flyne/php-switch.log"

[[ -z "$DOMAIN" || -z "$OLD_VER" || -z "$NEW_VER" ]] && exit 1

echo "[$(date)] START: $DOMAIN $OLD_VER -> $NEW_VER" >> "$LOG"

NEW_SOCKET="/run/php/php-${DOMAIN}.php${NEW_VER//./}.sock"
POOL_FILE="/etc/php/${NEW_VER}/fpm/pool.d/${DOMAIN}.conf"

[ -f "$POOL_FILE" ] && sed -i "s|listen = .*sock|listen = ${NEW_SOCKET}|" "$POOL_FILE"

systemctl reload "php${NEW_VER}-fpm" 2>/dev/null || systemctl restart "php${NEW_VER}-fpm"
sleep 1

# Cleanup old pools
for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
    [ "$v" != "$NEW_VER" ] && rm -f "/etc/php/${v}/fpm/pool.d/${DOMAIN}.conf" 2>/dev/null
done

echo "[$(date)] DONE: $DOMAIN now on PHP $NEW_VER" >> "$LOG"
PHPSWITCH
chmod +x ${FLYNE_DIR}/scripts/php-switch.sh
ln -sf ${FLYNE_DIR}/scripts/php-switch.sh /opt/flyne/php-switch.sh

#===============================================================================
# CRON JOBS
#===============================================================================
log "Setting up cron jobs..."
cat > /etc/cron.d/flyne << CRONEOF
# Flyne Engine Cron Jobs
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Expire SFTP access
*/5 * * * * root mysql -u root -p'${MYSQL_ROOT_PASS}' -N -e "SELECT username FROM flyne_engine.sftp_access WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_enabled = 1" 2>/dev/null | while read user; do usermod -L "\$user" 2>/dev/null; mysql -u root -p'${MYSQL_ROOT_PASS}' -e "UPDATE flyne_engine.sftp_access SET is_enabled=0 WHERE username='\$user'" 2>/dev/null; done

# Clean nginx cache older than 7 days
0 3 * * * root find /var/cache/nginx/fastcgi -type f -mtime +7 -delete 2>/dev/null

# Clean old backups (30 days)
0 4 * * 0 root find /opt/flyne/backups -type f -mtime +30 -delete 2>/dev/null

# Optimize all databases weekly
0 5 * * 0 root mysqlcheck -u root -p'${MYSQL_ROOT_PASS}' --optimize --all-databases 2>/dev/null

# Clear OPcache daily
0 6 * * * root find /tmp/opcache -type f -mtime +1 -delete 2>/dev/null

# WordPress cron for all sites
*/5 * * * * www-data for site in /var/www/sites/*/public/wp-cron.php; do [ -f "\$site" ] && php "\$site" 2>/dev/null; done
CRONEOF
chmod 644 /etc/cron.d/flyne

#===============================================================================
# SUDOERS
#===============================================================================
log "Setting up permissions..."
cat > /etc/sudoers.d/flyne << 'SUDOERS'
# Flyne Engine Sudoers

www-data ALL=(ALL) NOPASSWD: /usr/sbin/useradd *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/userdel *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/usermod *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd
www-data ALL=(ALL) NOPASSWD: /bin/mkdir *
www-data ALL=(ALL) NOPASSWD: /bin/chown *
www-data ALL=(ALL) NOPASSWD: /bin/chmod *
www-data ALL=(ALL) NOPASSWD: /bin/rm -rf /var/www/sites/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/sites-flyne/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /etc/php/*/fpm/pool.d/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -f /run/php/*
www-data ALL=(ALL) NOPASSWD: /bin/rm -rf /var/cache/nginx/fastcgi/*
www-data ALL=(ALL) NOPASSWD: /bin/touch *
www-data ALL=(ALL) NOPASSWD: /bin/ln *
www-data ALL=(ALL) NOPASSWD: /usr/bin/rsync *
www-data ALL=(ALL) NOPASSWD: /bin/tar *
www-data ALL=(ALL) NOPASSWD: /usr/bin/certbot *
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload php*-fpm
www-data ALL=(ALL) NOPASSWD: /bin/systemctl restart php*-fpm
www-data ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
www-data ALL=(ALL) NOPASSWD: /usr/bin/du *
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysqldump *
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysql *
www-data ALL=(ALL) NOPASSWD: /opt/flyne/scripts/php-switch.sh *
www-data ALL=(ALL) NOPASSWD: /opt/flyne/php-switch.sh *
SUDOERS
chmod 440 /etc/sudoers.d/flyne

#===============================================================================
# FAIL2BAN
#===============================================================================
log "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'F2BCONF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
port = http,https
maxretry = 3

[wordpress-hard]
enabled = true
filter = wordpress-hard
logpath = /var/www/sites/*/logs/access.log
maxretry = 3
bantime = 86400
F2BCONF

cat > /etc/fail2ban/filter.d/wordpress-hard.conf << 'F2BFILTER'
[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php
            ^<HOST> .* "POST /xmlrpc\.php
ignoreregex =
F2BFILTER

systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban || warn "Fail2ban restart failed"

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

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

case "$1" in
    status)
        echo -e "${BLUE}=== Flyne Engine Status ===${NC}"
        echo ""
        for svc in nginx mariadb redis-server; do
            systemctl is-active --quiet $svc && echo -e "$svc: ${GREEN}✓ Running${NC}" || echo -e "$svc: ${RED}✗ Stopped${NC}"
        done
        for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
            systemctl is-active --quiet php${v}-fpm 2>/dev/null && echo -e "PHP ${v}: ${GREEN}✓ Running${NC}"
        done
        echo ""
        echo -e "Sites: ${YELLOW}$(mysql -u root -p"$MYSQL_ROOT_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites" 2>/dev/null || echo 0)${NC}"
        echo -e "API: ${BLUE}https://${API_DOMAIN}${NC}"
        ;;
        
    sites)
        mysql -u root -p"$MYSQL_ROOT_PASS" -e "SELECT domain, php_version, status, ssl_enabled, created_at FROM flyne_engine.sites" 2>/dev/null
        ;;
        
    create)
        [[ -z "$2" ]] && echo "Usage: flyne create domain.com [email]" && exit 1
        DOMAIN="$2"
        EMAIL="${3:-admin@$DOMAIN}"
        echo -e "Creating site ${YELLOW}$DOMAIN${NC}..."
        # Use direct PHP for reliability
        php -d max_execution_time=900 -r "
            \$_SERVER['FLYNE_API_SECRET'] = '${API_SECRET}';
            \$_SERVER['FLYNE_MYSQL_PASS'] = '${MYSQL_ROOT_PASS}';
            \$_SERVER['FLYNE_REDIS_PASS'] = '${REDIS_PASS}';
            \$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ${API_SECRET}';
            \$_POST['action'] = 'create_site';
            \$_POST['domain'] = '$DOMAIN';
            \$_POST['admin_email'] = '$EMAIL';
            chdir('/opt/flyne');
            include '/opt/flyne/index.php';
        " | jq . 2>/dev/null || cat
        ;;
        
    delete)
        [[ -z "$2" ]] && echo "Usage: flyne delete domain.com" && exit 1
        read -p "Are you sure you want to delete $2? [y/N] " confirm
        [[ "$confirm" != "y" ]] && exit 0
        curl -sk -X POST "https://${API_DOMAIN}/index.php" \
            -H "Authorization: Bearer ${API_SECRET}" \
            -d "action=delete_site&domain=$2" | jq . 2>/dev/null || cat
        ;;
        
    cache-clear)
        echo "Clearing all caches..."
        rm -rf /var/cache/nginx/fastcgi/*
        redis-cli -a "$REDIS_PASS" FLUSHALL 2>/dev/null
        find /tmp/opcache -type f -delete 2>/dev/null
        echo -e "${GREEN}Cache cleared!${NC}"
        ;;
        
    test)
        echo "Testing API..."
        curl -sk "https://${API_DOMAIN}/index.php?action=site_list" \
            -H "Authorization: Bearer ${API_SECRET}" | jq . 2>/dev/null || echo "API test failed"
        ;;
        
    logs)
        [[ -z "$2" ]] && tail -f /var/log/flyne/*.log || tail -f /var/www/sites/$2/logs/*.log
        ;;
        
    *)
        echo -e "${BLUE}Flyne Engine CLI${NC}"
        echo ""
        echo "Commands:"
        echo "  status              Show system status"
        echo "  sites               List all sites"
        echo "  create <domain>     Create new WordPress site"
        echo "  delete <domain>     Delete a site"
        echo "  cache-clear         Clear all caches"
        echo "  test                Test API connection"
        echo "  logs [domain]       View logs"
        ;;
esac
CLIFILE
chmod +x /usr/local/bin/flyne

#===============================================================================
# KERNEL TUNING
#===============================================================================
log "Applying kernel optimizations..."
cat > /etc/sysctl.d/99-flyne-performance.conf << 'SYSCTL'
# Network Performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65535
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# Memory
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50

# File System
fs.file-max = 2097152
fs.nr_open = 2097152
fs.inotify.max_user_watches = 524288
SYSCTL
sysctl -p /etc/sysctl.d/99-flyne-performance.conf 2>/dev/null || warn "Some kernel parameters could not be applied"

# File limits
cat > /etc/security/limits.d/flyne.conf << 'LIMITS'
* soft nofile 65535
* hard nofile 65535
www-data soft nofile 65535
www-data hard nofile 65535
root soft nofile 65535
root hard nofile 65535
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
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) 2>/dev/null
    endscript
}
LOGROTATE

#===============================================================================
# DOWNLOAD INDEX.PHP
#===============================================================================
log "Downloading API file..."
wget -qO ${FLYNE_DIR}/index.php https://raw.githubusercontent.com/Flynecom/flyne/main/index.php || {
    warn "Failed to download index.php - download manually"
}

if [[ -f "${FLYNE_DIR}/index.php" ]]; then
    chown www-data:www-data ${FLYNE_DIR}/index.php
    chmod 644 ${FLYNE_DIR}/index.php
    log "API file downloaded successfully!"
else
    warn "index.php not found - upload manually to ${FLYNE_DIR}/"
fi

#===============================================================================
# FINAL VERIFICATION
#===============================================================================
log "Verifying installation..."
ERRORS=0

nginx -t &>/dev/null || { warn "Nginx config test failed"; ERRORS=$((ERRORS + 1)); }
systemctl is-active --quiet mariadb || { warn "MariaDB not running"; ERRORS=$((ERRORS + 1)); }
systemctl is-active --quiet redis-server || { warn "Redis not running"; ERRORS=$((ERRORS + 1)); }
systemctl is-active --quiet php8.4-fpm || { warn "PHP 8.4 FPM not running"; ERRORS=$((ERRORS + 1)); }
mysql -u root -p"${MYSQL_ROOT_PASS}" -e "SELECT 1" &>/dev/null || { warn "MySQL connection failed"; ERRORS=$((ERRORS + 1)); }

[[ $ERRORS -gt 0 ]] && warn "Completed with $ERRORS warning(s)" || log "All services verified!"
#===============================================================================
# OUTPUT
#===============================================================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   FLYNE ENGINE v2.5 INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Performance Features:${NC}"
echo -e "  ✓ FastCGI Page Cache (10GB)"
echo -e "  ✓ Redis Object Cache (${REDIS_MEM}MB)"
echo -e "  ✓ OPcache with JIT (512MB + 256MB JIT)"
echo -e "  ✓ MariaDB Query Cache (${QUERY_CACHE})"
echo -e "  ✓ HTTP/2 enabled"
echo -e "  ✓ Gzip compression"
echo -e "  ✓ Static file caching (1 year)"
echo ""
echo -e "${BLUE}System Resources:${NC}"
echo -e "  RAM:           ${TOTAL_RAM}MB"
echo -e "  CPU Cores:     ${CPU_CORES}"
echo -e "  InnoDB Buffer: ${INNODB_BUFFER}"
echo -e "  PHP Workers:   ${PHP_MAX_CHILDREN}"
echo ""
echo -e "${BLUE}URLs:${NC}"
echo -e "  API:        ${CYAN}https://${API_DOMAIN}${NC}"
echo -e "  phpMyAdmin: ${CYAN}https://${PMA_DOMAIN}${NC}"
echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}   CREDENTIALS - SAVE THESE SECURELY!${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  API Secret:     ${YELLOW}${API_SECRET}${NC}"
echo -e "  MySQL Root:     ${YELLOW}${MYSQL_ROOT_PASS}${NC}"
echo -e "  Redis Password: ${YELLOW}${REDIS_PASS}${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo -e "  ${CYAN}flyne test${NC}                    # Test API"
echo -e "  ${CYAN}flyne create example.com${NC}      # Create site"
echo -e "  ${CYAN}flyne status${NC}                  # System status"
echo ""

# Save credentials to file
cat > ${FLYNE_DIR}/credentials.txt << CREDEOF
=== FLYNE ENGINE CREDENTIALS ===
Generated: $(date)

API Domain:    https://${API_DOMAIN}
PMA Domain:    https://${PMA_DOMAIN}

API Secret:    ${API_SECRET}
MySQL Root:    ${MYSQL_ROOT_PASS}
Redis Pass:    ${REDIS_PASS}
Admin Email:   ${ADMIN_EMAIL}

Performance Settings:
- InnoDB Buffer: ${INNODB_BUFFER}
- Redis Memory: ${REDIS_MEM}MB
- PHP Workers: ${PHP_MAX_CHILDREN}
- Query Cache: ${QUERY_CACHE}

DELETE THIS FILE AFTER SAVING CREDENTIALS SECURELY!
CREDEOF
chmod 600 ${FLYNE_DIR}/credentials.txt

echo -e "Credentials saved to: ${YELLOW}${FLYNE_DIR}/credentials.txt${NC}"
echo -e "${RED}Delete this file after saving credentials securely!${NC}"
echo ""
log "Installation complete! Run 'flyne create yourdomain.com' to create your first site."
echo ""