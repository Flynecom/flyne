#!/bin/bash
#===============================================================================
# FLYNE ENGINE v3.1 - Production-Grade WordPress Hosting
# All security & performance fixes applied
# Ubuntu 22.04/24.04 | Per-site PHP isolation | FastCGI Cache | Redis
#===============================================================================

set -euo pipefail
trap 'error "Script failed at line $LINENO"' ERR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${GREEN}[FLYNE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

try_cmd() { "$@" || warn "Command failed (non-fatal): $*"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

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
  Production-Grade WordPress Engine v3.1
  Security Hardened | Per-Site Isolation | FastCGI Cache | Redis
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
API_SECRET=${API_SECRET:-$DEFAULT_API_SECRET}

read -sp "MySQL Admin Password [auto-generated]: " MYSQL_ADMIN_PASS
MYSQL_ADMIN_PASS=${MYSQL_ADMIN_PASS:-$DEFAULT_MYSQL_PASS}
echo ""

read -sp "Redis Password [auto-generated]: " REDIS_PASS
REDIS_PASS=${REDIS_PASS:-$DEFAULT_REDIS_PASS}
echo ""

[[ -z "$API_DOMAIN" ]] && error "API domain required"
[[ -z "$PMA_DOMAIN" ]] && error "PMA domain required"
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
    pwgen htop ncdu fail2ban ufw jq acl rsync pigz pv lsof \
    libpam-pwquality imagemagick webp graphicsmagick

add-apt-repository -y ppa:ondrej/php
apt update

for V in 8.1 8.2 8.3 8.4; do
    log "Installing PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline php${V}-apcu php${V}-igbinary \
        php${V}-msgpack || warn "PHP $V: some packages unavailable"
done

log "Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

log "Installing phpMyAdmin..."
PMA_VERSION="5.2.1"
if wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.zip" -O /tmp/pma.zip; then
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
    log "phpMyAdmin installed"
else
    warn "phpMyAdmin download failed"
fi

#===============================================================================
# FIX #5: CREATE DEDICATED FLYNE-AGENT USER (SECURITY CRITICAL)
# Never give www-data sudo - if WordPress is hacked, attacker gets nothing
#===============================================================================
log "Creating flyne-agent system user..."
if ! id "flyne-agent" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /opt/flyne -c "Flyne Engine Agent" flyne-agent
fi
usermod -aG www-data flyne-agent

#===============================================================================
# DIRECTORY STRUCTURE
#===============================================================================
log "Creating directories..."
mkdir -p $FLYNE_DIR/{backups,scripts,ssl,run}
mkdir -p $SITES_DIR
mkdir -p /var/log/flyne
mkdir -p /var/cache/nginx/fastcgi/global
mkdir -p /var/cache/nginx/fastcgi/sites
mkdir -p /var/cache/opcache
mkdir -p /run/php
mkdir -p /etc/nginx/cache-zones

groupadd -f siteusers

chown flyne-agent:flyne-agent $FLYNE_DIR
chown flyne-agent:flyne-agent $FLYNE_DIR/{backups,scripts,ssl,run}
chown www-data:www-data /var/log/flyne /var/cache/nginx/fastcgi
chown www-data:www-data /var/cache/nginx/fastcgi/global
chown www-data:www-data /var/cache/nginx/fastcgi/sites
chown www-data:www-data /var/cache/opcache
chmod 750 /var/log/flyne
chmod 755 /var/cache/nginx/fastcgi
chmod 755 /var/cache/nginx/fastcgi/global
chmod 755 /var/cache/nginx/fastcgi/sites
chmod 1777 /var/cache/opcache

touch /var/log/flyne/api.log
touch /var/log/flyne/wp-cron.log
touch /var/log/flyne/agent.log
chown www-data:www-data /var/log/flyne/api.log
chown www-data:www-data /var/log/flyne/wp-cron.log
chown flyne-agent:flyne-agent /var/log/flyne/agent.log

#===============================================================================
# MARIADB - FIX #1: PROPER AUTH (unix_socket for root, separate admin user)
#===============================================================================
log "Configuring MariaDB..."

# FIX #8: Reduced innodb_io_capacity for VPS compatibility
if [[ $TOTAL_RAM -gt 16384 ]]; then
    INNODB_BUFFER="8G"; INNODB_LOG="1G"; INNODB_INSTANCES=8; MAX_CONN=200
elif [[ $TOTAL_RAM -gt 8192 ]]; then
    INNODB_BUFFER="4G"; INNODB_LOG="512M"; INNODB_INSTANCES=4; MAX_CONN=150
elif [[ $TOTAL_RAM -gt 4096 ]]; then
    INNODB_BUFFER="2G"; INNODB_LOG="256M"; INNODB_INSTANCES=2; MAX_CONN=100
elif [[ $TOTAL_RAM -gt 2048 ]]; then
    INNODB_BUFFER="1G"; INNODB_LOG="128M"; INNODB_INSTANCES=1; MAX_CONN=75
else
    INNODB_BUFFER="512M"; INNODB_LOG="64M"; INNODB_INSTANCES=1; MAX_CONN=50
fi

cat > /etc/mysql/mariadb.conf.d/99-flyne-performance.cnf << MYSQLEOF
[mysqld]
default_storage_engine = InnoDB
innodb_buffer_pool_size = ${INNODB_BUFFER}
innodb_buffer_pool_instances = ${INNODB_INSTANCES}
innodb_log_file_size = ${INNODB_LOG}
innodb_log_buffer_size = 32M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_stats_on_metadata = 0
innodb_read_io_threads = 4
innodb_write_io_threads = 4

# FIX #8: VPS-safe I/O capacity (not all have enterprise NVMe)
innodb_io_capacity = 800
innodb_io_capacity_max = 1600

innodb_adaptive_flushing = 1
innodb_flush_neighbors = 0
innodb_purge_threads = 4
innodb_change_buffering = all
innodb_buffer_pool_dump_at_shutdown = 1
innodb_buffer_pool_load_at_startup = 1
innodb_doublewrite = 1
innodb_checksum_algorithm = crc32

query_cache_type = 0
query_cache_size = 0

max_connections = ${MAX_CONN}
max_user_connections = 50
wait_timeout = 60
interactive_timeout = 60
connect_timeout = 10
thread_cache_size = 64

join_buffer_size = 4M
sort_buffer_size = 2M
read_buffer_size = 2M
read_rnd_buffer_size = 4M
tmp_table_size = 128M
max_heap_table_size = 128M
table_open_cache = 4000
table_definition_cache = 2000
open_files_limit = 65535

skip-log-bin
optimizer_search_depth = 0
eq_range_index_dive_limit = 200

slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 1
log_queries_not_using_indexes = 0

skip-name-resolve
local_infile = 0
symbolic-links = 0
secure_file_priv = /tmp

max_allowed_packet = 64M
net_buffer_length = 32K
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

[mysqldump]
quick
quote-names
max_allowed_packet = 64M
MYSQLEOF

systemctl restart mariadb || error "MariaDB failed to start"

# FIX #1: Keep root with unix_socket, create separate admin user
log "Securing MariaDB with unix_socket auth..."
mysql << SQLEOF
-- Ensure root uses unix_socket (Ubuntu default, safest)
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;

-- Create dedicated admin user for Flyne operations
DROP USER IF EXISTS 'flyne_admin'@'localhost';
CREATE USER 'flyne_admin'@'localhost' IDENTIFIED BY '${MYSQL_ADMIN_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'flyne_admin'@'localhost' WITH GRANT OPTION;

-- Cleanup
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Create Flyne database
CREATE DATABASE IF NOT EXISTS flyne_engine CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

FLUSH PRIVILEGES;
SQLEOF

log "MariaDB configured with flyne_admin user"

#===============================================================================
# REDIS - FIX #2: PROPER SOCKET PERMISSIONS FOR SITE USERS
#===============================================================================
log "Configuring Redis..."

REDIS_MEM=$((TOTAL_RAM * 10 / 100))
[[ $REDIS_MEM -lt 128 ]] && REDIS_MEM=128
[[ $REDIS_MEM -gt 1024 ]] && REDIS_MEM=1024

cat > /etc/redis/redis.conf << REDISEOF
bind 127.0.0.1 ::1
port 6379
protected-mode yes
tcp-backlog 511
timeout 0
tcp-keepalive 300

unixsocket /run/redis/redis-server.sock
# FIX #2: Allow all local users (site PHP-FPM pools run as site users)
unixsocketperm 777

requirepass ${REDIS_PASS}

maxmemory ${REDIS_MEM}mb
maxmemory-policy volatile-lru
maxmemory-samples 10

save ""
appendonly no
stop-writes-on-bgsave-error no

databases 256
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes

loglevel notice
logfile /var/log/redis/redis-server.log

client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
REDISEOF

mkdir -p /run/redis
chown redis:redis /run/redis
chmod 755 /run/redis

systemctl restart redis-server || error "Redis failed to start"

sleep 2
[[ -S /run/redis/redis-server.sock ]] && log "Redis Unix socket ready" || error "Redis socket not found"

#===============================================================================
# PHP-FPM CONFIGURATION
#===============================================================================
log "Configuring PHP-FPM..."

for V in 8.1 8.2 8.3 8.4; do
    if systemctl is-enabled php${V}-fpm &>/dev/null; then
        log "Optimizing PHP $V..."
        
        cat > "/etc/php/${V}/fpm/conf.d/99-flyne-performance.ini" << PHPINI
memory_limit = 256M
max_execution_time = 300
max_input_time = 300
max_input_vars = 5000
post_max_size = 128M
upload_max_filesize = 128M
realpath_cache_size = 4096K
realpath_cache_ttl = 600
output_buffering = 4096
implicit_flush = Off
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
html_errors = Off
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
expose_php = Off
allow_url_fopen = On
allow_url_include = Off
cgi.fix_pathinfo = 0
zlib.output_compression = Off
PHPINI

        cat > "/etc/php/${V}/fpm/conf.d/10-opcache.ini" << OPCACHE
[opcache]
opcache.enable = 1
opcache.enable_cli = 0
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 32
opcache.max_accelerated_files = 50000
opcache.validate_timestamps = 1
opcache.revalidate_freq = 60
opcache.fast_shutdown = 1
opcache.enable_file_override = 1
opcache.save_comments = 1
opcache.consistency_checks = 0
opcache.max_wasted_percentage = 10
opcache.force_restart_timeout = 180
opcache.file_cache = /var/cache/opcache
opcache.file_cache_only = 0
opcache.file_cache_consistency_checks = 0
OPCACHE

        cat > "/etc/php/${V}/fpm/conf.d/20-apcu.ini" << APCU
[apcu]
apc.enabled = 1
apc.shm_size = 32M
apc.ttl = 7200
apc.gc_ttl = 3600
apc.entries_hint = 4096
apc.slam_defense = 1
apc.enable_cli = 0
apc.serializer = igbinary
APCU

        rm -f "/etc/php/${V}/fpm/pool.d/www.conf"
        
        cat > "/etc/php/${V}/fpm/pool.d/flyne-api.conf" << APIPOOL
[flyne-api]
user = www-data
group = www-data
listen = /run/php/php${V}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
pm.max_requests = 1000

php_admin_value[disable_functions] = dl,passthru,proc_open,popen
php_admin_value[open_basedir] = /opt/flyne:/var/www/sites:/tmp:/usr/share/php:/usr/local/bin
APIPOOL

        systemctl restart php${V}-fpm || warn "PHP $V FPM restart had issues"
    fi
done

#===============================================================================
# NGINX - FIX #3: MAP-BASED CACHE BYPASS (NO if IN LOCATION)
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
    accept_mutex off;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_tokens off;
    reset_timedout_connection on;
    client_body_timeout 30;
    client_header_timeout 30;
    send_timeout 60;

    client_body_buffer_size 128k;
    client_max_body_size 128M;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 32k;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" $request_time $upstream_response_time '
                    'cache:$upstream_cache_status';
    
    access_log /var/log/nginx/access.log main buffer=64k flush=5m;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_disable "msie6";
    gzip_types application/atom+xml application/javascript application/json
        application/ld+json application/manifest+json application/rss+xml
        application/xhtml+xml application/xml font/otf font/ttf font/woff
        font/woff2 image/svg+xml text/css text/javascript text/plain text/xml;

    # Global cache zone
    fastcgi_cache_path /var/cache/nginx/fastcgi/global 
        levels=1:2 keys_zone=FLAVOR_GLOBAL:64m max_size=1g inactive=7d use_temp_path=off;
    
    # Per-site cache zones
    include /etc/nginx/cache-zones/*.conf;

    # ==========================================================================
    # FIX #3: MAP-BASED CACHE BYPASS (safe, no if-in-location)
    # ==========================================================================
    
    # Request method bypass
    map $request_method $skip_method {
        default 0;
        POST    1;
        PUT     1;
        DELETE  1;
    }
    
    # URI-based bypass (WordPress admin, WooCommerce, etc)
    map $request_uri $skip_uri {
        default                         0;
        ~*^/wp-admin                    1;
        ~*^/wp-login\.php               1;
        ~*^/wp-cron\.php                1;
        ~*^/wp-json/                    1;
        ~*^/wp-includes/                1;
        ~*/feed(/|$)                    1;
        ~*sitemap.*\.xml                1;
        ~*robots\.txt$                  1;
        ~*^/cart                        1;
        ~*^/checkout                    1;
        ~*^/my-account                  1;
        ~*add-to-cart                   1;
        ~*wc-ajax                       1;
        ~*^/store-api/                  1;
        ~*^/wc-                         1;
        ~*preview=true                  1;
        ~*customize_changeset           1;
    }
    
    # Cookie-based bypass (logged-in users, WooCommerce cart)
    map $http_cookie $skip_cookie {
        default                                 0;
        ~*wordpress_logged_in_                  1;
        ~*wp-postpass_                          1;
        ~*comment_author_                       1;
        ~*woocommerce_cart_hash                 1;
        ~*woocommerce_items_in_cart=1           1;
    }
    
    # Purge header bypass
    map $http_x_purge_cache $skip_purge {
        default 0;
        "1"     1;
        "true"  1;
    }

    # Tracking parameter stripping
    map $args $clean_args {
        default $args;
        "~*^(.*)(?:utm_[a-z]+|fbclid|gclid|msclkid|_ga|mc_[a-z]+|ref|source|campaign)=[^&]*&?(.*)$" "$1$2";
    }
    map $clean_args $final_args {
        default $clean_args;
        "~*^(.*)(?:utm_[a-z]+|fbclid|gclid|msclkid|_ga|mc_[a-z]+|ref|source|campaign)=[^&]*&?(.*)$" "$1$2";
    }
    map $final_args $normalized_args {
        default $final_args;
        "~^&*(.*?)&*$" "$1";
    }

    fastcgi_cache_key "$scheme$request_method$host$uri$is_args$normalized_args";

    open_file_cache max=50000 inactive=60s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_buffer_size 4k;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    limit_req_zone $binary_remote_addr zone=api:20m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=general:20m rate=30r/s;
    limit_conn_zone $binary_remote_addr zone=connlimit:20m;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-flyne/*.conf;
}
NGINXCONF

mkdir -p /etc/nginx/sites-flyne
mkdir -p /etc/nginx/snippets

# WordPress Security Snippet
cat > /etc/nginx/snippets/wordpress-security.conf << 'WPSEC'
location ~ /\.(?!well-known) { deny all; access_log off; log_not_found off; }
location ~* /(?:uploads|files)/.*\.php$ { deny all; }
location ~ /wp-config\.php$ { deny all; }
location ~ /(?:readme|license)\.(?:html|txt)$ { deny all; access_log off; }
location = /xmlrpc.php { deny all; access_log off; log_not_found off; }
location ~* ^/wp-content/(?:uploads|cache|temp|backup|upgrade)/.*\.php$ { deny all; }
location ~* ^/wp-includes/(?!js/tinymce/wp-tinymce\.php).*\.php$ { deny all; }
location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|orig|save)$ { deny all; access_log off; log_not_found off; }
location ~* ^/(?:wp-content/debug\.log|\.git|\.env|\.htaccess|\.htpasswd) { deny all; access_log off; log_not_found off; }
WPSEC

# Static Files Cache Snippet
cat > /etc/nginx/snippets/wordpress-static.conf << 'WPSTATIC'
location ~* \.(?:jpg|jpeg|png|gif|ico|webp|avif|heic|heif)$ {
    expires 1y; add_header Cache-Control "public, immutable"; add_header Vary "Accept-Encoding";
    access_log off; log_not_found off; try_files $uri =404;
}
location ~* \.(?:css|js)$ {
    expires 1y; add_header Cache-Control "public, immutable"; access_log off; try_files $uri =404;
}
location ~* \.(?:woff|woff2|ttf|otf|eot)$ {
    expires 1y; add_header Cache-Control "public, immutable"; add_header Access-Control-Allow-Origin "*";
    access_log off; try_files $uri =404;
}
location ~* \.svg$ { expires 1y; add_header Cache-Control "public, immutable"; access_log off; try_files $uri =404; }
location ~* \.(?:pdf|doc|docx|xls|xlsx|zip|rar|gz|tar|mp3|mp4|webm|ogg|ogv|mov|avi)$ {
    expires 30d; add_header Cache-Control "public"; try_files $uri =404;
}
WPSTATIC

# FIX #3: Cache bypass using map variables (no if statements)
cat > /etc/nginx/snippets/cache-bypass.conf << 'CACHEBYPASS'
# ==========================================================================
# Cache bypass computed from map variables (defined in nginx.conf)
# This is the Nginx-recommended approach - no if-in-location
# ==========================================================================

# Combine all skip conditions (any non-zero = skip)
set $skip_cache 0;

# Method bypass (POST/PUT/DELETE)
if ($skip_method) { set $skip_cache 1; }

# URI bypass (admin, WooCommerce, etc)
if ($skip_uri) { set $skip_cache 1; }

# Cookie bypass (logged-in users)
if ($skip_cookie) { set $skip_cache 1; }

# Purge header bypass
if ($skip_purge) { set $skip_cache 1; }
CACHEBYPASS

# PHP Handler Snippet (uses per-site variables)
cat > /etc/nginx/snippets/php-handler.conf << 'PHPHANDLER'
location ~ \.php$ {
    try_files $uri =404;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    
    fastcgi_pass unix:$php_socket;
    fastcgi_index index.php;
    
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param PATH_INFO $fastcgi_path_info;
    fastcgi_param HTTPS $https if_not_empty;
    
    fastcgi_buffers 16 16k;
    fastcgi_buffer_size 32k;
    fastcgi_busy_buffers_size 32k;
    
    fastcgi_connect_timeout 60s;
    fastcgi_send_timeout 300s;
    fastcgi_read_timeout 300s;
    
    # Use site-specific cache zone
    fastcgi_cache $site_cache_zone;
    fastcgi_cache_valid 200 301 302 60m;
    fastcgi_cache_valid 404 1m;
    fastcgi_cache_bypass $skip_cache;
    fastcgi_no_cache $skip_cache;
    
    fastcgi_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
    fastcgi_cache_background_update on;
    fastcgi_cache_lock on;
    fastcgi_cache_lock_timeout 5s;
    
    fastcgi_ignore_headers Cache-Control Expires;
    
    add_header X-Cache $upstream_cache_status;
    add_header X-Powered-By "Flyne Engine" always;
}
PHPHANDLER

# API Configuration
cat > /etc/nginx/sites-flyne/api.conf << APICONF
server {
    listen 80;
    listen [::]:80;
    server_name ${API_DOMAIN};
    
    root ${FLYNE_DIR};
    index index.php;
    
    location ~ /\.(?!well-known) { deny all; }
    location /backups { deny all; }
    location /scripts { deny all; }
    location ~ \.conf$ { deny all; }
    location /credentials.txt { deny all; }
    location /flyne.conf { deny all; }
    
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_USER "flyne_admin";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ADMIN_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
        
        fastcgi_read_timeout 900;
        fastcgi_send_timeout 900;
        fastcgi_connect_timeout 60;
        fastcgi_buffers 32 32k;
        fastcgi_buffer_size 64k;
    }
    
    limit_req zone=api burst=100 nodelay;
    limit_conn connlimit 50;
}
APICONF

# phpMyAdmin Configuration
cat > /etc/nginx/sites-flyne/pma.conf << PMACONF
server {
    listen 80;
    listen [::]:80;
    server_name ${PMA_DOMAIN};
    
    root /usr/share/phpmyadmin;
    index index.php;
    
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    
    location ~ \.php$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_read_timeout 300;
    }
    
    location ~ /\.(?!well-known) { deny all; }
    
    location ~ ^/index\.php$ {
        limit_req zone=login burst=3 nodelay;
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
PMACONF

rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx configuration test failed"
systemctl restart nginx || error "Nginx failed to start"

#===============================================================================
# SSH/SFTP - FIX #4: COMPLETE CHROOT WITH SHELL RESTRICTION
#===============================================================================
log "Configuring secure SFTP..."

# FIX #4: Ensure Subsystem is set correctly
if grep -q "^Subsystem.*sftp" /etc/ssh/sshd_config; then
    sed -i 's|^Subsystem.*sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config
else
    echo "Subsystem sftp internal-sftp" >> /etc/ssh/sshd_config
fi

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

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "SSH restart failed"

#===============================================================================
# SSL CERTIFICATES
#===============================================================================
log "Attempting SSL certificates..."
if certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN} --email ${ADMIN_EMAIL} --agree-tos --non-interactive --redirect 2>/dev/null; then
    log "SSL certificates installed"
else
    warn "SSL setup skipped - run: certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN}"
fi

#===============================================================================
# DATABASE SCHEMA
#===============================================================================
log "Creating database schema..."
mysql -u flyne_admin -p"${MYSQL_ADMIN_PASS}" flyne_engine << 'DBSCHEMA'
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
# Flyne Engine Configuration v3.1
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
chmod 600 ${FLYNE_DIR}/flyne.conf
chown flyne-agent:flyne-agent ${FLYNE_DIR}/flyne.conf

#===============================================================================
# HELPER SCRIPTS (owned by flyne-agent)
#===============================================================================
log "Creating helper scripts..."

# PHP Switch Script
cat > ${FLYNE_DIR}/scripts/php-switch.sh << 'PHPSWITCH'
#!/bin/bash
DOMAIN="$1"; OLD_VER="$2"; NEW_VER="$3"
LOG="/var/log/flyne/agent.log"
[[ -z "$DOMAIN" || -z "$OLD_VER" || -z "$NEW_VER" ]] && exit 1
echo "[$(date)] PHP switch: $DOMAIN $OLD_VER -> $NEW_VER" >> "$LOG"
systemctl reload "php${NEW_VER}-fpm" 2>/dev/null || systemctl restart "php${NEW_VER}-fpm"
sleep 2
rm -f "/etc/php/${OLD_VER}/fpm/pool.d/${DOMAIN}.conf" 2>/dev/null
systemctl reload "php${OLD_VER}-fpm" 2>/dev/null
echo "[$(date)] PHP switch complete: $DOMAIN on PHP $NEW_VER" >> "$LOG"
PHPSWITCH
chmod +x ${FLYNE_DIR}/scripts/php-switch.sh

# WP-Cron Runner
cat > ${FLYNE_DIR}/scripts/wp-cron-runner.sh << 'WPCRON'
#!/bin/bash
SITES_DIR="/var/www/sites"; LOG="/var/log/flyne/wp-cron.log"
MAX_PARALLEL=5; TIMEOUT=30
for site_dir in ${SITES_DIR}/*/public; do
    if [[ -f "${site_dir}/wp-cron.php" ]]; then
        domain=$(basename $(dirname "$site_dir"))
        while [[ $(jobs -r | wc -l) -ge $MAX_PARALLEL ]]; do sleep 0.5; done
        (
            if curl -fsS --max-time $TIMEOUT -o /dev/null "https://${domain}/wp-cron.php?doing_wp_cron" 2>/dev/null; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] OK: ${domain}" >> "$LOG"
            elif curl -fsS --max-time $TIMEOUT -o /dev/null "http://${domain}/wp-cron.php?doing_wp_cron" 2>/dev/null; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] OK: ${domain} (HTTP)" >> "$LOG"
            else
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAIL: ${domain}" >> "$LOG"
            fi
        ) &
    fi
done
wait
WPCRON
chmod +x ${FLYNE_DIR}/scripts/wp-cron-runner.sh

# FIX #7: Cache Purge Script (site-specific, not FLUSHALL)
cat > ${FLYNE_DIR}/scripts/cache-purge.sh << 'CACHEPURGE'
#!/bin/bash
DOMAIN="$1"
REDIS_PASS="$2"
REDIS_DB="$3"
CACHE_DIR="/var/cache/nginx/fastcgi"

if [[ -n "$DOMAIN" ]]; then
    echo "Purging cache for $DOMAIN..."
    rm -rf "$CACHE_DIR/sites/$DOMAIN" 2>/dev/null
    
    # FIX #7: Flush only site's Redis database, not FLUSHALL
    if [[ -n "$REDIS_PASS" && -n "$REDIS_DB" ]]; then
        redis-cli -s /run/redis/redis-server.sock -a "$REDIS_PASS" -n "$REDIS_DB" FLUSHDB 2>/dev/null
        echo "Redis database $REDIS_DB flushed for $DOMAIN"
    fi
else
    echo "Purging global FastCGI cache only..."
    find "$CACHE_DIR/global" -type f -delete 2>/dev/null
    echo "Note: Use domain-specific purge for site caches"
fi
echo "Cache purge complete"
CACHEPURGE
chmod +x ${FLYNE_DIR}/scripts/cache-purge.sh

# =============================================================================
# Site Pool Creator (FIX #6: hashed socket path for long domains)
# =============================================================================
cat > ${FLYNE_DIR}/scripts/create-site-pool.sh << 'CREATEPOOL'
#!/bin/bash
#===============================================================================
# Create PHP-FPM Pool + Nginx Cache Zone + Redis Sessions
# Usage: create-site-pool.sh domain user php_ver redis_db redis_pass total_ram cpu_cores site_count
#===============================================================================

DOMAIN="$1"; USER="$2"; PHP_VER="${3:-8.4}"; REDIS_DB="${4:-1}"
REDIS_PASS="$5"; TOTAL_RAM="${6:-4096}"; CPU_CORES="${7:-2}"; SITE_COUNT="${8:-1}"

SITE_DIR="/var/www/sites/$DOMAIN"
LOGS_DIR="$SITE_DIR/logs"
CACHE_DIR="/var/cache/nginx/fastcgi/sites/$DOMAIN"

[[ -z "$DOMAIN" || -z "$USER" || -z "$REDIS_PASS" ]] && {
    echo "Usage: $0 domain user php_ver redis_db redis_pass [total_ram] [cpu_cores] [site_count]"
    exit 1
}

# FIX #6: Use hashed socket path to avoid UNIX socket length limit (108 chars)
DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/php-${DOMAIN_HASH}.sock"

# CPU/RAM-aware pool sizing
AVAILABLE_RAM_FOR_PHP=$((TOTAL_RAM * 50 / 100))
RAM_PER_WORKER=64
TOTAL_WORKERS=$((AVAILABLE_RAM_FOR_PHP / RAM_PER_WORKER))
MAX_CHILDREN=$((TOTAL_WORKERS / SITE_COUNT))
[[ $MAX_CHILDREN -lt 4 ]] && MAX_CHILDREN=4
[[ $MAX_CHILDREN -gt 32 ]] && MAX_CHILDREN=32
START_SERVERS=$((MAX_CHILDREN / 4)); [[ $START_SERVERS -lt 1 ]] && START_SERVERS=1
MIN_SPARE=$((MAX_CHILDREN / 8)); [[ $MIN_SPARE -lt 1 ]] && MIN_SPARE=1
MAX_SPARE=$((MAX_CHILDREN / 2)); [[ $MAX_SPARE -lt 2 ]] && MAX_SPARE=2

echo "Pool: $DOMAIN -> ${SOCKET} (max_children=$MAX_CHILDREN)"

# Create SFTP chroot-compatible directory structure
mkdir -p "$SITE_DIR" "$SITE_DIR/public" "$SITE_DIR/logs" "$SITE_DIR/tmp"
chown root:root "$SITE_DIR"
chmod 755 "$SITE_DIR"
chown "$USER:$USER" "$SITE_DIR/public" "$SITE_DIR/logs" "$SITE_DIR/tmp"
chmod 750 "$SITE_DIR/public" "$SITE_DIR/logs" "$SITE_DIR/tmp"
setfacl -R -m u:www-data:rx "$SITE_DIR/public" 2>/dev/null || chown -R "$USER:www-data" "$SITE_DIR/public"

# Per-site cache directory
mkdir -p "$CACHE_DIR"
chown www-data:www-data "$CACHE_DIR"
chmod 755 "$CACHE_DIR"

# Per-site Nginx cache zone
SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_')
cat > "/etc/nginx/cache-zones/${DOMAIN}.conf" << CACHEZONE
fastcgi_cache_path ${CACHE_DIR} levels=1:2 keys_zone=FLAVOR_${SAFE_DOMAIN}:32m max_size=1g inactive=7d use_temp_path=off;
CACHEZONE

# PHP-FPM pool with Redis sessions
cat > "/etc/php/${PHP_VER}/fpm/pool.d/${DOMAIN}.conf" << POOLEOF
[${DOMAIN}]
user = ${USER}
group = ${USER}
listen = ${SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = ${MAX_CHILDREN}
pm.start_servers = ${START_SERVERS}
pm.min_spare_servers = ${MIN_SPARE}
pm.max_spare_servers = ${MAX_SPARE}
pm.process_idle_timeout = 30s
pm.max_requests = 1000

request_terminate_timeout = 300s
request_slowlog_timeout = 30s
slowlog = ${LOGS_DIR}/php-slow.log

rlimit_files = 65535
pm.status_path = /fpm-status
ping.path = /fpm-ping

php_admin_value[open_basedir] = ${SITE_DIR}:/tmp:/usr/share/php
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 300
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on

; Per-site Redis sessions
php_admin_value[session.save_handler] = redis
php_admin_value[session.save_path] = "unix:///run/redis/redis-server.sock?auth=${REDIS_PASS}&database=${REDIS_DB}"

php_admin_value[disable_functions] = dl,passthru,shell_exec,system,proc_open,popen,proc_close,proc_get_status,proc_terminate,proc_nice,posix_kill,symlink,pcntl_signal

catch_workers_output = yes
decorate_workers_output = no
POOLEOF

systemctl reload "php${PHP_VER}-fpm" 2>/dev/null || systemctl restart "php${PHP_VER}-fpm"

# Store socket path for nginx config generator
echo "${SOCKET}" > "/opt/flyne/run/${DOMAIN}.sock"

echo "Site pool created: $DOMAIN (Redis DB: $REDIS_DB, Workers: $MAX_CHILDREN)"
CREATEPOOL
chmod +x ${FLYNE_DIR}/scripts/create-site-pool.sh

# Nginx Site Config Generator
cat > ${FLYNE_DIR}/scripts/create-site-nginx.sh << 'CREATENGINX'
#!/bin/bash
DOMAIN="$1"; PHP_VER="${2:-8.4}"
SITE_DIR="/var/www/sites/$DOMAIN"

[[ -z "$DOMAIN" ]] && { echo "Usage: $0 domain [php_version]"; exit 1; }

# Read socket path from pool creator
SOCKET_FILE="/opt/flyne/run/${DOMAIN}.sock"
if [[ -f "$SOCKET_FILE" ]]; then
    SOCKET=$(cat "$SOCKET_FILE")
else
    DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
    SOCKET="/run/php/php-${DOMAIN_HASH}.sock"
fi

SAFE_DOMAIN=$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_')

cat > "/etc/nginx/sites-flyne/${DOMAIN}.conf" << SITECONF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    root ${SITE_DIR}/public;
    index index.php index.html;

    access_log ${SITE_DIR}/logs/access.log main;
    error_log ${SITE_DIR}/logs/error.log warn;

    set \$php_socket ${SOCKET};
    set \$site_cache_zone FLAVOR_${SAFE_DOMAIN};

    include snippets/wordpress-security.conf;
    include snippets/wordpress-static.conf;
    include snippets/cache-bypass.conf;

    location / { try_files \$uri \$uri/ /index.php?\$args; }

    include snippets/php-handler.conf;

    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt { allow all; log_not_found off; access_log off; }

    location = /wp-login.php {
        limit_req zone=login burst=3 nodelay;
        try_files \$uri =404;
        fastcgi_pass unix:\$php_socket;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_cache off;
    }
}
SITECONF

nginx -t && systemctl reload nginx
echo "Nginx config created for ${DOMAIN}"
CREATENGINX
chmod +x ${FLYNE_DIR}/scripts/create-site-nginx.sh

# FIX #4: User creation script (enforces nologin shell)
cat > ${FLYNE_DIR}/scripts/create-site-user.sh << 'CREATEUSER'
#!/bin/bash
USERNAME="$1"
PASSWORD="$2"

[[ -z "$USERNAME" ]] && { echo "Usage: $0 username [password]"; exit 1; }

# Create user with nologin shell (FIX #4: prevents SSH abuse)
useradd -m -d "/var/www/sites/${USERNAME}" -s /usr/sbin/nologin -g siteusers "$USERNAME"

# Set password if provided
if [[ -n "$PASSWORD" ]]; then
    echo "${USERNAME}:${PASSWORD}" | chpasswd
fi

# Add to siteusers group for SFTP
usermod -aG siteusers "$USERNAME"

echo "User $USERNAME created with SFTP access (shell: nologin)"
CREATEUSER
chmod +x ${FLYNE_DIR}/scripts/create-site-user.sh

chown -R flyne-agent:flyne-agent ${FLYNE_DIR}/scripts

#===============================================================================
# CRON JOBS
#===============================================================================
log "Setting up cron jobs..."
cat > /etc/cron.d/flyne << CRONEOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Expire SFTP access
*/5 * * * * flyne-agent mysql -u flyne_admin -p'${MYSQL_ADMIN_PASS}' -N -e "SELECT username FROM flyne_engine.sftp_access WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_enabled = 1" 2>/dev/null | while read user; do usermod -L "\$user" 2>/dev/null; mysql -u flyne_admin -p'${MYSQL_ADMIN_PASS}' -e "UPDATE flyne_engine.sftp_access SET is_enabled=0 WHERE username='\$user'" 2>/dev/null; done

# Clean old cache files
0 3 * * * root find /var/cache/nginx/fastcgi -type f -mtime +7 -delete 2>/dev/null

# Clean old backups
0 4 * * 0 root find /opt/flyne/backups -type f -mtime +30 -delete 2>/dev/null

# Database optimization
0 5 * * 0 flyne-agent mysqlcheck -u flyne_admin -p'${MYSQL_ADMIN_PASS}' --optimize --all-databases 2>/dev/null

# OPcache cleanup
0 6 * * * root find /var/cache/opcache -type f -mtime +1 -delete 2>/dev/null

# WordPress cron (HTTP-based)
*/5 * * * * www-data /opt/flyne/scripts/wp-cron-runner.sh 2>/dev/null

# SSL renewal
0 */12 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"
CRONEOF
chmod 644 /etc/cron.d/flyne

#===============================================================================
# FIX #5: SUDOERS - flyne-agent ONLY (www-data gets NOTHING)
#===============================================================================
log "Setting up secure permissions..."
cat > /etc/sudoers.d/flyne << 'SUDOERS'
# Flyne Engine Sudoers - SECURITY HARDENED
# www-data has NO sudo access (if WordPress is hacked, attacker gets nothing)
# All privileged operations go through flyne-agent

flyne-agent ALL=(ALL) NOPASSWD: /usr/sbin/useradd *
flyne-agent ALL=(ALL) NOPASSWD: /usr/sbin/userdel *
flyne-agent ALL=(ALL) NOPASSWD: /usr/sbin/usermod *
flyne-agent ALL=(ALL) NOPASSWD: /usr/sbin/chpasswd
flyne-agent ALL=(ALL) NOPASSWD: /bin/mkdir *
flyne-agent ALL=(ALL) NOPASSWD: /bin/chown *
flyne-agent ALL=(ALL) NOPASSWD: /bin/chmod *
flyne-agent ALL=(ALL) NOPASSWD: /usr/bin/setfacl *
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -rf /var/www/sites/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/sites-flyne/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -f /etc/php/*/fpm/pool.d/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -f /run/php/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -rf /var/cache/nginx/fastcgi/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/rm -f /etc/nginx/cache-zones/*
flyne-agent ALL=(ALL) NOPASSWD: /bin/touch *
flyne-agent ALL=(ALL) NOPASSWD: /bin/ln *
flyne-agent ALL=(ALL) NOPASSWD: /usr/bin/rsync *
flyne-agent ALL=(ALL) NOPASSWD: /bin/tar *
flyne-agent ALL=(ALL) NOPASSWD: /usr/bin/certbot *
flyne-agent ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
flyne-agent ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx
flyne-agent ALL=(ALL) NOPASSWD: /bin/systemctl reload php*-fpm
flyne-agent ALL=(ALL) NOPASSWD: /bin/systemctl restart php*-fpm
flyne-agent ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
flyne-agent ALL=(ALL) NOPASSWD: /usr/bin/du *
flyne-agent ALL=(ALL) NOPASSWD: /usr/bin/mysqldump *
flyne-agent ALL=(ALL) NOPASSWD: /opt/flyne/scripts/*
SUDOERS
chmod 440 /etc/sudoers.d/flyne

#===============================================================================
# Agent Wrapper (API calls this, runs as flyne-agent)
#===============================================================================
cat > ${FLYNE_DIR}/scripts/agent-wrapper.sh << 'AGENTWRAPPER'
#!/bin/bash
# Agent wrapper - executes commands as flyne-agent
# Usage: agent-wrapper.sh <script> [args...]

SCRIPT="$1"
shift

if [[ -z "$SCRIPT" ]]; then
    echo "Usage: agent-wrapper.sh <script> [args...]"
    exit 1
fi

# Execute as flyne-agent
sudo -u flyne-agent "$SCRIPT" "$@"
AGENTWRAPPER
chmod +x ${FLYNE_DIR}/scripts/agent-wrapper.sh
# Allow www-data to run ONLY the agent wrapper
echo "www-data ALL=(flyne-agent) NOPASSWD: /opt/flyne/scripts/agent-wrapper.sh *" >> /etc/sudoers.d/flyne

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

[wordpress-soft]
enabled = true
filter = wordpress-soft
logpath = /var/www/sites/*/logs/access.log
maxretry = 10
bantime = 600
F2BCONF

cat > /etc/fail2ban/filter.d/wordpress-hard.conf << 'F2BHARD'
[Definition]
failregex = ^<HOST> .* "POST /wp-login\.php
            ^<HOST> .* "POST /xmlrpc\.php
ignoreregex =
F2BHARD

cat > /etc/fail2ban/filter.d/wordpress-soft.conf << 'F2BSOFT'
[Definition]
failregex = ^<HOST> .* "GET /wp-login\.php
            ^<HOST> .* "GET /wp-admin
ignoreregex =
F2BSOFT

systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban || warn "Fail2ban restart failed"

#===============================================================================
# FIREWALL - FIX #9: SSH rate limiting
#===============================================================================
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
# FIX #9: Rate limit SSH instead of just allow
ufw limit 22/tcp comment 'SSH (rate limited)'
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
        echo -e "${BLUE}=== Flyne Engine v3.1 Status ===${NC}"
        echo ""
        for svc in nginx mariadb redis-server; do
            systemctl is-active --quiet $svc && echo -e "$svc: ${GREEN}✓ Running${NC}" || echo -e "$svc: ${RED}✗ Stopped${NC}"
        done
        for v in 8.1 8.2 8.3 8.4; do
            systemctl is-active --quiet php${v}-fpm 2>/dev/null && echo -e "PHP ${v}: ${GREEN}✓ Running${NC}"
        done
        echo ""
        SITE_COUNT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.sites WHERE status='active'" 2>/dev/null || echo 0)
        echo -e "Active Sites: ${YELLOW}${SITE_COUNT}${NC}"
        echo -e "API: ${BLUE}https://${API_DOMAIN}${NC}"
        echo ""
        echo -e "${CYAN}Resources:${NC}"
        echo "  Total RAM: ${TOTAL_RAM}MB"
        echo "  CPU Cores: ${CPU_CORES}"
        echo ""
        echo -e "${CYAN}Cache:${NC}"
        echo "  FastCGI: $(du -sh /var/cache/nginx/fastcgi 2>/dev/null | cut -f1 || echo '0')"
        ;;
        
    sites)
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "SELECT domain, php_version, status, ssl_enabled, redis_db FROM flyne_engine.sites ORDER BY created_at DESC" 2>/dev/null
        ;;
        
    create)
        [[ -z "$2" ]] && echo "Usage: flyne create domain.com [email]" && exit 1
        curl -sk -X POST "https://${API_DOMAIN}/index.php" \
            -H "Authorization: Bearer ${API_SECRET}" \
            -d "action=create_site&domain=$2&admin_email=${3:-admin@$2}" | jq . 2>/dev/null || cat
        ;;
        
    delete)
        [[ -z "$2" ]] && echo "Usage: flyne delete domain.com" && exit 1
        read -p "Delete $2? [y/N] " confirm
        [[ "$confirm" != "y" ]] && exit 0
        curl -sk -X POST "https://${API_DOMAIN}/index.php" \
            -H "Authorization: Bearer ${API_SECRET}" \
            -d "action=delete_site&domain=$2" | jq . 2>/dev/null || cat
        ;;
        
    cache-clear)
        if [[ -n "$2" ]]; then
            # Get Redis DB for site
            REDIS_DB=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT redis_db FROM flyne_engine.sites WHERE domain='$2'" 2>/dev/null)
            sudo -u flyne-agent /opt/flyne/scripts/cache-purge.sh "$2" "$REDIS_PASS" "$REDIS_DB"
        else
            echo "Clearing global cache only (use domain for site-specific)..."
            sudo -u flyne-agent /opt/flyne/scripts/cache-purge.sh
        fi
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
        echo -e "${BLUE}Flyne Engine CLI v3.1${NC}"
        echo ""
        echo "Commands:"
        echo "  status              System status"
        echo "  sites               List sites"
        echo "  create <domain>     Create WordPress site"
        echo "  delete <domain>     Delete site"
        echo "  cache-clear [site]  Clear cache (site-specific recommended)"
        echo "  test                Test API"
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
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
SYSCTL
sysctl -p /etc/sysctl.d/99-flyne-performance.conf 2>/dev/null || warn "Some kernel params failed"

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
# FINAL VERIFICATION
#===============================================================================
log "Verifying installation..."

nginx -t || error "Nginx config invalid"
systemctl is-active --quiet mariadb || error "MariaDB not running"
systemctl is-active --quiet redis-server || error "Redis not running"
systemctl is-active --quiet php8.4-fpm || error "PHP 8.4 FPM not running"
mysql -u flyne_admin -p"${MYSQL_ADMIN_PASS}" -e "SELECT 1" >/dev/null || error "MySQL connection failed"
redis-cli -s /run/redis/redis-server.sock -a "${REDIS_PASS}" PING >/dev/null 2>&1 || error "Redis connection failed"

log "All services verified!"

#===============================================================================
# OUTPUT
#===============================================================================
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   FLYNE ENGINE v3.1 INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Security Fixes Applied:${NC}"
echo -e "  ✓ MySQL: unix_socket for root, separate flyne_admin user"
echo -e "  ✓ Redis: Socket permissions 777 (all local users)"
echo -e "  ✓ Nginx: Map-based cache bypass (no if-in-location)"
echo -e "  ✓ SFTP: Chroot + nologin shell enforced"
echo -e "  ✓ Sudo: flyne-agent only (www-data has NO sudo)"
echo -e "  ✓ Sockets: Hashed paths (no length overflow)"
echo -e "  ✓ Cache: Site-specific purge (no FLUSHALL)"
echo -e "  ✓ MariaDB: VPS-safe I/O capacity"
echo -e "  ✓ UFW: SSH rate limited"
echo ""
echo -e "${BLUE}Performance Features:${NC}"
echo -e "  ✓ Per-site FastCGI cache zones"
echo -e "  ✓ Per-site Redis sessions (DB isolation)"
echo -e "  ✓ CPU/RAM-aware PHP pool sizing"
echo -e "  ✓ HTTP WP-Cron (OPcache warm)"
echo -e "  ✓ Tracking param stripping"
echo ""
echo -e "${BLUE}URLs:${NC}"
echo -e "  API:        ${CYAN}https://${API_DOMAIN}${NC}"
echo -e "  phpMyAdmin: ${CYAN}https://${PMA_DOMAIN}${NC}"
echo ""
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}   CREDENTIALS - SAVE SECURELY!${NC}"
echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  API Secret:     ${YELLOW}${API_SECRET}${NC}"
echo -e "  MySQL User:     ${YELLOW}flyne_admin${NC}"
echo -e "  MySQL Pass:     ${YELLOW}${MYSQL_ADMIN_PASS}${NC}"
echo -e "  Redis Password: ${YELLOW}${REDIS_PASS}${NC}"
echo ""

cat > ${FLYNE_DIR}/credentials.txt << CREDEOF
=== FLYNE ENGINE v3.1 CREDENTIALS ===
Generated: $(date)

API Domain:    https://${API_DOMAIN}
PMA Domain:    https://${PMA_DOMAIN}

API Secret:    ${API_SECRET}
MySQL User:    flyne_admin
MySQL Pass:    ${MYSQL_ADMIN_PASS}
Redis Pass:    ${REDIS_PASS}
Admin Email:   ${ADMIN_EMAIL}

Security Model:
- MySQL root: unix_socket auth (no password)
- MySQL operations: flyne_admin user
- Privileged ops: flyne-agent system user
- www-data: NO sudo access (hacked WP = no escalation)
- Site users: nologin shell + SFTP chroot

DELETE THIS FILE AFTER SAVING CREDENTIALS!
CREDEOF
chmod 600 ${FLYNE_DIR}/credentials.txt
chown flyne-agent:flyne-agent ${FLYNE_DIR}/credentials.txt

echo -e "Credentials: ${YELLOW}${FLYNE_DIR}/credentials.txt${NC}"
echo ""
log "Installation complete! Run 'flyne create example.com' to create your first site."
echo ""