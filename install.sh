#!/bin/bash
#===============================================================================
# FLYNE ENGINE - Minimal WordPress Hosting Platform
# Single-command installer for Ubuntu 22.04/24.04
# Structure: /opt/flyne/ with just 2 files + backups folder
#===============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log() { echo -e "${GREEN}[FLYNE]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

clear
echo -e "${BLUE}"
cat << "EOF"
   _____ _                        _____            _            
  |  ___| |_   _ _ __   ___      | ____|_ __   __ _(_)_ __   ___ 
  | |_  | | | | | '_ \ / _ \_____|  _| | '_ \ / _` | | '_ \ / _ \
  |  _| | | |_| | | | |  __/_____| |___| | | | (_| | | | | |  __/
  |_|   |_|\__, |_| |_|\___|     |_____|_| |_|\__, |_|_| |_|\___|
           |___/                              |___/              
  Lightweight WordPress Hosting Engine v1.0
EOF
echo -e "${NC}"

#===============================================================================
# CONFIGURATION
#===============================================================================
echo ""
read -p "API Domain (e.g., api.flyne.ge): " API_DOMAIN
read -p "phpMyAdmin Domain (e.g., pma.flyne.ge): " PMA_DOMAIN
read -p "Admin Email (for SSL): " ADMIN_EMAIL
read -sp "API Secret Key (min 32 chars): " API_SECRET
echo ""
read -sp "MySQL Root Password: " MYSQL_ROOT_PASS
echo ""
read -sp "Redis Password: " REDIS_PASS
echo ""

[[ -z "$API_DOMAIN" ]] && error "API domain required"
[[ -z "$PMA_DOMAIN" ]] && error "PMA domain required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ characters"

FLYNE_DIR="/opt/flyne"
SITES_DIR="/var/www/sites"

log "Starting installation..."

#===============================================================================
# SYSTEM PACKAGES
#===============================================================================
log "Updating system..."
apt update && apt upgrade -y

log "Installing packages..."
apt install -y software-properties-common curl wget git unzip zip \
    nginx mariadb-server redis-server certbot python3-certbot-nginx \
    pwgen htop ncdu fail2ban ufw jq

# PHP repository
add-apt-repository -y ppa:ondrej/php
apt update

# Install all PHP versions with extensions
for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    log "Installing PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline 2>/dev/null || warn "PHP $V not available"
done

# WP-CLI
log "Installing WP-CLI..."
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

# phpMyAdmin
log "Installing phpMyAdmin..."
DEBIAN_FRONTEND=noninteractive apt install -y phpmyadmin

#===============================================================================
# DIRECTORY STRUCTURE (MINIMAL)
#===============================================================================
log "Creating directories..."
mkdir -p $FLYNE_DIR/backups
mkdir -p $SITES_DIR
mkdir -p /var/log/flyne

#===============================================================================
# MARIADB
#===============================================================================
log "Configuring MariaDB..."
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';"
mysql -u root -p"${MYSQL_ROOT_PASS}" << EOF
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
CREATE DATABASE IF NOT EXISTS flyne_engine;
FLUSH PRIVILEGES;
EOF

cat > /etc/mysql/mariadb.conf.d/99-flyne.cnf << 'EOF'
[mysqld]
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
query_cache_type = 1
query_cache_size = 32M
max_connections = 200
skip-name-resolve
EOF
systemctl restart mariadb

#===============================================================================
# REDIS
#===============================================================================
log "Configuring Redis..."
cat > /etc/redis/redis.conf << EOF
bind 127.0.0.1 ::1
port 6379
requirepass ${REDIS_PASS}
maxmemory 256mb
maxmemory-policy allkeys-lru
save ""
appendonly no
EOF
systemctl restart redis-server

#===============================================================================
# NGINX
#===============================================================================
log "Configuring Nginx..."

cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" $request_time';
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript 
               application/xml application/rss+xml application/atom+xml image/svg+xml;
    
    fastcgi_cache_path /tmp/nginx-cache levels=1:2 keys_zone=WORDPRESS:100m max_size=1g inactive=60m;
    fastcgi_cache_key "$scheme$request_method$host$request_uri";
    fastcgi_cache_use_stale error timeout updating http_500 http_503;
    fastcgi_cache_background_update on;
    fastcgi_cache_lock on;
    
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-flyne/*.conf;
}
EOF

mkdir -p /etc/nginx/sites-flyne

# API config
cat > /etc/nginx/sites-flyne/api.conf << EOF
server {
    listen 80;
    server_name ${API_DOMAIN};
    root ${FLYNE_DIR};
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ROOT_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
    }
    
    location /backups { deny all; }
    location ~ /\.  { deny all; }
    
    limit_req zone=api burst=50 nodelay;
}
EOF

# phpMyAdmin config
cat > /etc/nginx/sites-flyne/pma.conf << EOF
server {
    listen 80;
    server_name ${PMA_DOMAIN};
    root /usr/share/phpmyadmin;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

#===============================================================================
# SSL
#===============================================================================
log "Installing SSL..."
certbot --nginx -d ${API_DOMAIN} -d ${PMA_DOMAIN} --email ${ADMIN_EMAIL} --agree-tos --non-interactive || warn "SSL failed - check DNS"

#===============================================================================
# CONFIG FILE (Single file, not folder)
#===============================================================================
log "Creating config..."
cat > ${FLYNE_DIR}/flyne.conf << EOF
API_DOMAIN="${API_DOMAIN}"
PMA_DOMAIN="${PMA_DOMAIN}"
API_SECRET="${API_SECRET}"
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS}"
REDIS_PASS="${REDIS_PASS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
SITES_DIR="${SITES_DIR}"
FLYNE_DIR="${FLYNE_DIR}"
DEFAULT_PHP="8.4"
EOF
chmod 600 ${FLYNE_DIR}/flyne.conf

#===============================================================================
# DATABASE SCHEMA
#===============================================================================
log "Creating database..."
mysql -u root -p"${MYSQL_ROOT_PASS}" flyne_engine << 'EOF'
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    type ENUM('full','files','database') DEFAULT 'full',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB;
EOF

#===============================================================================
# SUDOERS
#===============================================================================
log "Setting up permissions..."
cat > /etc/sudoers.d/flyne << 'EOF'
www-data ALL=(ALL) NOPASSWD: /usr/sbin/useradd *
www-data ALL=(ALL) NOPASSWD: /usr/sbin/userdel *
www-data ALL=(ALL) NOPASSWD: /usr/bin/chpasswd
www-data ALL=(ALL) NOPASSWD: /bin/mkdir *
www-data ALL=(ALL) NOPASSWD: /bin/chown *
www-data ALL=(ALL) NOPASSWD: /bin/chmod *
www-data ALL=(ALL) NOPASSWD: /bin/rm -rf /var/www/sites/*
www-data ALL=(ALL) NOPASSWD: /usr/bin/rsync *
www-data ALL=(ALL) NOPASSWD: /bin/tar *
www-data ALL=(ALL) NOPASSWD: /usr/bin/certbot *
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
www-data ALL=(ALL) NOPASSWD: /bin/systemctl reload php*-fpm
www-data ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
www-data ALL=(ALL) NOPASSWD: /usr/bin/du *
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysqldump *
www-data ALL=(ALL) NOPASSWD: /usr/bin/mysql *
EOF
chmod 440 /etc/sudoers.d/flyne

#===============================================================================
# CLI TOOL
#===============================================================================
log "Installing CLI..."
cat > /usr/local/bin/flyne << 'CLIFILE'
#!/bin/bash
source /opt/flyne/flyne.conf 2>/dev/null || { echo "Flyne not configured"; exit 1; }

case "$1" in
    status)
        echo "=== Flyne Engine Status ==="
        systemctl is-active --quiet nginx && echo "Nginx: ✓ Running" || echo "Nginx: ✗ Stopped"
        systemctl is-active --quiet mariadb && echo "MariaDB: ✓ Running" || echo "MariaDB: ✗ Stopped"
        systemctl is-active --quiet redis-server && echo "Redis: ✓ Running" || echo "Redis: ✗ Stopped"
        for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
            systemctl is-active --quiet php${v}-fpm 2>/dev/null && echo "PHP ${v}: ✓ Running"
        done
        echo ""
        echo "Sites: $(ls -1 /var/www/sites 2>/dev/null | wc -l)"
        echo "API: https://${API_DOMAIN}"
        ;;
    test)
        echo "Testing API..."
        curl -s -H "Authorization: Bearer ${API_SECRET}" "https://${API_DOMAIN}/index.php?action=site_list"
        ;;
    *)
        echo "Usage: flyne [status|test]"
        ;;
esac
CLIFILE
chmod +x /usr/local/bin/flyne

#===============================================================================
# FIREWALL
#===============================================================================
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

#===============================================================================
# DONE
#===============================================================================
echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   FLYNE ENGINE INSTALLED!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "Structure:"
echo -e "  ${FLYNE_DIR}/"
echo -e "  ├── index.php      ${YELLOW}← Upload this next!${NC}"
echo -e "  ├── flyne.conf     ✓ Created"
echo -e "  └── backups/       ✓ Created"
echo ""
echo -e "API URL:     ${BLUE}https://${API_DOMAIN}${NC}"
echo -e "phpMyAdmin:  ${BLUE}https://${PMA_DOMAIN}${NC}"
echo ""
echo -e "${YELLOW}NEXT STEP:${NC}"
echo -e "  Upload index.php to ${FLYNE_DIR}/index.php"
echo ""
echo -e "API Secret: ${YELLOW}${API_SECRET}${NC}"
echo -e "${RED}Save this! You need it for your frontend.${NC}"
echo ""