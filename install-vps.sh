#!/bin/bash
#===============================================================================
# FLYNE VPS CONTROL PANEL v1.0 - Managed VPS Hosting Platform
# Full control panel: multi-webserver, email, DNS, FTP, cron, Node.js, apps
# Ubuntu 22.04/24.04 | Nginx/Apache/OLS switching | Production-Grade
#
# Domain creation = empty vhost (like cPanel)
# Apps (WordPress, Node.js, etc.) installed separately via App Installer
#===============================================================================

set -uo pipefail
trap 'echo -e "${RED}[ERROR]${NC} Script failed at line $LINENO"; exit 1' ERR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[FLYNE-VPS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error(){ echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install-vps.sh"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    [[ "$ID" != "ubuntu" ]] && error "Only Ubuntu 22.04/24.04 supported"
else
    error "Cannot detect OS"
fi

clear
echo -e "${BLUE}"
cat << "EOF"
   _____ _                   __     ______  ____  
  |  ___| |_   _ _ __   ___  \ \   / /  _ \/ ___| 
  | |_  | | | | | '_ \ / _ \  \ \ / /| |_) \___ \ 
  |  _| | | |_| | | | |  __/   \ V / |  __/ ___) |
  |_|   |_|\__, |_| |_|\___|    \_/  |_|   |____/ 
           |___/                                    
  Managed VPS Control Panel v1.0
EOF
echo -e "${NC}"

#===============================================================================
# CONFIGURATION PROMPTS
#===============================================================================
echo -e "${CYAN}=== Server Configuration ===${NC}"
read -p "Control Panel API Domain (e.g., api.flyne.ge): " PANEL_DOMAIN
read -p "phpMyAdmin Domain (e.g., pma.flyne.ge): " PMA_DOMAIN
read -p "Server Hostname (e.g., vps1.flyne.ge): " SERVER_HOSTNAME
read -p "Admin Email: " ADMIN_EMAIL
read -p "Nameserver 1 (e.g., ns1.flyne.ge): " NS1
NS1="${NS1:-ns1.${PANEL_DOMAIN}}"
read -p "Nameserver 2 (e.g., ns2.flyne.ge): " NS2
NS2="${NS2:-ns2.${PANEL_DOMAIN}}"

DEFAULT_API_SECRET=$(openssl rand -hex 32)
DEFAULT_MYSQL_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
DEFAULT_REDIS_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 24)

echo ""
echo -e "${YELLOW}Generated secure defaults (press Enter to accept):${NC}"
read -p "API Secret [$DEFAULT_API_SECRET]: " API_SECRET
API_SECRET="${API_SECRET:-$DEFAULT_API_SECRET}"
read -sp "MySQL Root Password [auto]: " MYSQL_ROOT_PASS
echo ""; MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-$DEFAULT_MYSQL_PASS}"
read -sp "Redis Password [auto]: " REDIS_PASS
echo ""; REDIS_PASS="${REDIS_PASS:-$DEFAULT_REDIS_PASS}"

[[ -z "$PANEL_DOMAIN" ]] && error "Panel domain required"
[[ -z "$ADMIN_EMAIL" ]] && error "Admin email required"
[[ ${#API_SECRET} -lt 32 ]] && error "API secret must be 32+ chars"

TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
CPU_CORES=$(nproc)
SERVER_IP=$(curl -s4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

log "Detected: ${TOTAL_RAM}MB RAM, ${CPU_CORES} CPUs, IP: ${SERVER_IP}"

FLYNE_DIR="/opt/flyne-vps"
SITES_DIR="/var/www/vhosts"
MAIL_DIR="/var/mail/vhosts"
DNS_DIR="/etc/bind/zones"
NODE_DIR="/opt/node-apps"

log "Starting full installation..."

#===============================================================================
# 1. SYSTEM PACKAGES
#===============================================================================
log "Updating system..."
export DEBIAN_FRONTEND=noninteractive
hostnamectl set-hostname "$SERVER_HOSTNAME"
grep -q "$SERVER_HOSTNAME" /etc/hosts || echo "$SERVER_IP $SERVER_HOSTNAME" >> /etc/hosts

apt update && apt upgrade -y

log "Installing core packages..."
apt install -y software-properties-common curl wget git unzip zip \
    pwgen htop ncdu jq acl rsync pigz pv lsof net-tools dnsutils \
    certbot python3-certbot-nginx python3-certbot-apache \
    fail2ban ufw logrotate cron at \
    build-essential libpcre3-dev zlib1g-dev libssl-dev

#--- PHP ---
log "Installing PHP versions..."
add-apt-repository -y ppa:ondrej/php
apt update

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    log "  PHP $V..."
    apt install -y php${V}-fpm php${V}-cli php${V}-mysql php${V}-curl \
        php${V}-gd php${V}-mbstring php${V}-xml php${V}-zip php${V}-bcmath \
        php${V}-intl php${V}-soap php${V}-redis php${V}-imagick \
        php${V}-opcache php${V}-readline php${V}-imap php${V}-pgsql \
        php${V}-sqlite3 2>/dev/null || warn "PHP $V: some packages unavailable"
done

#--- Node.js (via NVM for multi-version) ---
log "Installing Node.js versions..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null || warn "Node 20 repo failed"
apt install -y nodejs 2>/dev/null || warn "Node.js install failed"
npm install -g pm2 yarn 2>/dev/null || warn "PM2/Yarn install failed"

# Install NVM system-wide for multi-version Node
export NVM_DIR="/opt/nvm"
mkdir -p "$NVM_DIR"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | NVM_DIR="$NVM_DIR" bash 2>/dev/null || warn "NVM install failed"
if [[ -f "$NVM_DIR/nvm.sh" ]]; then
    source "$NVM_DIR/nvm.sh"
    nvm install 18 2>/dev/null || true
    nvm install 20 2>/dev/null || true
    nvm install 22 2>/dev/null || true
    nvm alias default 20
fi

cat > /etc/profile.d/nvm.sh << 'NVMEOF'
export NVM_DIR="/opt/nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"
NVMEOF

#--- Nginx ---
log "Installing Nginx..."
apt install -y nginx
systemctl stop nginx

#--- Apache ---
log "Installing Apache..."
apt install -y apache2 libapache2-mod-fcgid
a2enmod proxy_fcgi setenvif rewrite ssl headers expires deflate http2 actions alias 2>/dev/null
systemctl stop apache2
systemctl disable apache2

#--- OpenLiteSpeed ---
log "Installing OpenLiteSpeed..."
wget -qO - https://repo.litespeed.sh | bash 2>/dev/null || warn "OLS repo failed"
apt install -y openlitespeed lsphp84 2>/dev/null || warn "OLS install failed - can be installed later"
systemctl stop lsws 2>/dev/null || true
systemctl disable lsws 2>/dev/null || true

#--- MariaDB ---
log "Installing MariaDB..."
apt install -y mariadb-server mariadb-client

#--- Redis ---
log "Installing Redis..."
apt install -y redis-server

#--- BIND9 DNS ---
log "Installing BIND9..."
apt install -y bind9 bind9utils bind9-dnsutils

#--- Mail Stack ---
log "Installing mail stack (Postfix + Dovecot + DKIM + SpamAssassin)..."
debconf-set-selections <<< "postfix postfix/mailname string ${SERVER_HOSTNAME}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt install -y postfix postfix-mysql \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql \
    opendkim opendkim-tools \
    spamassassin spamc 2>/dev/null || warn "Some mail packages failed"

#--- FTP ---
log "Installing ProFTPD..."
apt install -y proftpd-basic proftpd-mod-mysql 2>/dev/null || {
    apt install -y vsftpd 2>/dev/null || warn "FTP server install failed"
}

#--- phpMyAdmin ---
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
\$cfg['TempDir'] = '/tmp';
PMAEOF
    chown -R www-data:www-data /usr/share/phpmyadmin
    mkdir -p /usr/share/phpmyadmin/tmp && chmod 777 /usr/share/phpmyadmin/tmp
fi

#--- WP-CLI ---
log "Installing WP-CLI..."
curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp

#--- Composer ---
curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer 2>/dev/null || warn "Composer failed"

#===============================================================================
# 2. SYSTEM USERS & GROUPS
#===============================================================================
log "Creating system users and groups..."
groupadd -f vhostusers
groupadd -f sftpusers
groupadd -f vmail 2>/dev/null || true
useradd -r -g vmail -d "$MAIL_DIR" -s /usr/sbin/nologin -u 5000 vmail 2>/dev/null || true

if ! id "flyne-agent" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d "$FLYNE_DIR" -c "Flyne VPS Agent" flyne-agent
fi
usermod -aG www-data,vhostusers flyne-agent

#===============================================================================
# 3. DIRECTORY STRUCTURE
#===============================================================================
log "Creating directory structure..."
mkdir -p ${FLYNE_DIR}/{api,scripts,ssl,run,templates,tmp,backups}
mkdir -p ${SITES_DIR}
mkdir -p ${MAIL_DIR}
mkdir -p ${DNS_DIR}
mkdir -p ${NODE_DIR}
mkdir -p /var/log/flyne
mkdir -p /var/cache/nginx/fastcgi/{global,sites}
mkdir -p /run/php
mkdir -p /etc/nginx/{sites-vhost,snippets,cache-zones}
mkdir -p /etc/apache2/sites-vhost

chown flyne-agent:flyne-agent ${FLYNE_DIR}
chown -R flyne-agent:flyne-agent ${FLYNE_DIR}/{api,scripts,ssl,run,templates,tmp,backups}
chown www-data:www-data ${SITES_DIR}
chmod 755 ${SITES_DIR}
chown vmail:vmail ${MAIL_DIR}
chmod 770 ${MAIL_DIR}
chown -R bind:bind ${DNS_DIR}
chown -R flyne-agent:www-data /var/log/flyne
chmod 775 /var/log/flyne

touch /var/log/flyne/{api.log,agent.log,mail.log,dns.log,cron.log,apps.log}
chown flyne-agent:www-data /var/log/flyne/*.log
chmod 664 /var/log/flyne/*.log

#===============================================================================
# 4. MARIADB CONFIGURATION
#===============================================================================
log "Configuring MariaDB..."

if [[ $TOTAL_RAM -gt 16384 ]]; then IB="8G"; IL="1G"; MC=300
elif [[ $TOTAL_RAM -gt 8192 ]]; then IB="4G"; IL="512M"; MC=200
elif [[ $TOTAL_RAM -gt 4096 ]]; then IB="2G"; IL="256M"; MC=150
elif [[ $TOTAL_RAM -gt 2048 ]]; then IB="1G"; IL="128M"; MC=100
else IB="512M"; IL="64M"; MC=75; fi

cat > /etc/mysql/mariadb.conf.d/99-flyne.cnf << EOF
[mysqld]
innodb_buffer_pool_size = ${IB}
innodb_log_file_size = ${IL}
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
max_connections = ${MC}
query_cache_type = 0
skip-log-bin
skip-name-resolve
max_allowed_packet = 128M
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF

systemctl restart mariadb || error "MariaDB failed"

mysql << SQLEOF
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
DROP USER IF EXISTS 'flyne_admin'@'localhost';
CREATE USER 'flyne_admin'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'flyne_admin'@'localhost' WITH GRANT OPTION;
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQLEOF

log "MariaDB configured"

#===============================================================================
# 5. DATABASE SCHEMA
#===============================================================================
log "Creating control panel database..."

mysql -u flyne_admin -p"${MYSQL_ROOT_PASS}" << 'SCHEMA'
CREATE DATABASE IF NOT EXISTS flyne_vps CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE flyne_vps;

-- System accounts (panel users / resellers)
CREATE TABLE IF NOT EXISTS accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    plan VARCHAR(64) DEFAULT 'default',
    status ENUM('active','suspended','pending') DEFAULT 'active',
    max_domains INT DEFAULT 10,
    max_databases INT DEFAULT 10,
    max_email_accounts INT DEFAULT 50,
    max_ftp_accounts INT DEFAULT 10,
    disk_quota_mb INT DEFAULT 10240,
    bandwidth_mb BIGINT DEFAULT 1048576,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status)
) ENGINE=InnoDB;

-- Domains (main domains) - NO app installed by default
CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    site_user VARCHAR(64) NOT NULL,
    document_root VARCHAR(500) NOT NULL,
    webserver ENUM('nginx','apache','openlitespeed') DEFAULT 'nginx',
    php_version VARCHAR(10) DEFAULT '8.4',
    ssl_enabled TINYINT(1) DEFAULT 0,
    ssl_type ENUM('none','letsencrypt','custom') DEFAULT 'none',
    status ENUM('active','suspended','creating','error') DEFAULT 'creating',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    INDEX idx_domain (domain),
    INDEX idx_status (status)
) ENGINE=InnoDB;

-- Subdomains
CREATE TABLE IF NOT EXISTS subdomains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    subdomain VARCHAR(255) NOT NULL,
    full_domain VARCHAR(500) NOT NULL UNIQUE,
    document_root VARCHAR(500) NOT NULL,
    php_version VARCHAR(10) DEFAULT '8.4',
    ssl_enabled TINYINT(1) DEFAULT 0,
    status ENUM('active','suspended') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_full (full_domain)
) ENGINE=InnoDB;

-- Installed applications (WordPress, Node.js, etc.)
CREATE TABLE IF NOT EXISTS apps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    subdomain_id INT NULL,
    app_type ENUM('wordpress','nodejs','python','static','laravel','custom') NOT NULL,
    app_name VARCHAR(128),
    install_path VARCHAR(500) NOT NULL,
    app_url VARCHAR(500),
    node_version VARCHAR(20) NULL,
    node_entry VARCHAR(255) NULL,
    node_port INT NULL,
    pm2_name VARCHAR(128) NULL,
    db_name VARCHAR(64) NULL,
    db_user VARCHAR(64) NULL,
    db_pass VARCHAR(255) NULL,
    redis_db INT NULL,
    status ENUM('active','stopped','error','installing') DEFAULT 'installing',
    config JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_type (app_type),
    INDEX idx_status (status)
) ENGINE=InnoDB;

-- Databases
CREATE TABLE IF NOT EXISTS user_databases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_id INT NOT NULL,
    domain_id INT NULL,
    db_name VARCHAR(64) NOT NULL UNIQUE,
    db_user VARCHAR(64) NOT NULL,
    db_pass VARCHAR(255) NOT NULL,
    db_size_mb BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    INDEX idx_account (account_id)
) ENGINE=InnoDB;

-- DNS Zones
CREATE TABLE IF NOT EXISTS dns_zones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    serial INT DEFAULT 1,
    status ENUM('active','inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- DNS Records
CREATE TABLE IF NOT EXISTS dns_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    zone_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    type ENUM('A','AAAA','CNAME','MX','TXT','NS','SRV','CAA','PTR') NOT NULL,
    content VARCHAR(1024) NOT NULL,
    ttl INT DEFAULT 3600,
    priority INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (zone_id) REFERENCES dns_zones(id) ON DELETE CASCADE,
    INDEX idx_zone_type (zone_id, type)
) ENGINE=InnoDB;

-- Email domains
CREATE TABLE IF NOT EXISTS mail_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    dkim_enabled TINYINT(1) DEFAULT 0,
    dkim_selector VARCHAR(64) DEFAULT 'default',
    spf_record VARCHAR(500),
    max_accounts INT DEFAULT 50,
    status ENUM('active','suspended') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Email accounts
CREATE TABLE IF NOT EXISTS mail_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mail_domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    quota_mb INT DEFAULT 1024,
    used_mb INT DEFAULT 0,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mail_domain_id) REFERENCES mail_domains(id) ON DELETE CASCADE,
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- Email aliases / forwards
CREATE TABLE IF NOT EXISTS mail_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mail_domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mail_domain_id) REFERENCES mail_domains(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_alias (source, destination)
) ENGINE=InnoDB;

-- FTP accounts
CREATE TABLE IF NOT EXISTS ftp_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    home_dir VARCHAR(500) NOT NULL,
    quota_mb INT DEFAULT 0,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Cron jobs
CREATE TABLE IF NOT EXISTS cron_jobs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    minute VARCHAR(20) DEFAULT '*',
    hour VARCHAR(20) DEFAULT '*',
    day VARCHAR(20) DEFAULT '*',
    month VARCHAR(20) DEFAULT '*',
    weekday VARCHAR(20) DEFAULT '*',
    command TEXT NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    last_run DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain (domain_id)
) ENGINE=InnoDB;

-- SSL certificates
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    type ENUM('letsencrypt','custom','selfsigned') DEFAULT 'letsencrypt',
    cert_path VARCHAR(500),
    key_path VARCHAR(500),
    chain_path VARCHAR(500),
    expires_at DATETIME NULL,
    auto_renew TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Backups
CREATE TABLE IF NOT EXISTS backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NULL,
    account_id INT NULL,
    type ENUM('full','files','database','email') DEFAULT 'full',
    status ENUM('pending','running','completed','failed') DEFAULT 'pending',
    file_path VARCHAR(500),
    file_size BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Activity / audit log
CREATE TABLE IF NOT EXISTS activity_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    account_id INT NULL,
    domain_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created (created_at),
    INDEX idx_action (action)
) ENGINE=InnoDB;

-- Insert default admin account
INSERT IGNORE INTO accounts (username, email, plan, max_domains, max_databases, max_email_accounts, disk_quota_mb)
VALUES ('admin', '${ADMIN_EMAIL}', 'admin', 999, 999, 9999, 0);
SCHEMA

log "Database schema created"

#===============================================================================
# 6. REDIS
#===============================================================================
log "Configuring Redis..."
REDIS_MEM=$((TOTAL_RAM * 10 / 100))
[[ $REDIS_MEM -lt 128 ]] && REDIS_MEM=128
[[ $REDIS_MEM -gt 2048 ]] && REDIS_MEM=2048

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

mkdir -p /run/redis && chown redis:redis /run/redis
systemctl restart redis-server || error "Redis failed"

#===============================================================================
# 7. PHP-FPM BASE CONFIG
#===============================================================================
log "Configuring PHP-FPM..."

for V in 7.4 8.0 8.1 8.2 8.3 8.4; do
    [[ ! -d "/etc/php/${V}" ]] && continue
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
session.save_handler = files
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

    # Only remove default pool on 8.4 where API pool replaces it
    # Other versions keep www.conf so FPM can start (site pools added later)
    if [[ "$V" == "8.4" ]]; then
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
pm.max_children = 15
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 6
pm.max_requests = 1000
php_admin_value[open_basedir] = /opt/flyne-vps:/var/www/vhosts:/tmp:/usr/share/php:/usr/local/bin
APIPOOL
    fi

    systemctl restart php${V}-fpm 2>/dev/null || warn "PHP $V FPM restart failed"
done

#===============================================================================
# 8. NGINX CONFIGURATION (Default Web Server)
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
    client_max_body_size 512M;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" $upstream_cache_status';
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types application/javascript application/json application/xml text/css text/plain text/xml image/svg+xml;

    fastcgi_cache_path /var/cache/nginx/fastcgi/global levels=1:2 keys_zone=GLOBAL_CACHE:64m max_size=1g inactive=7d;
    include /etc/nginx/cache-zones/*.conf;
    fastcgi_cache_key "$scheme$request_method$host$request_uri";

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;

    limit_req_zone $binary_remote_addr zone=api:20m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Websocket support for Node.js
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    include /etc/nginx/sites-vhost/*.conf;
}
NGINXCONF

# --- Shared Snippets ---
cat > /etc/nginx/snippets/security.conf << 'SECSNIP'
location ~ /\.(?!well-known) { deny all; }
location ~* \.(bak|config|sql|ini|log|sh|swp|env|git)$ { deny all; }
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
SECSNIP

cat > /etc/nginx/snippets/static-cache.conf << 'STATICSNIP'
location ~* \.(jpg|jpeg|png|gif|ico|webp|avif|svg)$ {
    expires 1y; add_header Cache-Control "public, immutable"; try_files $uri =404;
}
location ~* \.(css|js)$ {
    expires 1y; add_header Cache-Control "public, immutable"; try_files $uri =404;
}
location ~* \.(woff|woff2|ttf|otf|eot)$ {
    expires 1y; add_header Cache-Control "public, immutable";
    add_header Access-Control-Allow-Origin "*"; try_files $uri =404;
}
STATICSNIP

cat > /etc/nginx/snippets/php-fpm.conf << 'PHPSNIP'
try_files $uri =404;
fastcgi_index index.php;
include fastcgi_params;
fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
fastcgi_read_timeout 300;
fastcgi_send_timeout 300;
fastcgi_buffers 16 16k;
fastcgi_buffer_size 32k;
PHPSNIP

cat > /etc/nginx/snippets/node-proxy.conf << 'NODESNIP'
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_cache_bypass $http_upgrade;
proxy_read_timeout 86400;
NODESNIP

# --- Panel API vhost ---
cat > /etc/nginx/sites-vhost/000-panel-api.conf << APICONF
server {
    listen 80;
    listen [::]:80;
    server_name ${PANEL_DOMAIN};
    root ${FLYNE_DIR}/api;
    index index.php;

    location ~ /\\.(?!well-known) { deny all; }
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:/run/php/php8.4-fpm-api.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param FLYNE_API_SECRET "${API_SECRET}";
        fastcgi_param FLYNE_MYSQL_USER "flyne_admin";
        fastcgi_param FLYNE_MYSQL_PASS "${MYSQL_ROOT_PASS}";
        fastcgi_param FLYNE_REDIS_PASS "${REDIS_PASS}";
        fastcgi_param FLYNE_DIR "${FLYNE_DIR}";
        fastcgi_param FLYNE_SITES_DIR "${SITES_DIR}";
        fastcgi_param FLYNE_SERVER_IP "${SERVER_IP}";
        fastcgi_param FLYNE_NS1 "${NS1}";
        fastcgi_param FLYNE_NS2 "${NS2}";
        fastcgi_read_timeout 900;
        fastcgi_send_timeout 900;
        fastcgi_buffers 16 16k;
        fastcgi_buffer_size 32k;
    }
    limit_req zone=api burst=100 nodelay;
}
APICONF

# --- phpMyAdmin vhost ---
cat > /etc/nginx/sites-vhost/001-pma.conf << PMACONF
server {
    listen 80;
    listen [::]:80;
    server_name ${PMA_DOMAIN};
    root /usr/share/phpmyadmin;
    index index.php;
    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \\.php\$ {
        fastcgi_pass unix:/run/php/php8.4-fpm-api.sock;
        include snippets/php-fpm.conf;
    }
    location ~ /\\. { deny all; }
}
PMACONF

rm -f /etc/nginx/sites-enabled/default
nginx -t || error "Nginx config test failed"
systemctl restart nginx || error "Nginx failed"

#===============================================================================
# 9. BIND9 DNS CONFIGURATION
#===============================================================================
log "Configuring BIND9..."

cat > /etc/bind/named.conf.options << BINDOPTS
options {
    directory "/var/cache/bind";
    recursion no;
    allow-query { any; };
    allow-transfer { none; };
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
};
BINDOPTS

cat > /etc/bind/named.conf.local << BINDLOCAL
// Zone files managed by Flyne VPS
include "/etc/bind/zones/zones.conf";
BINDLOCAL

touch /etc/bind/zones/zones.conf
chown bind:bind /etc/bind/zones/zones.conf

systemctl restart bind9 2>/dev/null || systemctl restart named 2>/dev/null || warn "BIND9 restart failed"

#===============================================================================
# 10. POSTFIX + DOVECOT MAIL
#===============================================================================
log "Configuring mail server..."

cat > /etc/postfix/main.cf << POSTFIXCF
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

myhostname = ${SERVER_HOSTNAME}
mydomain = ${SERVER_HOSTNAME#*.}
myorigin = \$mydomain
mydestination = localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128

# Virtual mailbox settings
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailboxes.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-aliases.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_base = ${MAIL_DIR}

virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# TLS
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes
smtpd_tls_security_level = may

# SASL
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

smtpd_recipient_restrictions =
    permit_sasl_authenticated,
    permit_mynetworks,
    reject_unauth_destination,
    reject_unknown_recipient_domain

message_size_limit = 52428800
mailbox_size_limit = 0
POSTFIXCF

# Postfix MySQL lookups
cat > /etc/postfix/mysql-virtual-domains.cf << PVDOM
hosts = 127.0.0.1
user = flyne_admin
password = ${MYSQL_ROOT_PASS}
dbname = flyne_vps
query = SELECT domain FROM mail_domains WHERE domain='%s' AND status='active'
PVDOM

cat > /etc/postfix/mysql-virtual-mailboxes.cf << PVMBOX
hosts = 127.0.0.1
user = flyne_admin
password = ${MYSQL_ROOT_PASS}
dbname = flyne_vps
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM mail_accounts WHERE email='%s' AND is_active=1
PVMBOX

cat > /etc/postfix/mysql-virtual-aliases.cf << PVALIAS
hosts = 127.0.0.1
user = flyne_admin
password = ${MYSQL_ROOT_PASS}
dbname = flyne_vps
query = SELECT destination FROM mail_aliases WHERE source='%s' AND is_active=1
PVALIAS

chmod 640 /etc/postfix/mysql-*.cf
chgrp postfix /etc/postfix/mysql-*.cf

# Enable submission port
postconf -M submission/inet="submission inet n - y - - smtpd"
postconf -P submission/inet/syslog_name=postfix/submission
postconf -P submission/inet/smtpd_tls_security_level=encrypt
postconf -P submission/inet/smtpd_sasl_auth_enable=yes
postconf -P submission/inet/smtpd_recipient_restrictions="permit_sasl_authenticated,reject"

# Dovecot
cat > /etc/dovecot/dovecot.conf << 'DOVECOTMAIN'
protocols = imap pop3 lmtp
listen = *, ::
!include conf.d/*.conf
DOVECOTMAIN

cat > /etc/dovecot/conf.d/10-mail.conf << DOVEMAIL
mail_location = maildir:${MAIL_DIR}/%d/%n
mail_uid = 5000
mail_gid = 5000
mail_privileged_group = vmail
first_valid_uid = 5000
last_valid_uid = 5000
DOVEMAIL

cat > /etc/dovecot/conf.d/10-auth.conf << 'DOVEAUTH'
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-sql.conf.ext
DOVEAUTH

cat > /etc/dovecot/conf.d/auth-sql.conf.ext << 'DOVESQL'
passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
}
DOVESQL

cat > /etc/dovecot/dovecot-sql.conf.ext << DOVESQLEXT
driver = mysql
connect = host=127.0.0.1 dbname=flyne_vps user=flyne_admin password=${MYSQL_ROOT_PASS}
default_pass_scheme = BLF-CRYPT
password_query = SELECT email AS user, password_hash AS password FROM mail_accounts WHERE email='%u' AND is_active=1
user_query = SELECT 5000 AS uid, 5000 AS gid, '${MAIL_DIR}/%d/%n' AS home, CONCAT('*:bytes=', quota_mb * 1048576) AS quota_rule FROM mail_accounts WHERE email='%u'
DOVESQLEXT

chmod 600 /etc/dovecot/dovecot-sql.conf.ext

cat > /etc/dovecot/conf.d/10-master.conf << 'DOVEMASTER'
service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
        mode = 0600
        user = postfix
        group = postfix
    }
}
service auth {
    unix_listener /var/spool/postfix/private/auth {
        mode = 0660
        user = postfix
        group = postfix
    }
    unix_listener auth-userdb {
        mode = 0660
        user = vmail
        group = vmail
    }
}
service auth-worker {
    user = vmail
}
DOVEMASTER

cat > /etc/dovecot/conf.d/10-ssl.conf << 'DOVESSL'
ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
ssl_min_protocol = TLSv1.2
DOVESSL

cat > /etc/dovecot/conf.d/20-lmtp.conf << 'DOVELMTP'
protocol lmtp {
    mail_plugins = $mail_plugins
    postmaster_address = postmaster@localhost
}
DOVELMTP

# OpenDKIM
mkdir -p /etc/opendkim/keys
cat > /etc/opendkim.conf << DKIMCONF
Syslog yes
UMask 007
Socket local:/var/spool/postfix/opendkim/opendkim.sock
PidFile /run/opendkim/opendkim.pid
OversignHeaders From
TrustAnchorFile /usr/share/dns/root.key
Canonicalization relaxed/simple
Mode sv
SubDomains no
KeyTable /etc/opendkim/key.table
SigningTable refile:/etc/opendkim/signing.table
ExternalIgnoreList /etc/opendkim/trusted.hosts
InternalHosts /etc/opendkim/trusted.hosts
DKIMCONF

mkdir -p /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim

touch /etc/opendkim/key.table /etc/opendkim/signing.table
echo "127.0.0.1" > /etc/opendkim/trusted.hosts
echo "localhost" >> /etc/opendkim/trusted.hosts

postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = unix:opendkim/opendkim.sock"
postconf -e "non_smtpd_milters = unix:opendkim/opendkim.sock"

systemctl restart postfix 2>/dev/null || warn "Postfix restart failed"
systemctl restart dovecot 2>/dev/null || warn "Dovecot restart failed"
systemctl restart opendkim 2>/dev/null || warn "OpenDKIM restart failed"

#===============================================================================
# 11. PROFTPD CONFIGURATION
#===============================================================================
log "Configuring ProFTPD..."

if [[ -f /etc/proftpd/proftpd.conf ]]; then
cat > /etc/proftpd/proftpd.conf << PROFTPDCF
ServerName "${SERVER_HOSTNAME}"
ServerType standalone
DefaultServer on
Port 21
UseIPv6 off
Umask 022
MaxInstances 30
User nobody
Group nogroup

DefaultRoot ~
RequireValidShell off
AuthOrder mod_sql.c

PassivePorts 49152 65534
MasqueradeAddress ${SERVER_IP}

<IfModule mod_sql.c>
    SQLBackend mysql
    SQLAuthTypes Crypt
    SQLAuthenticate users
    SQLConnectInfo flyne_vps@localhost flyne_admin ${MYSQL_ROOT_PASS}
    SQLUserInfo ftp_accounts username password_hash NULL NULL home_dir NULL
    SQLUserWhereClause "is_active = 1"
    SQLMinUserUID 1000
    SQLDefaultUID 33
    SQLDefaultGID 33
</IfModule>

<IfModule mod_tls.c>
    TLSEngine on
    TLSLog /var/log/proftpd/tls.log
    TLSProtocol TLSv1.2 TLSv1.3
    TLSRSACertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    TLSRSACertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    TLSRequired off
</IfModule>

LogFormat default "%h %l %u %t \"%r\" %s %b"
LogFormat auth "%v [%P] %h %t \"%r\" %s"
PROFTPDCF

    systemctl restart proftpd 2>/dev/null || warn "ProFTPD restart failed"
fi

#===============================================================================
# 12. SSH/SFTP
#===============================================================================
log "Configuring SFTP..."

sed -i 's|^Subsystem.*sftp.*|Subsystem sftp internal-sftp|' /etc/ssh/sshd_config 2>/dev/null || \
    echo "Subsystem sftp internal-sftp" >> /etc/ssh/sshd_config

if ! grep -q "Match Group sftpusers" /etc/ssh/sshd_config; then
    cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Flyne VPS SFTP
Match Group sftpusers
    ChrootDirectory %h
    ForceCommand internal-sftp -u 0002
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
SSHCONF
fi

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "SSH restart failed"

#===============================================================================
# 13. SSL
#===============================================================================
log "Requesting SSL for panel domains..."
certbot --nginx -d ${PANEL_DOMAIN} -d ${PMA_DOMAIN} \
    --email ${ADMIN_EMAIL} --agree-tos --non-interactive --redirect 2>/dev/null || \
    warn "SSL failed - run: certbot --nginx -d ${PANEL_DOMAIN} -d ${PMA_DOMAIN}"

#===============================================================================
# 14. CONFIGURATION FILE
#===============================================================================
log "Creating configuration file..."
cat > "${FLYNE_DIR}/flyne-vps.conf" << CONFEOF
# Flyne VPS Control Panel Configuration v1.0
# Generated: $(date)

PANEL_DOMAIN="${PANEL_DOMAIN}"
PMA_DOMAIN="${PMA_DOMAIN}"
SERVER_HOSTNAME="${SERVER_HOSTNAME}"
SERVER_IP="${SERVER_IP}"
API_SECRET="${API_SECRET}"
MYSQL_USER="flyne_admin"
MYSQL_PASS="${MYSQL_ROOT_PASS}"
REDIS_PASS="${REDIS_PASS}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
NS1="${NS1}"
NS2="${NS2}"
SITES_DIR="${SITES_DIR}"
FLYNE_DIR="${FLYNE_DIR}"
MAIL_DIR="${MAIL_DIR}"
DNS_DIR="${DNS_DIR}"
NODE_DIR="${NODE_DIR}"
DEFAULT_PHP="8.4"
DEFAULT_WEBSERVER="nginx"
TOTAL_RAM="${TOTAL_RAM}"
CPU_CORES="${CPU_CORES}"
CONFEOF
chmod 640 "${FLYNE_DIR}/flyne-vps.conf"
chown flyne-agent:www-data "${FLYNE_DIR}/flyne-vps.conf"

#===============================================================================
# 15. NGINX VHOST TEMPLATE (for domain creation)
#===============================================================================
log "Creating vhost templates..."

mkdir -p "${FLYNE_DIR}/templates"

# Nginx: plain domain (no app) - serves static files + PHP
cat > "${FLYNE_DIR}/templates/nginx-domain.conf.tpl" << 'NGXTPL'
server {
    listen 80;
    listen [::]:80;
    server_name {{DOMAIN}} www.{{DOMAIN}};

    root {{DOCUMENT_ROOT}};
    index index.php index.html index.htm;

    access_log {{LOGS_DIR}}/access.log;
    error_log {{LOGS_DIR}}/error.log;

    include snippets/security.conf;
    include snippets/static-cache.conf;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:{{PHP_SOCKET}};
        include snippets/php-fpm.conf;
    }
}
NGXTPL

# Nginx: subdomain
cat > "${FLYNE_DIR}/templates/nginx-subdomain.conf.tpl" << 'NGXSUBTPL'
server {
    listen 80;
    listen [::]:80;
    server_name {{FULL_DOMAIN}};

    root {{DOCUMENT_ROOT}};
    index index.php index.html index.htm;

    access_log {{LOGS_DIR}}/access.log;
    error_log {{LOGS_DIR}}/error.log;

    include snippets/security.conf;
    include snippets/static-cache.conf;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:{{PHP_SOCKET}};
        include snippets/php-fpm.conf;
    }
}
NGXSUBTPL

# Nginx: Node.js proxy
cat > "${FLYNE_DIR}/templates/nginx-nodejs.conf.tpl" << 'NGXNODETPL'
server {
    listen 80;
    listen [::]:80;
    server_name {{DOMAIN}};

    access_log {{LOGS_DIR}}/access.log;
    error_log {{LOGS_DIR}}/error.log;

    location / {
        proxy_pass http://127.0.0.1:{{NODE_PORT}};
        include snippets/node-proxy.conf;
    }

    # Serve static files directly if they exist
    location /static/ {
        alias {{DOCUMENT_ROOT}}/static/;
        expires 30d;
    }
    location /public/ {
        alias {{DOCUMENT_ROOT}}/public/;
        expires 30d;
    }
}
NGXNODETPL

# Apache: plain domain
cat > "${FLYNE_DIR}/templates/apache-domain.conf.tpl" << 'APACHETPL'
<VirtualHost *:80>
    ServerName {{DOMAIN}}
    ServerAlias www.{{DOMAIN}}
    DocumentRoot {{DOCUMENT_ROOT}}

    <Directory {{DOCUMENT_ROOT}}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <FilesMatch \.php$>
        SetHandler "proxy:unix:{{PHP_SOCKET}}|fcgi://localhost"
    </FilesMatch>

    ErrorLog {{LOGS_DIR}}/error.log
    CustomLog {{LOGS_DIR}}/access.log combined
</VirtualHost>
APACHETPL

# Apache: Node.js proxy
cat > "${FLYNE_DIR}/templates/apache-nodejs.conf.tpl" << 'APACHENODETPL'
<VirtualHost *:80>
    ServerName {{DOMAIN}}
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:{{NODE_PORT}}/
    ProxyPassReverse / http://127.0.0.1:{{NODE_PORT}}/

    ErrorLog {{LOGS_DIR}}/error.log
    CustomLog {{LOGS_DIR}}/access.log combined
</VirtualHost>
APACHENODETPL

# DNS zone template
cat > "${FLYNE_DIR}/templates/zone.tpl" << 'ZONETPL'
$TTL 3600
@   IN  SOA {{NS1}}. admin.{{DOMAIN}}. (
        {{SERIAL}}  ; serial
        3600        ; refresh
        900         ; retry
        1209600     ; expire
        86400       ; minimum TTL
    )

    IN  NS  {{NS1}}.
    IN  NS  {{NS2}}.
    IN  A   {{SERVER_IP}}

www IN  A   {{SERVER_IP}}
mail IN A   {{SERVER_IP}}

@   IN  MX  10  mail.{{DOMAIN}}.
@   IN  TXT "v=spf1 a mx ip4:{{SERVER_IP}} ~all"
ZONETPL

# Default index.html for new domains
cat > "${FLYNE_DIR}/templates/default-index.html" << 'INDEXHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
            margin: 0; background: #0f172a; color: #e2e8f0; }
        .container { text-align: center; padding: 2rem; }
        h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        p { color: #94a3b8; font-size: 1.1rem; }
        .badge { display: inline-block; padding: 0.25rem 0.75rem; background: #1e293b;
            border-radius: 9999px; font-size: 0.85rem; color: #38bdf8; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Site is Ready</h1>
        <p>Your hosting is configured and ready for deployment.</p>
        <span class="badge">Powered by Flyne VPS</span>
    </div>
</body>
</html>
INDEXHTML

chown -R flyne-agent:flyne-agent "${FLYNE_DIR}/templates"

#===============================================================================
# 16. MANAGEMENT SCRIPTS
#===============================================================================
log "Creating management scripts..."

# ==================== DOMAIN CREATE ====================
# Creates domain with EMPTY document root (just default index.html)
cat > "${FLYNE_DIR}/scripts/domain-create.sh" << 'DOMCREATE'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
ACCOUNT="${2:-admin}"
PHP_VERSION="${3:-8.4}"
WEBSERVER="${4:-nginx}"

FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

LOG="/var/log/flyne/agent.log"
exec 2>>"$LOG"
echo "[$(date)] === Creating domain: $DOMAIN ===" >> "$LOG"

if [[ ! "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$ ]]; then
    echo '{"success":false,"error":"Invalid domain format"}'
    exit 1
fi

# Check if domain already exists
EXISTING=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
if [[ -n "$EXISTING" ]]; then
    echo '{"success":false,"error":"Domain already exists"}'
    exit 1
fi

ACCOUNT_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.accounts WHERE username='${ACCOUNT}'" 2>/dev/null)
if [[ -z "$ACCOUNT_ID" ]]; then
    echo '{"success":false,"error":"Account not found"}'
    exit 1
fi

SAFE_NAME=$(echo "$DOMAIN" | tr '.-' '__' | cut -c1-32)
SITE_USER="vhost_${SAFE_NAME}"

SITE_DIR="${SITES_DIR}/${DOMAIN}"
DOC_ROOT="${SITE_DIR}/public_html"
LOGS_DIR="${SITE_DIR}/logs"
TMP_DIR="${SITE_DIR}/tmp"
PRIVATE_DIR="${SITE_DIR}/private"

DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"

# Create system user
sudo useradd -r -d "$SITE_DIR" -s /usr/sbin/nologin -g www-data "$SITE_USER" 2>>"$LOG" || {
    if ! id "$SITE_USER" &>/dev/null; then
        echo '{"success":false,"error":"Failed to create system user"}'
        exit 1
    fi
}
sudo usermod -aG vhostusers "$SITE_USER"

# Create directories
sudo mkdir -p "$DOC_ROOT" "$LOGS_DIR" "$TMP_DIR" "$PRIVATE_DIR"
sudo chown root:root "$SITE_DIR"
sudo chmod 755 "$SITE_DIR"
sudo chown -R "${SITE_USER}:www-data" "$DOC_ROOT" "$LOGS_DIR" "$TMP_DIR" "$PRIVATE_DIR"
sudo chmod 2775 "$DOC_ROOT"
sudo chmod 750 "$LOGS_DIR" "$TMP_DIR" "$PRIVATE_DIR"

# Create log files
sudo touch "$LOGS_DIR"/{access.log,error.log,php-error.log}
sudo chown "${SITE_USER}:www-data" "$LOGS_DIR"/*.log
sudo chmod 664 "$LOGS_DIR"/*.log

# Copy default index page
sudo cp "${FLYNE_DIR}/templates/default-index.html" "$DOC_ROOT/index.html"
sudo chown "${SITE_USER}:www-data" "$DOC_ROOT/index.html"

# Create PHP-FPM pool
AVAILABLE_RAM=$((TOTAL_RAM * 50 / 100))
SITE_COUNT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT COUNT(*)+1 FROM flyne_vps.domains" 2>/dev/null || echo 1)
MAX_CH=$((AVAILABLE_RAM / 64 / SITE_COUNT))
[[ $MAX_CH -lt 4 ]] && MAX_CH=4; [[ $MAX_CH -gt 20 ]] && MAX_CH=20
START=$((MAX_CH / 4)); [[ $START -lt 1 ]] && START=1
MINSP=$((MAX_CH / 8)); [[ $MINSP -lt 1 ]] && MINSP=1
MAXSP=$((MAX_CH / 2)); [[ $MAXSP -lt 2 ]] && MAXSP=2

cat > "/tmp/pool-${DOMAIN}.conf" << POOLEOF
[${DOMAIN}]
user = ${SITE_USER}
group = www-data
listen = ${SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = ${MAX_CH}
pm.start_servers = ${START}
pm.min_spare_servers = ${MINSP}
pm.max_spare_servers = ${MAXSP}
pm.max_requests = 1000
request_terminate_timeout = 300s
slowlog = ${LOGS_DIR}/php-slow.log
php_admin_value[open_basedir] = ${SITE_DIR}:/tmp:/usr/share/php:/dev/urandom
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
php_admin_value[memory_limit] = 256M
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on
php_admin_value[session.save_handler] = files
php_admin_value[session.save_path] = ${TMP_DIR}
POOLEOF
sudo mv "/tmp/pool-${DOMAIN}.conf" "/etc/php/${PHP_VERSION}/fpm/pool.d/${DOMAIN}.conf"

# Create web server vhost
if [[ "$WEBSERVER" == "nginx" ]]; then
    sed -e "s|{{DOMAIN}}|${DOMAIN}|g" \
        -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
        -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
        -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
        "${FLYNE_DIR}/templates/nginx-domain.conf.tpl" > "/tmp/vhost-${DOMAIN}.conf"
    sudo mv "/tmp/vhost-${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}.conf"
elif [[ "$WEBSERVER" == "apache" ]]; then
    sed -e "s|{{DOMAIN}}|${DOMAIN}|g" \
        -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
        -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
        -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
        "${FLYNE_DIR}/templates/apache-domain.conf.tpl" > "/tmp/vhost-${DOMAIN}.conf"
    sudo mv "/tmp/vhost-${DOMAIN}.conf" "/etc/apache2/sites-vhost/${DOMAIN}.conf"
fi

# Save metadata
echo "$SOCKET" > "${FLYNE_DIR}/run/${DOMAIN}.sock"
echo "$PHP_VERSION" > "${FLYNE_DIR}/run/${DOMAIN}.php"
echo "$WEBSERVER" > "${FLYNE_DIR}/run/${DOMAIN}.ws"

# Register in database
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO domains (account_id, domain, site_user, document_root, webserver, php_version, status)
VALUES (${ACCOUNT_ID}, '${DOMAIN}', '${SITE_USER}', '${DOC_ROOT}', '${WEBSERVER}', '${PHP_VERSION}', 'active');
SQLEOF

# Reload services
sudo systemctl reload "php${PHP_VERSION}-fpm" 2>/dev/null
if [[ "$WEBSERVER" == "nginx" ]]; then
    sudo nginx -t >> "$LOG" 2>&1 && sudo systemctl reload nginx
elif [[ "$WEBSERVER" == "apache" ]]; then
    sudo apachectl configtest >> "$LOG" 2>&1 && sudo systemctl reload apache2
fi

# Background: SSL + DNS zone
cat > "/tmp/post-domain-${DOMAIN}.sh" << POSTEOF
#!/bin/bash
sleep 3
echo "[\$(date)] Post-setup for ${DOMAIN}" >> "$LOG"

# Attempt SSL
if sudo certbot --nginx -d "${DOMAIN}" -d "www.${DOMAIN}" --non-interactive --agree-tos --email "${ADMIN_EMAIL}" --redirect >> "$LOG" 2>&1; then
    mysql -u "${MYSQL_USER}" -p"${MYSQL_PASS}" -e \
        "UPDATE flyne_vps.domains SET ssl_enabled=1, ssl_type='letsencrypt' WHERE domain='${DOMAIN}'" 2>/dev/null
    echo "[\$(date)] SSL enabled for ${DOMAIN}" >> "$LOG"
fi

rm -f "/tmp/post-domain-${DOMAIN}.sh"
POSTEOF
chmod +x "/tmp/post-domain-${DOMAIN}.sh"
nohup /tmp/post-domain-${DOMAIN}.sh > /dev/null 2>&1 &
disown

echo "[$(date)] Domain created: $DOMAIN (empty, no app)" >> "$LOG"

cat << JSONEOF
{
    "success": true,
    "data": {
        "domain": "${DOMAIN}",
        "url": "http://${DOMAIN}",
        "document_root": "${DOC_ROOT}",
        "site_user": "${SITE_USER}",
        "php_version": "${PHP_VERSION}",
        "webserver": "${WEBSERVER}",
        "ssl_pending": true,
        "app_installed": null
    }
}
JSONEOF
DOMCREATE
chmod +x "${FLYNE_DIR}/scripts/domain-create.sh"

# ==================== DOMAIN DELETE ====================
cat > "${FLYNE_DIR}/scripts/domain-delete.sh" << 'DOMDELETE'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

LOG="/var/log/flyne/agent.log"
echo "[$(date)] Deleting domain: $DOMAIN" >> "$LOG"

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user, php_version, webserver FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
if [[ -z "$SITE_INFO" ]]; then
    echo '{"success":false,"error":"Domain not found"}'
    exit 1
fi
read DOMAIN_ID SITE_USER PHP_VER WS <<< "$SITE_INFO"

# Stop Node.js apps if any
PM2_NAMES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT pm2_name FROM flyne_vps.apps WHERE domain_id=${DOMAIN_ID} AND app_type='nodejs' AND pm2_name IS NOT NULL" 2>/dev/null)
for PM2N in $PM2_NAMES; do
    sudo -u "$SITE_USER" pm2 delete "$PM2N" 2>/dev/null || true
done

# Drop databases linked to domain apps
DB_NAMES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT db_name FROM flyne_vps.apps WHERE domain_id=${DOMAIN_ID} AND db_name IS NOT NULL" 2>/dev/null)
for DBN in $DB_NAMES; do
    DB_USR=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
        "SELECT db_user FROM flyne_vps.apps WHERE domain_id=${DOMAIN_ID} AND db_name='${DBN}'" 2>/dev/null)
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "DROP DATABASE IF EXISTS \`${DBN}\`; DROP USER IF EXISTS '${DB_USR}'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null
done

# Drop standalone databases
SDBNAMES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT db_name, db_user FROM flyne_vps.user_databases WHERE domain_id=${DOMAIN_ID}" 2>/dev/null)
while read DBN2 DBU2; do
    [[ -z "$DBN2" ]] && continue
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "DROP DATABASE IF EXISTS \`${DBN2}\`; DROP USER IF EXISTS '${DBU2}'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null
done <<< "$SDBNAMES"

# Remove DNS zone
sudo rm -f "${DNS_DIR}/${DOMAIN}.zone"
sudo sed -i "/${DOMAIN}/d" "${DNS_DIR}/zones.conf"
sudo rndc reload 2>/dev/null || true

# Remove mail domain data
MAIL_DOMAIN_DIR="${MAIL_DIR}/${DOMAIN}"
sudo rm -rf "$MAIL_DOMAIN_DIR"

# Remove DKIM keys
sudo rm -rf "/etc/opendkim/keys/${DOMAIN}"
sudo sed -i "/${DOMAIN}/d" /etc/opendkim/key.table 2>/dev/null
sudo sed -i "/${DOMAIN}/d" /etc/opendkim/signing.table 2>/dev/null

# Remove FTP accounts
FTP_USERS=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT username FROM flyne_vps.ftp_accounts WHERE domain_id=${DOMAIN_ID}" 2>/dev/null)
for FU in $FTP_USERS; do
    sudo userdel "$FU" 2>/dev/null || true
done

# Remove system user
sudo userdel "$SITE_USER" 2>/dev/null || true

# Remove files and configs
sudo rm -rf "${SITES_DIR}/${DOMAIN}"
sudo rm -f "/etc/nginx/sites-vhost/${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}_*.conf"
sudo rm -f "/etc/nginx/cache-zones/${DOMAIN}.conf"
sudo rm -f "/etc/apache2/sites-vhost/${DOMAIN}.conf" "/etc/apache2/sites-vhost/${DOMAIN}_*.conf"
sudo rm -f "/etc/php/${PHP_VER}/fpm/pool.d/${DOMAIN}.conf"
sudo rm -f "${FLYNE_DIR}/run/${DOMAIN}."*

# Remove from database (cascades to subdomains, apps, dns, mail, ftp, cron, ssl, backups)
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "DELETE FROM flyne_vps.domains WHERE id=${DOMAIN_ID}" 2>/dev/null

# Reload services
sudo systemctl reload "php${PHP_VER}-fpm" 2>/dev/null || true
sudo nginx -t 2>/dev/null && sudo systemctl reload nginx 2>/dev/null || true
sudo systemctl reload postfix 2>/dev/null || true

echo "[$(date)] Domain deleted: $DOMAIN" >> "$LOG"
echo '{"success":true,"message":"Domain and all associated data deleted"}'
DOMDELETE
chmod +x "${FLYNE_DIR}/scripts/domain-delete.sh"

# ==================== SUBDOMAIN CREATE ====================
cat > "${FLYNE_DIR}/scripts/subdomain-create.sh" << 'SUBCREATE'
#!/bin/bash
set -uo pipefail
SUBDOMAIN="$1"
PARENT_DOMAIN="$2"
CUSTOM_ROOT="${3:-}"

FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

LOG="/var/log/flyne/agent.log"
FULL_DOMAIN="${SUBDOMAIN}.${PARENT_DOMAIN}"

DOMAIN_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user, php_version, webserver FROM flyne_vps.domains WHERE domain='${PARENT_DOMAIN}'" 2>/dev/null)
if [[ -z "$DOMAIN_INFO" ]]; then
    echo '{"success":false,"error":"Parent domain not found"}'
    exit 1
fi
read DOMAIN_ID SITE_USER PHP_VER WS <<< "$DOMAIN_INFO"

SITE_DIR="${SITES_DIR}/${PARENT_DOMAIN}"
if [[ -n "$CUSTOM_ROOT" ]]; then
    DOC_ROOT="${SITE_DIR}/${CUSTOM_ROOT}"
else
    DOC_ROOT="${SITE_DIR}/subdomains/${SUBDOMAIN}"
fi
LOGS_DIR="${SITE_DIR}/logs"

DOMAIN_HASH=$(echo -n "$PARENT_DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"

sudo mkdir -p "$DOC_ROOT"
sudo chown "${SITE_USER}:www-data" "$DOC_ROOT"
sudo chmod 2775 "$DOC_ROOT"
sudo cp "${FLYNE_DIR}/templates/default-index.html" "$DOC_ROOT/index.html"
sudo chown "${SITE_USER}:www-data" "$DOC_ROOT/index.html"

if [[ "$WS" == "nginx" ]]; then
    sed -e "s|{{FULL_DOMAIN}}|${FULL_DOMAIN}|g" \
        -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
        -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
        -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
        "${FLYNE_DIR}/templates/nginx-subdomain.conf.tpl" > "/tmp/sub-${FULL_DOMAIN}.conf"
    sudo mv "/tmp/sub-${FULL_DOMAIN}.conf" "/etc/nginx/sites-vhost/${PARENT_DOMAIN}_${SUBDOMAIN}.conf"
    sudo nginx -t && sudo systemctl reload nginx
elif [[ "$WS" == "apache" ]]; then
    cat > "/tmp/sub-${FULL_DOMAIN}.conf" << APACHESUB
<VirtualHost *:80>
    ServerName ${FULL_DOMAIN}
    DocumentRoot ${DOC_ROOT}
    <Directory ${DOC_ROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch \.php\$>
        SetHandler "proxy:unix:${SOCKET}|fcgi://localhost"
    </FilesMatch>
    ErrorLog ${LOGS_DIR}/error.log
    CustomLog ${LOGS_DIR}/access.log combined
</VirtualHost>
APACHESUB
    sudo mv "/tmp/sub-${FULL_DOMAIN}.conf" "/etc/apache2/sites-vhost/${PARENT_DOMAIN}_${SUBDOMAIN}.conf"
    sudo apachectl configtest && sudo systemctl reload apache2
fi

# Add DNS A record for subdomain
ZONE_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.dns_zones WHERE domain='${PARENT_DOMAIN}'" 2>/dev/null)
if [[ -n "$ZONE_ID" ]]; then
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
        "INSERT INTO flyne_vps.dns_records (zone_id, name, type, content) VALUES (${ZONE_ID}, '${SUBDOMAIN}', 'A', '${SERVER_IP}')" 2>/dev/null
    # Regenerate zone file
    sudo bash "${FLYNE_DIR}/scripts/dns-rebuild-zone.sh" "$PARENT_DOMAIN"
fi

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO subdomains (domain_id, subdomain, full_domain, document_root, php_version, status)
VALUES (${DOMAIN_ID}, '${SUBDOMAIN}', '${FULL_DOMAIN}', '${DOC_ROOT}', '${PHP_VER}', 'active');
SQLEOF

# Attempt SSL in background
nohup bash -c "sleep 3; certbot --nginx -d ${FULL_DOMAIN} --non-interactive --agree-tos --email ${ADMIN_EMAIL} --redirect 2>/dev/null && mysql -u ${MYSQL_USER} -p'${MYSQL_PASS}' -e \"UPDATE flyne_vps.subdomains SET ssl_enabled=1 WHERE full_domain='${FULL_DOMAIN}'\" 2>/dev/null" > /dev/null 2>&1 &

echo "[$(date)] Subdomain created: $FULL_DOMAIN" >> "$LOG"
cat << JSONEOF
{
    "success": true,
    "data": {
        "subdomain": "${SUBDOMAIN}",
        "full_domain": "${FULL_DOMAIN}",
        "document_root": "${DOC_ROOT}",
        "parent_domain": "${PARENT_DOMAIN}"
    }
}
JSONEOF
SUBCREATE
chmod +x "${FLYNE_DIR}/scripts/subdomain-create.sh"

# ==================== APP INSTALL (WordPress, Node.js, etc.) ====================
cat > "${FLYNE_DIR}/scripts/app-install.sh" << 'APPINSTALL'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
APP_TYPE="$2"
shift 2
# Additional params passed as key=value
declare -A PARAMS
for arg in "$@"; do
    key="${arg%%=*}"; val="${arg#*=}"
    PARAMS["$key"]="$val"
done

FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

LOG="/var/log/flyne/apps.log"
echo "[$(date)] Installing ${APP_TYPE} on ${DOMAIN}" >> "$LOG"

DOMAIN_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user, document_root, php_version, webserver FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
if [[ -z "$DOMAIN_INFO" ]]; then
    echo '{"success":false,"error":"Domain not found"}'
    exit 1
fi
read DOMAIN_ID SITE_USER DOC_ROOT PHP_VER WS <<< "$DOMAIN_INFO"

SITE_DIR="${SITES_DIR}/${DOMAIN}"
LOGS_DIR="${SITE_DIR}/logs"
INSTALL_PATH="${PARAMS[path]:-$DOC_ROOT}"

# Make path absolute if relative
[[ "$INSTALL_PATH" != /* ]] && INSTALL_PATH="${DOC_ROOT}/${INSTALL_PATH}"

SAFE_NAME=$(echo "$DOMAIN" | tr '.-' '__' | cut -c1-32)

case "$APP_TYPE" in

# ============== WORDPRESS ==============
wordpress)
    APP_TITLE="${PARAMS[title]:-$DOMAIN}"
    ADMIN_USER="${PARAMS[admin_user]:-admin}"
    ADMIN_PASS="${PARAMS[admin_pass]:-$(openssl rand -hex 8)}"
    ADMIN_MAIL="${PARAMS[admin_email]:-${ADMIN_EMAIL}}"

    DB_NAME="wp_${SAFE_NAME}"
    DB_USER="dbw_${SAFE_NAME}"
    DB_PASS=$(openssl rand -hex 16)
    REDIS_DB=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
        "SELECT COALESCE(MAX(redis_db),0)+1 FROM flyne_vps.apps WHERE redis_db IS NOT NULL" 2>/dev/null || echo 1)

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" << SQLEOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '${DB_USER}'@'localhost';
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

    sudo mkdir -p "$INSTALL_PATH"
    sudo chown "${SITE_USER}:www-data" "$INSTALL_PATH"
    cd "$INSTALL_PATH"

    sudo -u "$SITE_USER" wp core download --path="$INSTALL_PATH" >> "$LOG" 2>&1 || {
        echo '{"success":false,"error":"Failed to download WordPress"}'
        exit 1
    }

    cat > "/tmp/wp-config-${DOMAIN}.php" << WPCFG
<?php
define('DB_NAME', '${DB_NAME}');
define('DB_USER', '${DB_USER}');
define('DB_PASSWORD', '${DB_PASS}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
$(for i in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
    echo "define('${i}', '$(openssl rand -hex 32)');"
done)
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
WPCFG
    sudo mv "/tmp/wp-config-${DOMAIN}.php" "${INSTALL_PATH}/wp-config.php"
    sudo chown "${SITE_USER}:www-data" "${INSTALL_PATH}/wp-config.php"
    sudo chmod 640 "${INSTALL_PATH}/wp-config.php"

    SITE_URL="http://${DOMAIN}"
    [[ "$INSTALL_PATH" != "$DOC_ROOT" ]] && SITE_URL="${SITE_URL}/$(basename $INSTALL_PATH)"

    sudo -u "$SITE_USER" wp core install \
        --path="$INSTALL_PATH" --url="$SITE_URL" --title="$APP_TITLE" \
        --admin_user="$ADMIN_USER" --admin_email="$ADMIN_MAIL" \
        --admin_password="$ADMIN_PASS" --skip-email >> "$LOG" 2>&1 || {
        echo '{"success":false,"error":"WordPress install failed"}'
        exit 1
    }

    sudo chown -R "${SITE_USER}:www-data" "$INSTALL_PATH"
    sudo find "$INSTALL_PATH" -type d -exec chmod 2775 {} \;
    sudo find "$INSTALL_PATH" -type f -exec chmod 664 {} \;
    sudo chmod 640 "${INSTALL_PATH}/wp-config.php"

    # Update nginx vhost with WordPress-specific rules if at doc root
    if [[ "$INSTALL_PATH" == "$DOC_ROOT" && "$WS" == "nginx" ]]; then
        DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
        SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"
        SAFE_ZONE=$(echo "$DOMAIN" | tr '.-' '__')
        CACHE_DIR="/var/cache/nginx/fastcgi/sites/${DOMAIN}"
        sudo mkdir -p "$CACHE_DIR"
        sudo chown www-data:www-data "$CACHE_DIR"

        cat > "/tmp/cache-${DOMAIN}.conf" << CEOF
fastcgi_cache_path ${CACHE_DIR} levels=1:2 keys_zone=CACHE_${SAFE_ZONE}:32m max_size=512m inactive=7d use_temp_path=off;
CEOF
        sudo mv "/tmp/cache-${DOMAIN}.conf" "/etc/nginx/cache-zones/${DOMAIN}.conf"

        cat > "/tmp/vhost-wp-${DOMAIN}.conf" << NGXWP
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${DOC_ROOT};
    index index.php index.html;
    access_log ${LOGS_DIR}/access.log;
    error_log ${LOGS_DIR}/error.log;
    include snippets/security.conf;
    include snippets/static-cache.conf;

    location ~* /(?:uploads|files)/.*\.php\$ { deny all; }
    location ~ /wp-config\.php\$ { deny all; }
    location = /xmlrpc.php { deny all; }

    set \$skip_cache 0;
    if (\$request_method = POST) { set \$skip_cache 1; }
    if (\$request_uri ~* "/wp-admin/|/wp-login.php") { set \$skip_cache 1; }
    if (\$http_cookie ~* "wordpress_logged_in") { set \$skip_cache 1; }

    location / { try_files \$uri \$uri/ /index.php?\$args; }
    location ~ \.php\$ {
        fastcgi_pass unix:${SOCKET};
        include snippets/php-fpm.conf;
        fastcgi_cache CACHE_${SAFE_ZONE};
        fastcgi_cache_valid 200 60m;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        add_header X-Cache \$upstream_cache_status;
    }
}
NGXWP
        sudo mv "/tmp/vhost-wp-${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}.conf"
        sudo nginx -t && sudo systemctl reload nginx
    fi

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO apps (domain_id, app_type, app_name, install_path, app_url, db_name, db_user, db_pass, redis_db, status)
VALUES (${DOMAIN_ID}, 'wordpress', '${APP_TITLE}', '${INSTALL_PATH}', '${SITE_URL}', '${DB_NAME}', '${DB_USER}', '${DB_PASS}', ${REDIS_DB}, 'active');
SQLEOF

    cat << JSONEOF
{
    "success": true,
    "app": "wordpress",
    "data": {
        "url": "${SITE_URL}",
        "admin_url": "${SITE_URL}/wp-admin/",
        "admin_user": "${ADMIN_USER}",
        "admin_pass": "${ADMIN_PASS}",
        "admin_email": "${ADMIN_MAIL}",
        "db_name": "${DB_NAME}",
        "db_user": "${DB_USER}",
        "db_pass": "${DB_PASS}",
        "redis_db": ${REDIS_DB}
    }
}
JSONEOF
    ;;

# ============== NODE.JS ==============
nodejs)
    NODE_VER="${PARAMS[node_version]:-20}"
    ENTRY="${PARAMS[entry]:-app.js}"
    PORT="${PARAMS[port]:-$(shuf -i 3001-9999 -n 1)}"
    APP_NAME="${PARAMS[app_name]:-${SAFE_NAME}}"
    ENV_MODE="${PARAMS[env]:-production}"

    sudo mkdir -p "$INSTALL_PATH"
    sudo chown "${SITE_USER}:www-data" "$INSTALL_PATH"
    sudo chmod 2775 "$INSTALL_PATH"

    # Create a sample app if directory is empty
    if [[ ! -f "${INSTALL_PATH}/package.json" ]]; then
        cat > "/tmp/package-${DOMAIN}.json" << PKGJSON
{
    "name": "${APP_NAME}",
    "version": "1.0.0",
    "main": "${ENTRY}",
    "scripts": {
        "start": "node ${ENTRY}",
        "dev": "node --watch ${ENTRY}"
    }
}
PKGJSON
        sudo mv "/tmp/package-${DOMAIN}.json" "${INSTALL_PATH}/package.json"

        cat > "/tmp/app-${DOMAIN}.js" << APPJS
const http = require('http');
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>Node.js App Running</h1><p>Port: ${PORT}</p>');
});
server.listen(${PORT}, '127.0.0.1', () => {
    console.log('Server running on port ${PORT}');
});
APPJS
        sudo mv "/tmp/app-${DOMAIN}.js" "${INSTALL_PATH}/${ENTRY}"
        sudo chown -R "${SITE_USER}:www-data" "$INSTALL_PATH"
    fi

    # Install dependencies if package.json exists
    if [[ -f "${INSTALL_PATH}/package.json" ]]; then
        cd "$INSTALL_PATH"
        export NVM_DIR="/opt/nvm"
        [[ -s "$NVM_DIR/nvm.sh" ]] && source "$NVM_DIR/nvm.sh"
        nvm use "$NODE_VER" 2>/dev/null || nvm use default
        sudo -u "$SITE_USER" bash -c "cd ${INSTALL_PATH} && export NVM_DIR=/opt/nvm && source \$NVM_DIR/nvm.sh && nvm use ${NODE_VER} 2>/dev/null; npm install --production" >> "$LOG" 2>&1 || warn "npm install failed"
    fi

    # Create PM2 ecosystem file
    cat > "/tmp/ecosystem-${DOMAIN}.json" << PM2CFG
{
    "apps": [{
        "name": "${APP_NAME}",
        "script": "${INSTALL_PATH}/${ENTRY}",
        "cwd": "${INSTALL_PATH}",
        "instances": 1,
        "exec_mode": "fork",
        "env": {
            "NODE_ENV": "${ENV_MODE}",
            "PORT": "${PORT}"
        },
        "max_memory_restart": "256M",
        "log_file": "${LOGS_DIR}/node-${APP_NAME}.log",
        "error_file": "${LOGS_DIR}/node-${APP_NAME}-error.log",
        "out_file": "${LOGS_DIR}/node-${APP_NAME}-out.log"
    }]
}
PM2CFG
    sudo mv "/tmp/ecosystem-${DOMAIN}.json" "${INSTALL_PATH}/ecosystem.config.json"
    sudo chown "${SITE_USER}:www-data" "${INSTALL_PATH}/ecosystem.config.json"

    # Start with PM2
    sudo -u "$SITE_USER" pm2 start "${INSTALL_PATH}/ecosystem.config.json" >> "$LOG" 2>&1 || warn "PM2 start failed"
    sudo -u "$SITE_USER" pm2 save >> "$LOG" 2>&1

    # Setup PM2 startup
    pm2 startup systemd -u "$SITE_USER" --hp "${SITE_DIR}" >> "$LOG" 2>&1 || true

    # Update nginx to proxy to Node.js
    DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
    if [[ "$WS" == "nginx" ]]; then
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" \
            -e "s|{{DOCUMENT_ROOT}}|${INSTALL_PATH}|g" \
            -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
            -e "s|{{NODE_PORT}}|${PORT}|g" \
            "${FLYNE_DIR}/templates/nginx-nodejs.conf.tpl" > "/tmp/vhost-node-${DOMAIN}.conf"
        sudo mv "/tmp/vhost-node-${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}.conf"
        sudo nginx -t && sudo systemctl reload nginx
    elif [[ "$WS" == "apache" ]]; then
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" \
            -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
            -e "s|{{NODE_PORT}}|${PORT}|g" \
            "${FLYNE_DIR}/templates/apache-nodejs.conf.tpl" > "/tmp/vhost-node-${DOMAIN}.conf"
        sudo mv "/tmp/vhost-node-${DOMAIN}.conf" "/etc/apache2/sites-vhost/${DOMAIN}.conf"
        sudo apachectl configtest && sudo systemctl reload apache2
    fi

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO apps (domain_id, app_type, app_name, install_path, app_url, node_version, node_entry, node_port, pm2_name, status)
VALUES (${DOMAIN_ID}, 'nodejs', '${APP_NAME}', '${INSTALL_PATH}', 'http://${DOMAIN}', '${NODE_VER}', '${ENTRY}', ${PORT}, '${APP_NAME}', 'active');
SQLEOF

    cat << JSONEOF
{
    "success": true,
    "app": "nodejs",
    "data": {
        "url": "http://${DOMAIN}",
        "app_name": "${APP_NAME}",
        "node_version": "${NODE_VER}",
        "entry": "${ENTRY}",
        "port": ${PORT},
        "pm2_name": "${APP_NAME}",
        "install_path": "${INSTALL_PATH}"
    }
}
JSONEOF
    ;;

# ============== STATIC SITE ==============
static)
    sudo mkdir -p "$INSTALL_PATH"
    sudo cp "${FLYNE_DIR}/templates/default-index.html" "$INSTALL_PATH/index.html"
    sudo chown -R "${SITE_USER}:www-data" "$INSTALL_PATH"

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO apps (domain_id, app_type, app_name, install_path, app_url, status)
VALUES (${DOMAIN_ID}, 'static', 'Static Site', '${INSTALL_PATH}', 'http://${DOMAIN}', 'active');
SQLEOF

    echo '{"success":true,"app":"static","data":{"message":"Static site ready","path":"'"$INSTALL_PATH"'"}}'
    ;;

# ============== LARAVEL ==============
laravel)
    DB_NAME="lv_${SAFE_NAME}"
    DB_USER="dbl_${SAFE_NAME}"
    DB_PASS=$(openssl rand -hex 16)

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" << SQLEOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '${DB_USER}'@'localhost';
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQLEOF

    sudo mkdir -p "$INSTALL_PATH"
    sudo chown "${SITE_USER}:www-data" "$INSTALL_PATH"
    cd "$INSTALL_PATH"

    sudo -u "$SITE_USER" composer create-project laravel/laravel . >> "$LOG" 2>&1 || {
        echo '{"success":false,"error":"Laravel install failed - composer may not be available"}'
        exit 1
    }

    # Update .env
    sudo -u "$SITE_USER" sed -i "s|DB_DATABASE=.*|DB_DATABASE=${DB_NAME}|" "${INSTALL_PATH}/.env"
    sudo -u "$SITE_USER" sed -i "s|DB_USERNAME=.*|DB_USERNAME=${DB_USER}|" "${INSTALL_PATH}/.env"
    sudo -u "$SITE_USER" sed -i "s|DB_PASSWORD=.*|DB_PASSWORD=${DB_PASS}|" "${INSTALL_PATH}/.env"
    sudo -u "$SITE_USER" sed -i "s|APP_URL=.*|APP_URL=http://${DOMAIN}|" "${INSTALL_PATH}/.env"

    # Point document root to public/
    DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
    SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"
    if [[ "$WS" == "nginx" ]]; then
        cat > "/tmp/vhost-laravel-${DOMAIN}.conf" << NGXLARA
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${INSTALL_PATH}/public;
    index index.php;
    access_log ${LOGS_DIR}/access.log;
    error_log ${LOGS_DIR}/error.log;
    include snippets/security.conf;
    location / { try_files \$uri \$uri/ /index.php?\$query_string; }
    location ~ \.php\$ {
        fastcgi_pass unix:${SOCKET};
        include snippets/php-fpm.conf;
    }
}
NGXLARA
        sudo mv "/tmp/vhost-laravel-${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}.conf"
        sudo nginx -t && sudo systemctl reload nginx
    fi

    sudo chown -R "${SITE_USER}:www-data" "$INSTALL_PATH"
    sudo chmod -R 775 "${INSTALL_PATH}/storage" "${INSTALL_PATH}/bootstrap/cache"

    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT INTO apps (domain_id, app_type, app_name, install_path, app_url, db_name, db_user, db_pass, status)
VALUES (${DOMAIN_ID}, 'laravel', 'Laravel', '${INSTALL_PATH}', 'http://${DOMAIN}', '${DB_NAME}', '${DB_USER}', '${DB_PASS}', 'active');
SQLEOF

    cat << JSONEOF
{
    "success": true,
    "app": "laravel",
    "data": {
        "url": "http://${DOMAIN}",
        "install_path": "${INSTALL_PATH}",
        "db_name": "${DB_NAME}",
        "db_user": "${DB_USER}",
        "db_pass": "${DB_PASS}"
    }
}
JSONEOF
    ;;

*)
    echo "{\"success\":false,\"error\":\"Unknown app type: ${APP_TYPE}\"}"
    exit 1
    ;;
esac

echo "[$(date)] App ${APP_TYPE} installed on ${DOMAIN}" >> "$LOG"
APPINSTALL
chmod +x "${FLYNE_DIR}/scripts/app-install.sh"

# ==================== APP UNINSTALL ====================
cat > "${FLYNE_DIR}/scripts/app-uninstall.sh" << 'APPUNINSTALL'
#!/bin/bash
set -uo pipefail
APP_ID="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

APP_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT a.app_type, a.install_path, a.db_name, a.db_user, a.pm2_name, a.domain_id, d.site_user, d.domain, d.document_root, d.php_version, d.webserver \
     FROM flyne_vps.apps a JOIN flyne_vps.domains d ON a.domain_id=d.id WHERE a.id=${APP_ID}" 2>/dev/null)
if [[ -z "$APP_INFO" ]]; then
    echo '{"success":false,"error":"App not found"}'
    exit 1
fi
read APP_TYPE INSTALL_PATH DB_NAME DB_USER PM2_NAME DOMAIN_ID SITE_USER DOMAIN DOC_ROOT PHP_VER WS <<< "$APP_INFO"

# Stop Node.js if applicable
if [[ "$APP_TYPE" == "nodejs" && -n "$PM2_NAME" && "$PM2_NAME" != "NULL" ]]; then
    sudo -u "$SITE_USER" pm2 delete "$PM2_NAME" 2>/dev/null || true
fi

# Drop database if applicable
if [[ -n "$DB_NAME" && "$DB_NAME" != "NULL" ]]; then
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
        "DROP DATABASE IF EXISTS \`${DB_NAME}\`; DROP USER IF EXISTS '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;" 2>/dev/null
fi

# Clean app files (but keep directory with default index)
sudo rm -rf "${INSTALL_PATH}"/*
sudo cp "${FLYNE_DIR}/templates/default-index.html" "${INSTALL_PATH}/index.html"
sudo chown "${SITE_USER}:www-data" "${INSTALL_PATH}/index.html"

# Restore default vhost (if at doc root)
if [[ "$INSTALL_PATH" == "$DOC_ROOT" ]]; then
    DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
    SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"
    if [[ "$WS" == "nginx" ]]; then
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
            -e "s|{{LOGS_DIR}}|${SITES_DIR}/${DOMAIN}/logs|g" -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
            "${FLYNE_DIR}/templates/nginx-domain.conf.tpl" > "/etc/nginx/sites-vhost/${DOMAIN}.conf"
        sudo rm -f "/etc/nginx/cache-zones/${DOMAIN}.conf"
        sudo nginx -t && sudo systemctl reload nginx
    fi
fi

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "DELETE FROM flyne_vps.apps WHERE id=${APP_ID}" 2>/dev/null
echo '{"success":true,"message":"App uninstalled"}'
APPUNINSTALL
chmod +x "${FLYNE_DIR}/scripts/app-uninstall.sh"

# ==================== WEBSERVER SWITCH ====================
cat > "${FLYNE_DIR}/scripts/webserver-switch.sh" << 'WSSWITCH'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
NEW_WS="$2"

FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

LOG="/var/log/flyne/agent.log"

ALLOWED="nginx apache openlitespeed"
if [[ ! " $ALLOWED " =~ " $NEW_WS " ]]; then
    echo '{"success":false,"error":"Invalid webserver. Use: nginx, apache, openlitespeed"}'
    exit 1
fi

DOMAIN_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user, document_root, php_version, webserver FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
if [[ -z "$DOMAIN_INFO" ]]; then
    echo '{"success":false,"error":"Domain not found"}'
    exit 1
fi
read DID SITE_USER DOC_ROOT PHP_VER OLD_WS <<< "$DOMAIN_INFO"

if [[ "$OLD_WS" == "$NEW_WS" ]]; then
    echo '{"success":true,"message":"Already using '"$NEW_WS"'"}'
    exit 0
fi

LOGS_DIR="${SITES_DIR}/${DOMAIN}/logs"
DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"

# Check if domain has a Node.js app
NODE_PORT=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT node_port FROM flyne_vps.apps WHERE domain_id=${DID} AND app_type='nodejs' AND status='active' LIMIT 1" 2>/dev/null)

# Remove old config
sudo rm -f "/etc/nginx/sites-vhost/${DOMAIN}.conf" "/etc/nginx/sites-vhost/${DOMAIN}_*.conf"
sudo rm -f "/etc/apache2/sites-vhost/${DOMAIN}.conf" "/etc/apache2/sites-vhost/${DOMAIN}_*.conf"

# Generate new config
case "$NEW_WS" in
nginx)
    if [[ -n "$NODE_PORT" ]]; then
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
            -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" -e "s|{{NODE_PORT}}|${NODE_PORT}|g" \
            "${FLYNE_DIR}/templates/nginx-nodejs.conf.tpl" > "/etc/nginx/sites-vhost/${DOMAIN}.conf"
    else
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
            -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
            "${FLYNE_DIR}/templates/nginx-domain.conf.tpl" > "/etc/nginx/sites-vhost/${DOMAIN}.conf"
    fi
    sudo systemctl stop apache2 2>/dev/null; sudo systemctl stop lsws 2>/dev/null
    sudo nginx -t && sudo systemctl start nginx && sudo systemctl reload nginx
    ;;
apache)
    if [[ -n "$NODE_PORT" ]]; then
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" \
            -e "s|{{NODE_PORT}}|${NODE_PORT}|g" \
            "${FLYNE_DIR}/templates/apache-nodejs.conf.tpl" > "/etc/apache2/sites-vhost/${DOMAIN}.conf"
    else
        sed -e "s|{{DOMAIN}}|${DOMAIN}|g" -e "s|{{DOCUMENT_ROOT}}|${DOC_ROOT}|g" \
            -e "s|{{LOGS_DIR}}|${LOGS_DIR}|g" -e "s|{{PHP_SOCKET}}|${SOCKET}|g" \
            "${FLYNE_DIR}/templates/apache-domain.conf.tpl" > "/etc/apache2/sites-vhost/${DOMAIN}.conf"
    fi
    sudo systemctl stop nginx 2>/dev/null; sudo systemctl stop lsws 2>/dev/null
    sudo apachectl configtest && sudo systemctl start apache2 && sudo systemctl reload apache2
    ;;
openlitespeed)
    # OLS uses its own config structure
    OLS_VHOST="/usr/local/lsws/conf/vhosts/${DOMAIN}"
    sudo mkdir -p "$OLS_VHOST"
    cat > "/tmp/ols-${DOMAIN}.conf" << OLSCFG
docRoot \$VH_ROOT/public_html
vhDomain ${DOMAIN},www.${DOMAIN}
enableGzip 1
context / {
    location \$VH_ROOT/public_html/
    allowBrowse 1
    rewrite {
        RewriteRule ^(.*)$ /index.php?\$1 [QSA,L]
    }
}
OLSCFG
    sudo mv "/tmp/ols-${DOMAIN}.conf" "${OLS_VHOST}/vhconf.conf"
    
    # Add vhost to OLS httpd_config
    if ! grep -q "virtualhost ${DOMAIN}" /usr/local/lsws/conf/httpd_config.conf 2>/dev/null; then
        cat >> /usr/local/lsws/conf/httpd_config.conf << OLSVH

virtualhost ${DOMAIN} {
    vhRoot ${SITES_DIR}/${DOMAIN}
    configFile \$VH_ROOT/../../usr/local/lsws/conf/vhosts/${DOMAIN}/vhconf.conf
    allowSymbolLink 1
    enableScript 1
}

listener Default {
    map ${DOMAIN} ${DOMAIN}
}
OLSVH
    fi
    
    sudo systemctl stop nginx 2>/dev/null; sudo systemctl stop apache2 2>/dev/null
    sudo systemctl start lsws 2>/dev/null || warn "OLS start failed"
    ;;
esac

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
    "UPDATE flyne_vps.domains SET webserver='${NEW_WS}' WHERE id=${DID}"
echo "$NEW_WS" > "${FLYNE_DIR}/run/${DOMAIN}.ws"

echo "[$(date)] Webserver switched for ${DOMAIN}: ${OLD_WS} -> ${NEW_WS}" >> "$LOG"
echo "{\"success\":true,\"old\":\"${OLD_WS}\",\"new\":\"${NEW_WS}\"}"
WSSWITCH
chmod +x "${FLYNE_DIR}/scripts/webserver-switch.sh"

# ==================== PHP SWITCH ====================
cat > "${FLYNE_DIR}/scripts/php-switch.sh" << 'PHPSWITCH'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
NEW_VER="$2"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

ALLOWED="7.4 8.0 8.1 8.2 8.3 8.4"
[[ ! " $ALLOWED " =~ " $NEW_VER " ]] && { echo '{"success":false,"error":"Invalid PHP version"}'; exit 1; }

SITE_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT site_user, php_version FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$SITE_INFO" ]] && { echo '{"success":false,"error":"Domain not found"}'; exit 1; }
read SITE_USER OLD_VER <<< "$SITE_INFO"
[[ "$OLD_VER" == "$NEW_VER" ]] && { echo '{"success":true,"message":"Already on this version"}'; exit 0; }

SITE_DIR="${SITES_DIR}/${DOMAIN}"
LOGS_DIR="${SITE_DIR}/logs"
DOMAIN_HASH=$(echo -n "$DOMAIN" | sha1sum | cut -c1-12)
SOCKET="/run/php/vhost-${DOMAIN_HASH}.sock"

# Read existing pool or recreate
POOL_CONF="/etc/php/${OLD_VER}/fpm/pool.d/${DOMAIN}.conf"
if [[ -f "$POOL_CONF" ]]; then
    sudo cp "$POOL_CONF" "/etc/php/${NEW_VER}/fpm/pool.d/${DOMAIN}.conf"
    sudo rm -f "$POOL_CONF"
else
    # Recreate minimal pool
    cat > "/etc/php/${NEW_VER}/fpm/pool.d/${DOMAIN}.conf" << POOLEOF
[${DOMAIN}]
user = ${SITE_USER}
group = www-data
listen = ${SOCKET}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
pm.max_requests = 1000
php_admin_value[open_basedir] = ${SITE_DIR}:/tmp:/usr/share/php:/dev/urandom
php_admin_value[error_log] = ${LOGS_DIR}/php-error.log
php_admin_flag[log_errors] = on
POOLEOF
fi

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
    "UPDATE flyne_vps.domains SET php_version='${NEW_VER}' WHERE domain='${DOMAIN}'"
echo "$NEW_VER" > "${FLYNE_DIR}/run/${DOMAIN}.php"

sudo systemctl reload "php${NEW_VER}-fpm"
sudo systemctl reload "php${OLD_VER}-fpm" 2>/dev/null || true

echo "{\"success\":true,\"old\":\"${OLD_VER}\",\"new\":\"${NEW_VER}\"}"
PHPSWITCH
chmod +x "${FLYNE_DIR}/scripts/php-switch.sh"

# ==================== DNS ZONE CREATE ====================
cat > "${FLYNE_DIR}/scripts/dns-create-zone.sh" << 'DNSZONE'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

DOMAIN_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$DOMAIN_ID" ]] && { echo '{"success":false,"error":"Domain not found"}'; exit 1; }

SERIAL=$(date +%Y%m%d01)

sed -e "s|{{DOMAIN}}|${DOMAIN}|g" \
    -e "s|{{NS1}}|${NS1}|g" \
    -e "s|{{NS2}}|${NS2}|g" \
    -e "s|{{SERVER_IP}}|${SERVER_IP}|g" \
    -e "s|{{SERIAL}}|${SERIAL}|g" \
    "${FLYNE_DIR}/templates/zone.tpl" > "${DNS_DIR}/${DOMAIN}.zone"

chown bind:bind "${DNS_DIR}/${DOMAIN}.zone"

# Add to zones.conf if not present
if ! grep -q "zone \"${DOMAIN}\"" "${DNS_DIR}/zones.conf"; then
    cat >> "${DNS_DIR}/zones.conf" << ZONEENTRY
zone "${DOMAIN}" {
    type master;
    file "${DNS_DIR}/${DOMAIN}.zone";
    allow-query { any; };
};
ZONEENTRY
fi

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT IGNORE INTO dns_zones (domain_id, domain, serial) VALUES (${DOMAIN_ID}, '${DOMAIN}', ${SERIAL});
INSERT INTO dns_records (zone_id, name, type, content) VALUES (LAST_INSERT_ID(), '@', 'A', '${SERVER_IP}');
INSERT INTO dns_records (zone_id, name, type, content) VALUES (LAST_INSERT_ID(), 'www', 'A', '${SERVER_IP}');
INSERT INTO dns_records (zone_id, name, type, content) VALUES (LAST_INSERT_ID(), '@', 'NS', '${NS1}.');
INSERT INTO dns_records (zone_id, name, type, content) VALUES (LAST_INSERT_ID(), '@', 'NS', '${NS2}.');
INSERT INTO dns_records (zone_id, name, type, content) VALUES (LAST_INSERT_ID(), 'mail', 'A', '${SERVER_IP}');
INSERT INTO dns_records (zone_id, name, type, content, priority) VALUES (LAST_INSERT_ID(), '@', 'MX', 'mail.${DOMAIN}.', 10);
SQLEOF

sudo rndc reload 2>/dev/null || sudo systemctl reload bind9 2>/dev/null
echo '{"success":true,"message":"DNS zone created"}'
DNSZONE
chmod +x "${FLYNE_DIR}/scripts/dns-create-zone.sh"

# ==================== DNS REBUILD ZONE ====================
cat > "${FLYNE_DIR}/scripts/dns-rebuild-zone.sh" << 'DNSREBUILD'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

ZONE_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.dns_zones WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$ZONE_ID" ]] && { echo '{"success":false,"error":"Zone not found"}'; exit 1; }

SERIAL=$(date +%Y%m%d%H)
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
    "UPDATE flyne_vps.dns_zones SET serial=${SERIAL} WHERE id=${ZONE_ID}"

# Write zone header
cat > "${DNS_DIR}/${DOMAIN}.zone" << ZHEAD
\$TTL 3600
@   IN  SOA ${NS1}. admin.${DOMAIN}. (
        ${SERIAL}   ; serial
        3600        ; refresh
        900         ; retry
        1209600     ; expire
        86400       ; minimum
    )

ZHEAD

# Append records from DB
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT name, type, content, ttl, IFNULL(priority,'') FROM flyne_vps.dns_records WHERE zone_id=${ZONE_ID}" 2>/dev/null | \
while IFS=$'\t' read NAME TYPE CONTENT TTL PRIO; do
    if [[ "$TYPE" == "MX" || "$TYPE" == "SRV" ]]; then
        echo "${NAME} ${TTL} IN ${TYPE} ${PRIO} ${CONTENT}" >> "${DNS_DIR}/${DOMAIN}.zone"
    elif [[ "$TYPE" == "TXT" ]]; then
        echo "${NAME} ${TTL} IN TXT \"${CONTENT}\"" >> "${DNS_DIR}/${DOMAIN}.zone"
    else
        echo "${NAME} ${TTL} IN ${TYPE} ${CONTENT}" >> "${DNS_DIR}/${DOMAIN}.zone"
    fi
done

chown bind:bind "${DNS_DIR}/${DOMAIN}.zone"
sudo rndc reload 2>/dev/null || sudo systemctl reload bind9 2>/dev/null
echo '{"success":true,"message":"Zone rebuilt","serial":'"$SERIAL"'}'
DNSREBUILD
chmod +x "${FLYNE_DIR}/scripts/dns-rebuild-zone.sh"

# ==================== MAIL DOMAIN SETUP ====================
cat > "${FLYNE_DIR}/scripts/mail-setup-domain.sh" << 'MAILSETUP'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

DOMAIN_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$DOMAIN_ID" ]] && { echo '{"success":false,"error":"Domain not found"}'; exit 1; }

# Create mail directory
sudo mkdir -p "${MAIL_DIR}/${DOMAIN}"
sudo chown vmail:vmail "${MAIL_DIR}/${DOMAIN}"
sudo chmod 770 "${MAIL_DIR}/${DOMAIN}"

# Generate DKIM keys
sudo mkdir -p "/etc/opendkim/keys/${DOMAIN}"
sudo opendkim-genkey -D "/etc/opendkim/keys/${DOMAIN}" -d "$DOMAIN" -s default 2>/dev/null
sudo chown -R opendkim:opendkim "/etc/opendkim/keys/${DOMAIN}"

# Add to DKIM tables
echo "default._domainkey.${DOMAIN} ${DOMAIN}:default:/etc/opendkim/keys/${DOMAIN}/default.private" >> /etc/opendkim/key.table
echo "*@${DOMAIN} default._domainkey.${DOMAIN}" >> /etc/opendkim/signing.table
grep -q "$DOMAIN" /etc/opendkim/trusted.hosts || echo "*.${DOMAIN}" >> /etc/opendkim/trusted.hosts

# Read DKIM public key
DKIM_RECORD=""
if [[ -f "/etc/opendkim/keys/${DOMAIN}/default.txt" ]]; then
    DKIM_RECORD=$(cat "/etc/opendkim/keys/${DOMAIN}/default.txt" | tr -d '\n\t ' | sed 's/.*"p=\([^"]*\)".*/v=DKIM1; k=rsa; p=\1/')
fi

SPF="v=spf1 a mx ip4:${SERVER_IP} ~all"

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT IGNORE INTO mail_domains (domain_id, domain, dkim_enabled, spf_record)
VALUES (${DOMAIN_ID}, '${DOMAIN}', 1, '${SPF}');
SQLEOF

# Add DNS records for mail
ZONE_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id FROM flyne_vps.dns_zones WHERE domain='${DOMAIN}'" 2>/dev/null)
if [[ -n "$ZONE_ID" ]]; then
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_vps << SQLEOF
INSERT IGNORE INTO dns_records (zone_id, name, type, content, priority) VALUES (${ZONE_ID}, '@', 'MX', 'mail.${DOMAIN}.', 10);
INSERT IGNORE INTO dns_records (zone_id, name, type, content) VALUES (${ZONE_ID}, '@', 'TXT', '${SPF}');
INSERT IGNORE INTO dns_records (zone_id, name, type, content) VALUES (${ZONE_ID}, 'default._domainkey', 'TXT', '${DKIM_RECORD}');
INSERT IGNORE INTO dns_records (zone_id, name, type, content) VALUES (${ZONE_ID}, '_dmarc', 'TXT', 'v=DMARC1; p=quarantine; rua=mailto:postmaster@${DOMAIN}');
SQLEOF
    sudo bash "${FLYNE_DIR}/scripts/dns-rebuild-zone.sh" "$DOMAIN" > /dev/null 2>&1
fi

sudo systemctl reload opendkim 2>/dev/null || true
sudo systemctl reload postfix 2>/dev/null || true

echo "{\"success\":true,\"message\":\"Mail domain configured\",\"dkim\":\"${DKIM_RECORD}\",\"spf\":\"${SPF}\"}"
MAILSETUP
chmod +x "${FLYNE_DIR}/scripts/mail-setup-domain.sh"

# ==================== CRON SYNC ====================
cat > "${FLYNE_DIR}/scripts/cron-sync.sh" << 'CRONSYNC'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

DOMAIN_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$DOMAIN_INFO" ]] && { echo '{"success":false,"error":"Domain not found"}'; exit 1; }
read DID SITE_USER <<< "$DOMAIN_INFO"

# Build crontab from DB
CRONTAB=""
while IFS=$'\t' read MIN HOUR DAY MON WD CMD; do
    CRONTAB+="${MIN} ${HOUR} ${DAY} ${MON} ${WD} ${CMD}"$'\n'
done < <(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT minute, hour, day, month, weekday, command FROM flyne_vps.cron_jobs WHERE domain_id=${DID} AND is_active=1" 2>/dev/null)

echo "$CRONTAB" | sudo crontab -u "$SITE_USER" -

echo '{"success":true,"message":"Cron jobs synced"}'
CRONSYNC
chmod +x "${FLYNE_DIR}/scripts/cron-sync.sh"

# ==================== BACKUP SCRIPT ====================
cat > "${FLYNE_DIR}/scripts/backup-site.sh" << 'BACKUPSITE'
#!/bin/bash
set -uo pipefail
DOMAIN="$1"
TYPE="${2:-full}"
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf

DOMAIN_INFO=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT id, site_user FROM flyne_vps.domains WHERE domain='${DOMAIN}'" 2>/dev/null)
[[ -z "$DOMAIN_INFO" ]] && { echo '{"success":false,"error":"Domain not found"}'; exit 1; }
read DID SITE_USER <<< "$DOMAIN_INFO"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${FLYNE_DIR}/backups/${DOMAIN}"
mkdir -p "$BACKUP_DIR"

BACKUP_ID=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "INSERT INTO flyne_vps.backups (domain_id, type, status) VALUES (${DID}, '${TYPE}', 'running'); SELECT LAST_INSERT_ID();")

BACKUP_FILE="${BACKUP_DIR}/${DOMAIN}_${TYPE}_${TIMESTAMP}.tar.gz"

case "$TYPE" in
    full|files)
        tar czf "$BACKUP_FILE" -C "${SITES_DIR}" "${DOMAIN}" 2>/dev/null
        ;;
    database)
        # Dump all databases for this domain's apps
        DBS=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
            "SELECT db_name FROM flyne_vps.apps WHERE domain_id=${DID} AND db_name IS NOT NULL" 2>/dev/null)
        for DB in $DBS; do
            mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASS" "$DB" 2>/dev/null >> "/tmp/dbdump_${DOMAIN}.sql"
        done
        SDBNAMES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
            "SELECT db_name FROM flyne_vps.user_databases WHERE domain_id=${DID}" 2>/dev/null)
        for DB2 in $SDBNAMES; do
            mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASS" "$DB2" 2>/dev/null >> "/tmp/dbdump_${DOMAIN}.sql"
        done
        if [[ -f "/tmp/dbdump_${DOMAIN}.sql" ]]; then
            gzip -c "/tmp/dbdump_${DOMAIN}.sql" > "$BACKUP_FILE"
            rm -f "/tmp/dbdump_${DOMAIN}.sql"
        fi
        ;;
esac

if [[ -f "$BACKUP_FILE" ]]; then
    SIZE=$(stat -c%s "$BACKUP_FILE")
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
        "UPDATE flyne_vps.backups SET status='completed', file_path='${BACKUP_FILE}', file_size=${SIZE} WHERE id=${BACKUP_ID}"
    echo "{\"success\":true,\"backup_id\":${BACKUP_ID},\"file\":\"${BACKUP_FILE}\",\"size\":${SIZE}}"
else
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
        "UPDATE flyne_vps.backups SET status='failed' WHERE id=${BACKUP_ID}"
    echo '{"success":false,"error":"Backup failed"}'
fi
BACKUPSITE
chmod +x "${FLYNE_DIR}/scripts/backup-site.sh"

# Set ownership for all scripts
chown -R flyne-agent:flyne-agent "${FLYNE_DIR}/scripts"

#===============================================================================
# 17. SUDOERS
#===============================================================================
log "Configuring sudo permissions..."
cat > /etc/sudoers.d/flyne-vps << 'SUDOERS'
# Flyne VPS Control Panel Sudoers
flyne-agent ALL=(ALL) NOPASSWD: ALL
www-data ALL=(flyne-agent) NOPASSWD: /bin/bash /opt/flyne-vps/scripts/*.sh *
SUDOERS
chmod 440 /etc/sudoers.d/flyne-vps
visudo -cf /etc/sudoers.d/flyne-vps || error "Sudoers syntax error"

#===============================================================================
# 18. FIREWALL
#===============================================================================
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 21/tcp
ufw allow 25/tcp
ufw allow 587/tcp
ufw allow 993/tcp
ufw allow 995/tcp
ufw allow 110/tcp
ufw allow 143/tcp
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 49152:65534/tcp  # FTP passive
ufw --force enable

#===============================================================================
# 19. FAIL2BAN
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

[postfix]
enabled = true

[dovecot]
enabled = true

[proftpd]
enabled = true

[nginx-http-auth]
enabled = true
F2BJAIL
systemctl enable fail2ban
systemctl restart fail2ban || warn "Fail2ban restart failed"

#===============================================================================
# 20. KERNEL TUNING
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
LIMITS

#===============================================================================
# 21. LOGROTATE
#===============================================================================
cat > /etc/logrotate.d/flyne-vps << 'LOGROTATE'
/var/log/flyne/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 664 flyne-agent www-data
}
/var/www/vhosts/*/logs/*.log {
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
# 22. CRON JOBS
#===============================================================================
cat > /etc/cron.d/flyne-vps << 'CRONFILE'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root find /var/cache/nginx/fastcgi -type f -mtime +7 -delete 2>/dev/null
0 4 * * 0 root find /opt/flyne-vps/backups -type f -mtime +30 -delete 2>/dev/null
0 */12 * * * root certbot renew --quiet --post-hook "systemctl reload nginx; systemctl reload apache2 2>/dev/null; true"
*/5 * * * * root /opt/flyne-vps/scripts/sftp-expire-check.sh 2>/dev/null || true
CRONFILE
chmod 644 /etc/cron.d/flyne-vps

# SFTP expire check
cat > "${FLYNE_DIR}/scripts/sftp-expire-check.sh" << 'SFTPEXPIRE'
#!/bin/bash
FLYNE_DIR="/opt/flyne-vps"
source ${FLYNE_DIR}/flyne-vps.conf
EXPIRED=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e \
    "SELECT username FROM flyne_vps.ftp_accounts WHERE is_active=1 AND quota_mb=-1 AND created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)" 2>/dev/null)
# placeholder for expire logic
SFTPEXPIRE
chmod +x "${FLYNE_DIR}/scripts/sftp-expire-check.sh"

#===============================================================================
# 23. CLI TOOL
#===============================================================================
log "Installing CLI tool..."
cat > /usr/local/bin/flyne-vps << 'CLIEOF'
#!/bin/bash
source /opt/flyne-vps/flyne-vps.conf 2>/dev/null || { echo "Flyne VPS not configured"; exit 1; }

case "${1:-}" in
    status)
        echo "=== Flyne VPS Control Panel v1.0 ==="
        for svc in nginx apache2 lsws mariadb redis-server bind9 postfix dovecot proftpd; do
            systemctl is-active --quiet $svc 2>/dev/null && echo "  $svc: ✓ Running" || echo "  $svc: ✗ Stopped"
        done
        for v in 7.4 8.0 8.1 8.2 8.3 8.4; do
            systemctl is-active --quiet php${v}-fpm 2>/dev/null && echo "  PHP ${v}-FPM: ✓ Running"
        done
        echo ""
        SITES=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_vps.domains WHERE status='active'" 2>/dev/null || echo 0)
        APPS=$(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_vps.apps WHERE status='active'" 2>/dev/null || echo 0)
        echo "Active Domains: $SITES | Installed Apps: $APPS"
        echo "Panel API: https://${PANEL_DOMAIN}"
        ;;
    domains)
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e \
            "SELECT d.domain, d.webserver, d.php_version, d.ssl_enabled, d.status, IFNULL(GROUP_CONCAT(a.app_type),'none') as apps FROM flyne_vps.domains d LEFT JOIN flyne_vps.apps a ON d.id=a.domain_id GROUP BY d.id ORDER BY d.created_at DESC" 2>/dev/null
        ;;
    create)
        [[ -z "${2:-}" ]] && { echo "Usage: flyne-vps create domain.com [account] [php] [webserver]"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/domain-create.sh "$2" "${3:-admin}" "${4:-8.4}" "${5:-nginx}"
        ;;
    delete)
        [[ -z "${2:-}" ]] && { echo "Usage: flyne-vps delete domain.com"; exit 1; }
        read -p "Delete $2 and ALL data? [y/N] " confirm
        [[ "$confirm" != "y" ]] && exit 0
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/domain-delete.sh "$2"
        ;;
    install-app)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { echo "Usage: flyne-vps install-app domain.com wordpress|nodejs|laravel|static"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/app-install.sh "$2" "$3" "${@:4}"
        ;;
    switch-ws)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { echo "Usage: flyne-vps switch-ws domain.com nginx|apache|openlitespeed"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/webserver-switch.sh "$2" "$3"
        ;;
    switch-php)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { echo "Usage: flyne-vps switch-php domain.com 8.4"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/php-switch.sh "$2" "$3"
        ;;
    backup)
        [[ -z "${2:-}" ]] && { echo "Usage: flyne-vps backup domain.com [full|files|database]"; exit 1; }
        sudo -u flyne-agent /bin/bash /opt/flyne-vps/scripts/backup-site.sh "$2" "${3:-full}"
        ;;
    test)
        echo "Testing API..."
        curl -sk "https://${PANEL_DOMAIN}/index.php?action=system_status" -H "Authorization: Bearer ${API_SECRET}" | jq . 2>/dev/null || echo "API test failed"
        ;;
    logs)
        [[ -z "${2:-}" ]] && tail -f /var/log/flyne/*.log || tail -f /var/www/vhosts/$2/logs/*.log
        ;;
    *)
        echo "Flyne VPS Control Panel CLI v1.0"
        echo ""
        echo "Commands:"
        echo "  status                          System status"
        echo "  domains                         List all domains"
        echo "  create <domain>                 Create domain (empty, no app)"
        echo "  delete <domain>                 Delete domain + all data"
        echo "  install-app <domain> <type>     Install app (wordpress|nodejs|laravel|static)"
        echo "  switch-ws <domain> <ws>         Switch webserver (nginx|apache|openlitespeed)"
        echo "  switch-php <domain> <ver>       Switch PHP version"
        echo "  backup <domain> [type]          Create backup"
        echo "  test                            Test API"
        echo "  logs [domain]                   View logs"
        ;;
esac
CLIEOF
chmod +x /usr/local/bin/flyne-vps

#===============================================================================
# 24. SAVE CREDENTIALS
#===============================================================================
log "Saving credentials..."
cat > "${FLYNE_DIR}/credentials.txt" << CREDEOF
=== FLYNE VPS CONTROL PANEL v1.0 ===
Generated: $(date)

Panel API:     https://${PANEL_DOMAIN}
phpMyAdmin:    https://${PMA_DOMAIN}
Server IP:     ${SERVER_IP}
Hostname:      ${SERVER_HOSTNAME}

API Secret:    ${API_SECRET}
MySQL User:    flyne_admin
MySQL Pass:    ${MYSQL_ROOT_PASS}
Redis Pass:    ${REDIS_PASS}
Admin Email:   ${ADMIN_EMAIL}
Nameservers:   ${NS1}, ${NS2}

CLI: flyne-vps --help

DELETE THIS FILE AFTER SAVING CREDENTIALS SECURELY!
CREDEOF
chmod 600 "${FLYNE_DIR}/credentials.txt"
chown flyne-agent:flyne-agent "${FLYNE_DIR}/credentials.txt"

#===============================================================================
# 25. VERIFICATION
#===============================================================================
log "Verifying installation..."
nginx -t || error "Nginx config invalid"
systemctl is-active --quiet mariadb || error "MariaDB not running"
systemctl is-active --quiet redis-server || error "Redis not running"
systemctl is-active --quiet php8.4-fpm || error "PHP 8.4 FPM not running"
mysql -u flyne_admin -p"${MYSQL_ROOT_PASS}" -e "SELECT 1" >/dev/null 2>&1 || error "MySQL connection failed"
redis-cli -s /run/redis/redis-server.sock -a "${REDIS_PASS}" PING >/dev/null 2>&1 || error "Redis failed"

log "All services verified!"

echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   FLYNE VPS CONTROL PANEL v1.0 INSTALLED!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "  Panel API:     ${CYAN}https://${PANEL_DOMAIN}${NC}"
echo -e "  phpMyAdmin:    ${CYAN}https://${PMA_DOMAIN}${NC}"
echo -e "  Server IP:     ${CYAN}${SERVER_IP}${NC}"
echo ""
echo -e "${YELLOW}  API Secret:    ${API_SECRET}${NC}"
echo -e "${YELLOW}  MySQL Pass:    ${MYSQL_ROOT_PASS}${NC}"
echo -e "${YELLOW}  Redis Pass:    ${REDIS_PASS}${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo "  flyne-vps status"
echo "  flyne-vps create example.com"
echo "  flyne-vps install-app example.com wordpress"
echo "  flyne-vps install-app example.com nodejs node_version=20 port=3000"
echo "  flyne-vps switch-ws example.com apache"
echo ""
log "Installation complete!"