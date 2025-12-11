<?php
/**
 * FLYNE ENGINE - WordPress Hosting API
 * Single-file API handling all site operations
 * Place in: /opt/flyne/api/index.php
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/flyne/api.log');

// Config from environment (set by Nginx)
define('API_SECRET', $_SERVER['FLYNE_API_SECRET'] ?? '');
define('MYSQL_PASS', $_SERVER['FLYNE_MYSQL_PASS'] ?? '');
define('REDIS_PASS', $_SERVER['FLYNE_REDIS_PASS'] ?? '');
define('SITES_DIR', '/var/www/sites');
define('FLYNE_DIR', '/opt/flyne');
define('BACKUPS_DIR', '/opt/flyne/backups');

header('Content-Type: application/json');
header('X-Powered-By: Flyne Engine');

// ============================================================================
// DATABASE CONNECTION
// ============================================================================
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('mysql:host=localhost;dbname=flyne_engine;charset=utf8mb4', 'root', MYSQL_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
    }
    return $pdo;
}

// ============================================================================
// AUTHENTICATION
// ============================================================================
function authenticate(): bool {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_POST['api_key'] ?? $_GET['api_key'] ?? '';
    
    // Check bearer token
    if (preg_match('/Bearer\s+(.+)$/i', $authHeader, $m)) {
        if (hash_equals(API_SECRET, $m[1])) return true;
    }
    
    // Check API key
    if (!empty($apiKey) && hash_equals(API_SECRET, $apiKey)) return true;
    
    // Check stored API keys
    if (!empty($apiKey)) {
        $stmt = db()->prepare("SELECT id FROM api_keys WHERE key_hash = ?");
        $stmt->execute([hash('sha256', $apiKey)]);
        if ($stmt->fetch()) {
            db()->prepare("UPDATE api_keys SET last_used = NOW() WHERE key_hash = ?")->execute([hash('sha256', $apiKey)]);
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// RESPONSE HELPERS
// ============================================================================
function success($data = [], string $message = 'OK'): never {
    echo json_encode(['success' => true, 'message' => $message, 'data' => $data]);
    exit;
}

function error(string $message, int $code = 400): never {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $message]);
    exit;
}

function logAction(int $siteId, string $action, string $details = ''): void {
    db()->prepare("INSERT INTO activity_log (site_id, action, details, ip_address) VALUES (?, ?, ?, ?)")
        ->execute([$siteId ?: null, $action, $details, $_SERVER['REMOTE_ADDR'] ?? '']);
}

// ============================================================================
// SHELL EXECUTION
// ============================================================================
function shell(string $cmd, bool $sudo = true): array {
    $fullCmd = $sudo ? "sudo $cmd 2>&1" : "$cmd 2>&1";
    exec($fullCmd, $output, $code);
    return ['output' => implode("\n", $output), 'code' => $code, 'success' => $code === 0];
}

function wpcli(string $domain, string $cmd): array {
    $siteDir = SITES_DIR . "/$domain/public";
    if (!is_dir($siteDir)) return ['success' => false, 'output' => 'Site not found'];
    return shell("sudo -u site_" . preg_replace('/[^a-z0-9]/', '_', $domain) . " wp $cmd --path='$siteDir'", false);
}

// ============================================================================
// SITE MANAGEMENT
// ============================================================================
function getSite(string $domain): ?array {
    $stmt = db()->prepare("SELECT * FROM sites WHERE domain = ?");
    $stmt->execute([$domain]);
    return $stmt->fetch() ?: null;
}

function createSite(string $domain, string $phpVersion = '8.4'): array {
    if (getSite($domain)) error('Site already exists');
    if (!preg_match('/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i', $domain)) error('Invalid domain');
    
    $safeUser = 'site_' . preg_replace('/[^a-z0-9]/', '_', strtolower($domain));
    $safeUser = substr($safeUser, 0, 32);
    $dbName = 'wp_' . preg_replace('/[^a-z0-9]/', '_', strtolower($domain));
    $dbName = substr($dbName, 0, 64);
    $dbUser = substr($dbName, 0, 32);
    $dbPass = bin2hex(random_bytes(16));
    $redisDb = db()->query("SELECT COALESCE(MAX(redis_db), 0) + 1 FROM sites")->fetchColumn();
    
    db()->beginTransaction();
    try {
        // Insert site record
        $stmt = db()->prepare("INSERT INTO sites (domain, user_name, db_name, db_user, db_pass, php_version, redis_db, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'creating')");
        $stmt->execute([$domain, $safeUser, $dbName, $dbUser, $dbPass, $phpVersion, $redisDb]);
        $siteId = (int)db()->lastInsertId();
        
        // Create Linux user
        shell("useradd -m -d " . SITES_DIR . "/$domain -s /bin/bash $safeUser");
        shell("mkdir -p " . SITES_DIR . "/$domain/{public,logs,tmp}");
        shell("chown -R $safeUser:$safeUser " . SITES_DIR . "/$domain");
        shell("chmod 750 " . SITES_DIR . "/$domain");
        
        // Create database
        $pdo = new PDO('mysql:host=localhost', 'root', MYSQL_PASS);
        $pdo->exec("CREATE DATABASE `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("CREATE USER '$dbUser'@'localhost' IDENTIFIED BY '$dbPass'");
        $pdo->exec("GRANT ALL PRIVILEGES ON `$dbName`.* TO '$dbUser'@'localhost'");
        $pdo->exec("FLUSH PRIVILEGES");
        
        // Create PHP-FPM pool
        createPhpPool($domain, $safeUser, $phpVersion);
        
        // Create Nginx config
        createNginxConfig($domain, $phpVersion);
        
        // Reload services
        shell("systemctl reload php{$phpVersion}-fpm");
        shell("nginx -t && systemctl reload nginx");
        
        db()->prepare("UPDATE sites SET status = 'active' WHERE id = ?")->execute([$siteId]);
        db()->commit();
        
        logAction($siteId, 'site_created', $domain);
        return ['site_id' => $siteId, 'domain' => $domain, 'db_name' => $dbName, 'db_user' => $dbUser, 'db_pass' => $dbPass];
        
    } catch (Exception $e) {
        db()->rollBack();
        // Cleanup on failure
        shell("userdel -r $safeUser 2>/dev/null");
        shell("rm -rf " . SITES_DIR . "/$domain");
        throw $e;
    }
}

function createPhpPool(string $domain, string $user, string $phpVersion): void {
    $poolConfig = <<<POOL
[$domain]
user = $user
group = $user
listen = /run/php/php-$domain.sock
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
php_admin_value[open_basedir] = /var/www/sites/$domain:/tmp:/usr/share/php
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 300
php_admin_value[error_log] = /var/www/sites/$domain/logs/php-error.log
php_admin_flag[log_errors] = on
POOL;
    file_put_contents("/etc/php/$phpVersion/fpm/pool.d/$domain.conf", $poolConfig);
}

function createNginxConfig(string $domain, string $phpVersion): void {
    $nginxConfig = <<<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $domain www.$domain;
    root /var/www/sites/$domain/public;
    index index.php index.html;

    access_log /var/www/sites/$domain/logs/access.log;
    error_log /var/www/sites/$domain/logs/error.log;

    # Security
    location ~ /\\.ht { deny all; }
    location ~ /wp-config.php { deny all; }
    location ~* /(?:uploads|files)/.*\\.php$ { deny all; }

    # Static files caching
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files \$uri =404;
    }

    # FastCGI cache settings
    set \$skip_cache 0;
    if (\$request_method = POST) { set \$skip_cache 1; }
    if (\$query_string != "") { set \$skip_cache 1; }
    if (\$request_uri ~* "/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|index.php|sitemap") { set \$skip_cache 1; }
    if (\$http_cookie ~* "wordpress_logged_in|wp-postpass|woocommerce_") { set \$skip_cache 1; }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \\.php$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php-$domain.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        
        # Cache
        fastcgi_cache WORDPRESS;
        fastcgi_cache_valid 200 60m;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        add_header X-FastCGI-Cache \$upstream_cache_status;
    }
}
NGINX;
    file_put_contents("/etc/nginx/sites-flyne/$domain.conf", $nginxConfig);
}

function deleteSite(string $domain): bool {
    $site = getSite($domain);
    if (!$site) error('Site not found');
    
    db()->prepare("UPDATE sites SET status = 'deleting' WHERE domain = ?")->execute([$domain]);
    
    // Remove Nginx config
    @unlink("/etc/nginx/sites-flyne/$domain.conf");
    shell("nginx -t && systemctl reload nginx");
    
    // Remove PHP-FPM pool
    $phpVersion = $site['php_version'];
    @unlink("/etc/php/$phpVersion/fpm/pool.d/$domain.conf");
    shell("systemctl reload php{$phpVersion}-fpm");
    
    // Remove database
    $pdo = new PDO('mysql:host=localhost', 'root', MYSQL_PASS);
    $pdo->exec("DROP DATABASE IF EXISTS `{$site['db_name']}`");
    $pdo->exec("DROP USER IF EXISTS '{$site['db_user']}'@'localhost'");
    
    // Remove files and user
    shell("userdel -r {$site['user_name']} 2>/dev/null");
    shell("rm -rf " . SITES_DIR . "/$domain");
    
    // Delete from DB
    db()->prepare("DELETE FROM sites WHERE domain = ?")->execute([$domain]);
    logAction($site['id'], 'site_deleted', $domain);
    
    return true;
}

// ============================================================================
// WORDPRESS OPERATIONS
// ============================================================================
function installWordPress(string $domain, array $opts): array {
    $site = getSite($domain);
    if (!$site) error('Site not found');
    
    $siteDir = SITES_DIR . "/$domain/public";
    $user = $site['user_name'];
    
    // Download WordPress
    shell("sudo -u $user wp core download --path='$siteDir'", false);
    
    // Generate wp-config
    $authKeys = file_get_contents('https://api.wordpress.org/secret-key/1.1/salt/');
    $wpConfig = generateWpConfig($site, $authKeys);
    file_put_contents("$siteDir/wp-config.php", $wpConfig);
    shell("chown $user:$user $siteDir/wp-config.php");
    
    // Install WordPress
    $title = escapeshellarg($opts['title'] ?? $domain);
    $admin = escapeshellarg($opts['admin_user'] ?? 'admin');
    $email = escapeshellarg($opts['admin_email'] ?? 'admin@' . $domain);
    $pass = $opts['admin_pass'] ?? bin2hex(random_bytes(8));
    
    $result = shell("sudo -u $user wp core install --path='$siteDir' --url='https://$domain' --title=$title --admin_user=$admin --admin_email=$email --admin_password='$pass' --skip-email", false);
    
    if (!$result['success']) error('WordPress install failed: ' . $result['output']);
    
    // Install Redis cache plugin
    shell("sudo -u $user wp plugin install redis-cache --activate --path='$siteDir'", false);
    shell("sudo -u $user wp redis enable --path='$siteDir'", false);
    
    logAction($site['id'], 'wordpress_installed', $domain);
    
    return ['url' => "https://$domain", 'admin_url' => "https://$domain/wp-admin/", 'admin_user' => $opts['admin_user'] ?? 'admin', 'admin_pass' => $pass];
}

function generateWpConfig(array $site, string $authKeys): string {
    return <<<WPCONFIG
<?php
define('DB_NAME', '{$site['db_name']}');
define('DB_USER', '{$site['db_user']}');
define('DB_PASSWORD', '{$site['db_pass']}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

$authKeys

\$table_prefix = 'wp_';

define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_REDIS_PASSWORD', '" . REDIS_PASS . "');
define('WP_REDIS_DATABASE', {$site['redis_db']});

define('DISALLOW_FILE_EDIT', true);
define('WP_AUTO_UPDATE_CORE', false);
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');
define('WP_DEBUG', false);
define('FLYNE_ENGINE', true);

if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
WPCONFIG;
}

// ============================================================================
// API ROUTER
// ============================================================================
if (!authenticate()) error('Unauthorized', 401);

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = trim($uri, '/');
$parts = explode('/', $uri);

// Remove 'api' prefix if present
if (($parts[0] ?? '') === 'api') array_shift($parts);

$input = json_decode(file_get_contents('php://input'), true) ?? [];
$data = array_merge($_POST, $_GET, $input);
$domain = $data['domain'] ?? $parts[1] ?? '';
$action = $data['action'] ?? $parts[0] ?? '';

// Legacy handler.php compatibility - route by action parameter
if (!empty($data['action'])) {
    $action = $data['action'];
}

try {
    switch ($action) {
        // Site Management
        case 'site_create':
        case 'create_site':
            $result = createSite($data['domain'], $data['php_version'] ?? '8.4');
            success($result, 'Site created');
            
        case 'site_delete':
        case 'delete_site':
            deleteSite($domain);
            success([], 'Site deleted');
            
        case 'site_list':
        case 'list_sites':
            $sites = db()->query("SELECT id, domain, php_version, status, ssl_enabled, created_at FROM sites ORDER BY created_at DESC")->fetchAll();
            success(['sites' => $sites]);
            
        case 'site_info':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            $wpInfo = wpcli($domain, 'core version --extra');
            success(['site' => $site, 'wordpress' => $wpInfo['output']]);
            
        // WordPress Installation
        case 'wordpress_install':
        case 'wp_install':
            $result = installWordPress($domain, $data);
            success($result, 'WordPress installed');
            
        // Plugin Management
        case 'plugin_list':
            $result = wpcli($domain, 'plugin list --format=json');
            success(['plugins' => json_decode($result['output'], true) ?? []]);
            
        case 'plugin_activate':
            $result = wpcli($domain, 'plugin activate ' . escapeshellarg($data['plugin']));
            success(['message' => $result['output']]);
            
        case 'plugin_deactivate':
            $result = wpcli($domain, 'plugin deactivate ' . escapeshellarg($data['plugin']));
            success(['message' => $result['output']]);
            
        case 'plugin_install':
            $result = wpcli($domain, 'plugin install ' . escapeshellarg($data['plugin']) . ' --activate');
            success(['message' => $result['output']]);
            
        case 'plugin_delete':
            $result = wpcli($domain, 'plugin delete ' . escapeshellarg($data['plugin']));
            success(['message' => $result['output']]);
            
        case 'plugin_search':
            $result = wpcli($domain, 'plugin search ' . escapeshellarg($data['query']) . ' --format=json --per-page=12');
            success(['plugins' => json_decode($result['output'], true) ?? []]);
            
        case 'plugin_popular':
            $result = wpcli($domain, 'plugin search "" --format=json --per-page=12');
            success(['plugins' => json_decode($result['output'], true) ?? []]);
            
        // Theme Management  
        case 'theme_list':
            $result = wpcli($domain, 'theme list --format=json');
            success(['themes' => json_decode($result['output'], true) ?? []]);
            
        case 'theme_activate':
            $result = wpcli($domain, 'theme activate ' . escapeshellarg($data['theme']));
            success(['message' => $result['output']]);
            
        case 'theme_install':
            $result = wpcli($domain, 'theme install ' . escapeshellarg($data['theme']));
            success(['message' => $result['output']]);
            
        case 'theme_delete':
            $result = wpcli($domain, 'theme delete ' . escapeshellarg($data['theme']));
            success(['message' => $result['output']]);
            
        case 'theme_search':
            $result = wpcli($domain, 'theme search ' . escapeshellarg($data['query']) . ' --format=json --per-page=12');
            success(['themes' => json_decode($result['output'], true) ?? []]);
            
        // User Management
        case 'user_list':
            $result = wpcli($domain, 'user list --format=json');
            success(['users' => json_decode($result['output'], true) ?? []]);
            
        case 'user_create':
            $result = wpcli($domain, sprintf('user create %s %s --role=%s --porcelain',
                escapeshellarg($data['username']),
                escapeshellarg($data['email']),
                escapeshellarg($data['role'] ?? 'editor')
            ));
            success(['user_id' => trim($result['output'])]);
            
        // Database
        case 'db_info':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            success(['db_name' => $site['db_name'], 'db_user' => $site['db_user'], 'db_host' => 'localhost']);
            
        case 'db_export':
            $site = getSite($domain);
            $file = BACKUPS_DIR . "/{$domain}_" . date('Y-m-d_His') . '.sql.gz';
            @mkdir(BACKUPS_DIR, 0755, true);
            $result = shell("mysqldump -u {$site['db_user']} -p'{$site['db_pass']}' {$site['db_name']} | gzip > $file");
            success(['file' => $file, 'size' => filesize($file)]);
            
        case 'pma_login':
            $site = getSite($domain);
            // Generate a one-time token for phpMyAdmin SSO (simplified)
            success(['url' => "https://" . ($_SERVER['PMA_DOMAIN'] ?? 'pma.example.com'), 'db_name' => $site['db_name'], 'db_user' => $site['db_user'], 'db_pass' => $site['db_pass']]);
            
        // SFTP
        case 'sftp_info':
            $site = getSite($domain);
            success(['host' => $_SERVER['SERVER_NAME'], 'port' => 22, 'user' => $site['user_name'], 'path' => SITES_DIR . "/$domain/public"]);
            
        case 'sftp_reset_password':
            $site = getSite($domain);
            $newPass = bin2hex(random_bytes(12));
            shell("echo '{$site['user_name']}:$newPass' | chpasswd");
            success(['password' => $newPass]);
            
        // Cache
        case 'cache_flush':
            wpcli($domain, 'cache flush');
            wpcli($domain, 'redis flush');
            shell("rm -rf /tmp/nginx-cache/*$domain*");
            success([], 'Cache cleared');
            
        // SSL
        case 'ssl_enable':
            $result = shell("certbot --nginx -d $domain -d www.$domain --non-interactive --agree-tos");
            if ($result['success']) {
                db()->prepare("UPDATE sites SET ssl_enabled = 1 WHERE domain = ?")->execute([$domain]);
                success([], 'SSL enabled');
            }
            error('SSL installation failed: ' . $result['output']);
            
        case 'ssl_status':
            $site = getSite($domain);
            $ch = curl_init("https://$domain");
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_NOBODY => true, CURLOPT_SSL_VERIFYPEER => false]);
            curl_exec($ch);
            $sslActive = curl_errno($ch) === 0;
            curl_close($ch);
            success(['ssl_enabled' => (bool)$site['ssl_enabled'], 'ssl_active' => $sslActive]);
            
        // PHP Version
        case 'php_switch':
            $site = getSite($domain);
            $newVersion = $data['version'];
            if (!in_array($newVersion, ['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'])) error('Invalid PHP version');
            
            // Remove old pool
            @unlink("/etc/php/{$site['php_version']}/fpm/pool.d/$domain.conf");
            shell("systemctl reload php{$site['php_version']}-fpm");
            
            // Create new pool
            createPhpPool($domain, $site['user_name'], $newVersion);
            shell("systemctl reload php{$newVersion}-fpm");
            
            // Update Nginx
            createNginxConfig($domain, $newVersion);
            shell("nginx -t && systemctl reload nginx");
            
            db()->prepare("UPDATE sites SET php_version = ? WHERE domain = ?")->execute([$newVersion, $domain]);
            success([], "PHP switched to $newVersion");
            
        case 'php_versions':
            $versions = [];
            foreach (['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'] as $v) {
                if (file_exists("/etc/php/$v/fpm/php-fpm.conf")) {
                    $versions[] = ['version' => $v, 'available' => true];
                }
            }
            success(['versions' => $versions]);
            
        // Stats
        case 'disk_usage':
            $siteDir = SITES_DIR . "/$domain";
            $size = trim(shell("du -sm $siteDir | cut -f1", false)['output']);
            success(['used_mb' => (int)$size, 'total_mb' => 10240]); // 10GB default
            
        case 'bandwidth_usage':
            $logFile = SITES_DIR . "/$domain/logs/access.log";
            $bytes = 0;
            if (file_exists($logFile)) {
                $bytes = (int)shell("awk '{sum+=\$10} END {print sum}' $logFile", false)['output'];
            }
            success(['used_mb' => round($bytes / 1024 / 1024, 2)]);
            
        case 'visitor_stats':
            $logFile = SITES_DIR . "/$domain/logs/access.log";
            $today = date('d/M/Y');
            $visitors = 0;
            if (file_exists($logFile)) {
                $visitors = (int)shell("grep '$today' $logFile | awk '{print \$1}' | sort -u | wc -l", false)['output'];
            }
            success(['today' => $visitors]);
            
        // Backup
        case 'start_backup':
            $site = getSite($domain);
            $backupDir = BACKUPS_DIR . "/$domain";
            @mkdir($backupDir, 0755, true);
            $timestamp = date('Y-m-d_His');
            $filesArchive = "$backupDir/files_$timestamp.tar.gz";
            $dbArchive = "$backupDir/db_$timestamp.sql.gz";
            
            // Backup files
            shell("tar -czf $filesArchive -C " . SITES_DIR . "/$domain public");
            // Backup database
            shell("mysqldump -u {$site['db_user']} -p'{$site['db_pass']}' {$site['db_name']} | gzip > $dbArchive");
            
            $stmt = db()->prepare("INSERT INTO backups (site_id, type, status, file_path, file_size) VALUES (?, 'full', 'completed', ?, ?)");
            $stmt->execute([$site['id'], "$backupDir/$timestamp", filesize($filesArchive) + filesize($dbArchive)]);
            
            success(['backup_id' => db()->lastInsertId(), 'files' => $filesArchive, 'database' => $dbArchive]);
            
        case 'restore_backup':
            // Implementation for restore
            $backupId = (int)$data['backup_id'];
            // ... restore logic
            success([], 'Restore started');
            
        // Staging
        case 'create_staging':
            $stagingDomain = 'staging.' . $domain;
            $result = createSite($stagingDomain, getSite($domain)['php_version'] ?? '8.4');
            // Clone files and database
            shell("rsync -a " . SITES_DIR . "/$domain/public/ " . SITES_DIR . "/$stagingDomain/public/");
            $site = getSite($domain);
            $staging = getSite($stagingDomain);
            shell("mysqldump -u {$site['db_user']} -p'{$site['db_pass']}' {$site['db_name']} | mysql -u {$staging['db_user']} -p'{$staging['db_pass']}' {$staging['db_name']}");
            wpcli($stagingDomain, "search-replace '$domain' '$stagingDomain'");
            success(['staging_domain' => $stagingDomain]);
            
        case 'list_stagings':
            $stagings = db()->prepare("SELECT * FROM sites WHERE domain LIKE ?");
            $stagings->execute(['staging.' . $domain]);
            success(['stagings' => $stagings->fetchAll()]);
            
        default:
            error('Unknown action: ' . $action, 404);
    }
} catch (Throwable $e) {
    error($e->getMessage(), 500);
}