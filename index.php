<?php
/**
 * FLYNE ENGINE - Complete WordPress Hosting API
 * With SFTP Management & WP-CLI
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/flyne/api.log');

define('API_SECRET', $_SERVER['FLYNE_API_SECRET'] ?? '');
define('MYSQL_PASS', $_SERVER['FLYNE_MYSQL_PASS'] ?? '');
define('REDIS_PASS', $_SERVER['FLYNE_REDIS_PASS'] ?? '');
define('SITES_DIR', '/var/www/sites');
define('FLYNE_DIR', '/opt/flyne');

header('Content-Type: application/json');

function db(): PDO {
    static $pdo = null;
    if (!$pdo) {
        $pdo = new PDO('mysql:host=localhost;dbname=flyne_engine;charset=utf8mb4', 'root', MYSQL_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
    }
    return $pdo;
}

function authenticate(): bool {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $key = $_POST['api_key'] ?? $_GET['api_key'] ?? '';
    if (preg_match('/Bearer\s+(.+)$/i', $auth, $m) && hash_equals(API_SECRET, $m[1])) return true;
    if (!empty($key) && hash_equals(API_SECRET, $key)) return true;
    return false;
}

function success($data = [], string $msg = 'OK'): never {
    die(json_encode(['success' => true, 'message' => $msg, 'data' => $data]));
}

function error(string $msg): never {
    die(json_encode(['success' => false, 'error' => $msg]));
}

function shell(string $cmd): array {
    exec("sudo $cmd 2>&1", $out, $code);
    return ['output' => implode("\n", $out), 'code' => $code, 'success' => $code === 0];
}

function getSite(string $domain): ?array {
    $stmt = db()->prepare("SELECT * FROM sites WHERE domain = ?");
    $stmt->execute([$domain]);
    return $stmt->fetch() ?: null;
}

function createSiteWithWordPress(string $domain, string $phpVersion = '8.4', array $wpOpts = []): array {
    if (!preg_match('/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i', $domain)) {
        error('Invalid domain format');
    }
    
    if (getSite($domain)) {
        error('Site already exists');
    }

    $safeName = preg_replace('/[^a-z0-9]/', '_', strtolower($domain));
    $safeUser = 'site_' . substr($safeName, 0, 28);
    $dbName = 'wp_' . substr($safeName, 0, 60);
    $dbUser = substr($dbName, 0, 32);
    $dbPass = bin2hex(random_bytes(16));
    $wpPass = bin2hex(random_bytes(8));
    $redisDb = (int)db()->query("SELECT COALESCE(MAX(redis_db), 0) + 1 FROM sites")->fetchColumn();

    $siteDir = SITES_DIR . "/$domain";
    $publicDir = "$siteDir/public";
    $logsDir = "$siteDir/logs";

    try {
        shell("useradd -m -d $siteDir -s /bin/bash $safeUser");
        shell("mkdir -p $publicDir $logsDir $siteDir/tmp");
        shell("touch $logsDir/access.log $logsDir/error.log $logsDir/php-error.log");
        shell("chown -R $safeUser:$safeUser $siteDir");
        shell("chmod 755 $siteDir $publicDir");
        
        $pdo = new PDO('mysql:host=localhost', 'root', MYSQL_PASS);
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("DROP USER IF EXISTS '$dbUser'@'localhost'");
        $pdo->exec("CREATE USER '$dbUser'@'localhost' IDENTIFIED BY '$dbPass'");
        $pdo->exec("GRANT ALL PRIVILEGES ON `$dbName`.* TO '$dbUser'@'localhost'");
        $pdo->exec("FLUSH PRIVILEGES");

        $poolConf = "[{$domain}]
user = {$safeUser}
group = {$safeUser}
listen = /run/php/php-{$domain}.sock
listen.owner = www-data
listen.group = www-data
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[open_basedir] = {$siteDir}:/tmp:/usr/share/php
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 300
php_admin_value[error_log] = {$logsDir}/php-error.log
php_admin_flag[log_errors] = on
php_admin_value[disable_functions] = exec,shell_exec,system,passthru,popen,proc_open,proc_close,proc_get_status,proc_terminate,proc_nice,posix_kill,symlink,getmypid,getpwuid,posix_getpwuid,pcntl_signal,get_current_user,disk_total_space,disk_free_space,escapeshellcmd,escapeshellarg
";
        file_put_contents("/etc/php/{$phpVersion}/fpm/pool.d/{$domain}.conf", $poolConf);

        $nginxConf = "server {
    listen 80;
    listen [::]:80;
    server_name {$domain} www.{$domain};
    root {$publicDir};
    index index.php index.html;

    access_log {$logsDir}/access.log;
    error_log {$logsDir}/error.log;

    location ~ /\\.ht { deny all; }
    location ~ /wp-config.php { deny all; }
    location ~* /(?:uploads|files)/.*\\.php$ { deny all; }

    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control \"public, immutable\";
        try_files \$uri =404;
    }

    set \$skip_cache 0;
    if (\$request_method = POST) { set \$skip_cache 1; }
    if (\$query_string != \"\") { set \$skip_cache 1; }
    if (\$request_uri ~* \"/wp-admin/|/xmlrpc.php|wp-.*.php|/feed/|sitemap\") { set \$skip_cache 1; }
    if (\$http_cookie ~* \"wordpress_logged_in|wp-postpass|woocommerce_\") { set \$skip_cache 1; }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \\.php$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php-{$domain}.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_cache WORDPRESS;
        fastcgi_cache_valid 200 60m;
        fastcgi_cache_bypass \$skip_cache;
        fastcgi_no_cache \$skip_cache;
        add_header X-FastCGI-Cache \$upstream_cache_status;
    }
}
";
        file_put_contents("/etc/nginx/sites-flyne/{$domain}.conf", $nginxConf);

        shell("systemctl reload php{$phpVersion}-fpm");
        shell("nginx -t && systemctl reload nginx");

        shell("sudo -u $safeUser /usr/bin/php8.4 /usr/local/bin/wp core download --path='$publicDir'");

        $salts = @file_get_contents('https://api.wordpress.org/secret-key/1.1/salt/') ?: 
            "define('AUTH_KEY', '" . bin2hex(random_bytes(32)) . "');\ndefine('SECURE_AUTH_KEY', '" . bin2hex(random_bytes(32)) . "');\ndefine('LOGGED_IN_KEY', '" . bin2hex(random_bytes(32)) . "');\ndefine('NONCE_KEY', '" . bin2hex(random_bytes(32)) . "');\ndefine('AUTH_SALT', '" . bin2hex(random_bytes(32)) . "');\ndefine('SECURE_AUTH_SALT', '" . bin2hex(random_bytes(32)) . "');\ndefine('LOGGED_IN_SALT', '" . bin2hex(random_bytes(32)) . "');\ndefine('NONCE_SALT', '" . bin2hex(random_bytes(32)) . "');";

        $wpConfig = "<?php
define('DB_NAME', '{$dbName}');
define('DB_USER', '{$dbUser}');
define('DB_PASSWORD', '{$dbPass}');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');

{$salts}

\$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('DISALLOW_FILE_EDIT', true);
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');

define('WP_REDIS_HOST', '127.0.0.1');
define('WP_REDIS_PORT', 6379);
define('WP_REDIS_PASSWORD', '" . REDIS_PASS . "');
define('WP_REDIS_DATABASE', {$redisDb});

if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');
require_once ABSPATH . 'wp-settings.php';
";
        file_put_contents("$publicDir/wp-config.php", $wpConfig);
        shell("chown $safeUser:$safeUser $publicDir/wp-config.php");

        $title = escapeshellarg($wpOpts['title'] ?? $domain);
        $adminUser = $wpOpts['admin_user'] ?? 'admin';
        $adminEmail = $wpOpts['admin_email'] ?? "admin@$domain";
        
        $wpInstall = shell("sudo -u $safeUser /usr/bin/php8.4 /usr/local/bin/wp core install --path='$publicDir' --url='https://$domain' --title=$title --admin_user='$adminUser' --admin_email='$adminEmail' --admin_password='$wpPass' --skip-email");
        
        if (!$wpInstall['success']) {
            error('WordPress install failed: ' . $wpInstall['output']);
        }

        $stmt = db()->prepare("INSERT INTO sites (domain, user_name, db_name, db_user, db_pass, php_version, status, redis_db) VALUES (?, ?, ?, ?, ?, ?, 'active', ?)");
        $stmt->execute([$domain, $safeUser, $dbName, $dbUser, $dbPass, $phpVersion, $redisDb]);
        $siteId = (int)db()->lastInsertId();

        $sslResult = shell("certbot --nginx -d $domain --non-interactive --agree-tos --email $adminEmail");
        $sslEnabled = $sslResult['success'];
        
        if ($sslEnabled) {
            db()->prepare("UPDATE sites SET ssl_enabled = 1 WHERE id = ?")->execute([$siteId]);
        }

        return [
            'site_id' => $siteId,
            'domain' => $domain,
            'url' => ($sslEnabled ? 'https' : 'http') . "://$domain",
            'admin_url' => ($sslEnabled ? 'https' : 'http') . "://$domain/wp-admin/",
            'admin_user' => $adminUser,
            'admin_pass' => $wpPass,
            'admin_email' => $adminEmail,
            'db_name' => $dbName,
            'db_user' => $dbUser,
            'db_pass' => $dbPass,
            'php_version' => $phpVersion,
            'ssl_enabled' => $sslEnabled
        ];

    } catch (Throwable $e) {
        shell("userdel -r $safeUser 2>/dev/null");
        shell("rm -rf $siteDir");
        shell("rm -f /etc/nginx/sites-flyne/{$domain}.conf");
        shell("rm -f /etc/php/{$phpVersion}/fpm/pool.d/{$domain}.conf");
        $pdo = new PDO('mysql:host=localhost', 'root', MYSQL_PASS);
        $pdo->exec("DROP DATABASE IF EXISTS `$dbName`");
        $pdo->exec("DROP USER IF EXISTS '$dbUser'@'localhost'");
        db()->prepare("DELETE FROM sites WHERE domain = ?")->execute([$domain]);
        shell("systemctl reload nginx php{$phpVersion}-fpm");
        
        error('Site creation failed: ' . $e->getMessage());
    }
}

function deleteSite(string $domain): bool {
    $site = getSite($domain);
    if (!$site) error('Site not found');

    $phpVersion = $site['php_version'] ?? '8.4';
    
    @unlink("/etc/nginx/sites-flyne/{$domain}.conf");
    @unlink("/etc/php/{$phpVersion}/fpm/pool.d/{$domain}.conf");
    
    $pdo = new PDO('mysql:host=localhost', 'root', MYSQL_PASS);
    $pdo->exec("DROP DATABASE IF EXISTS `{$site['db_name']}`");
    $pdo->exec("DROP USER IF EXISTS '{$site['db_user']}'@'localhost'");
    
    // Delete SFTP user if exists
    $stmt = db()->prepare("SELECT username FROM sftp_access WHERE site_id = ?");
    $stmt->execute([$site['id']]);
    $sftp = $stmt->fetch();
    if ($sftp) {
        shell("userdel {$sftp['username']} 2>/dev/null");
    }
    
    shell("userdel -r {$site['user_name']} 2>/dev/null");
    shell("rm -rf " . SITES_DIR . "/$domain");
    
    db()->prepare("DELETE FROM sites WHERE domain = ?")->execute([$domain]);
    
    shell("systemctl reload nginx php{$phpVersion}-fpm");
    
    return true;
}

// ============================================================================
// WORDPRESS.ORG API HELPERS
// ============================================================================

function fetchWpOrgPlugins($args = []) {
    $defaults = ['browse' => 'popular', 'page' => 1, 'per_page' => 12];
    $args = array_merge($defaults, $args);
    
    $queryArgs = [
        'action' => 'query_plugins',
        'request[page]' => $args['page'],
        'request[per_page]' => $args['per_page'],
        'request[fields][icons]' => 'true',
        'request[fields][active_installs]' => 'true',
        'request[fields][short_description]' => 'true',
        'request[fields][rating]' => 'true',
        'request[fields][num_ratings]' => 'true',
        'request[fields][homepage]' => 'true',
        'request[fields][sections]' => 'false',
        'request[fields][versions]' => 'false'
    ];
    
    if (!empty($args['search'])) {
        $queryArgs['request[search]'] = $args['search'];
    } else {
        $queryArgs['request[browse]'] = $args['browse'];
    }
    
    $url = 'https://api.wordpress.org/plugins/info/1.2/?' . http_build_query($queryArgs);
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'WordPress/6.4',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) return null;
    return json_decode($response, true);
}

function fetchWpOrgThemes($args = []) {
    $defaults = ['browse' => 'popular', 'page' => 1, 'per_page' => 12];
    $args = array_merge($defaults, $args);
    
    $queryArgs = [
        'action' => 'query_themes',
        'request[page]' => $args['page'],
        'request[per_page]' => $args['per_page'],
        'request[fields][screenshot_url]' => 'true',
        'request[fields][active_installs]' => 'true',
        'request[fields][description]' => 'true',
        'request[fields][rating]' => 'true',
        'request[fields][num_ratings]' => 'true',
        'request[fields][homepage]' => 'true',
        'request[fields][sections]' => 'false',
        'request[fields][versions]' => 'false'
    ];
    
    if (!empty($args['search'])) {
        $queryArgs['request[search]'] = $args['search'];
    } else {
        $queryArgs['request[browse]'] = $args['browse'];
    }
    
    $url = 'https://api.wordpress.org/themes/info/1.2/?' . http_build_query($queryArgs);
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'WordPress/6.4',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) return null;
    return json_decode($response, true);
}

// Helper function for WP-CLI
function runWpCli(string $domain, string $command): array {
    $site = getSite($domain);
    if (!$site) error('Site not found');
    
    // Whitelist safe commands
    $allowed = ['plugin', 'theme', 'cache', 'option', 'post', 'user', 'db', 'search-replace', 'media', 'menu', 'widget', 'sidebar', 'cron', 'transient', 'rewrite', 'term', 'comment', 'core', 'config', 'cap', 'role', 'language', 'maintenance-mode', 'site'];
    
    // Block dangerous
    $blocked = ['eval', 'eval-file', 'shell', 'db drop', 'db reset'];
    foreach ($blocked as $b) {
        if (stripos($command, $b) !== false) {
            error("Command blocked: $b");
        }
    }
    
    $cmdParts = explode(' ', trim($command));
    $mainCmd = $cmdParts[0] ?? '';
    
    if (!in_array($mainCmd, $allowed)) {
        error("Command not allowed: $mainCmd");
    }
    
    $path = SITES_DIR . "/$domain/public";
    $result = shell("sudo -u {$site['user_name']} /usr/bin/php8.4 /usr/local/bin/wp $command --path='$path'");
    
    return ['command' => "wp $command", 'output' => $result['output'], 'exit_code' => $result['code']];
}

// ============================================================================
// ROUTER
// ============================================================================
if (!authenticate()) error('Unauthorized');

$action = $_POST['action'] ?? $_GET['action'] ?? '';
$domain = $_POST['domain'] ?? $_GET['domain'] ?? '';

try {
    switch ($action) {
        
        // ===== SITE MANAGEMENT =====
        case 'create_site':
        case 'site_create':
            $result = createSiteWithWordPress($domain, $_POST['php_version'] ?? '8.4', [
                'title' => $_POST['title'] ?? $domain,
                'admin_user' => $_POST['admin_user'] ?? 'admin',
                'admin_email' => $_POST['admin_email'] ?? "admin@$domain"
            ]);
            success($result, 'Site created with WordPress');

        case 'delete_site':
        case 'site_delete':
            deleteSite($domain);
            success([], 'Site deleted');

        case 'site_list':
        case 'list_sites':
            $sites = db()->query("SELECT id, domain, php_version, status, ssl_enabled, created_at FROM sites ORDER BY created_at DESC")->fetchAll();
            success(['sites' => $sites]);

        case 'site_info':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            success(['site' => $site]);

        // ===== SFTP MANAGEMENT =====
        case 'sftp_enable':
        case 'sftp_create':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            
            $expireIn = $_POST['expire'] ?? 'never';
            $expiresAt = null;
            
            switch ($expireIn) {
                case '1h': $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour')); break;
                case '24h': $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours')); break;
                case '7d': $expiresAt = date('Y-m-d H:i:s', strtotime('+7 days')); break;
                case '30d': $expiresAt = date('Y-m-d H:i:s', strtotime('+30 days')); break;
                default: $expiresAt = null;
            }
            
            $safeDomain = preg_replace('/[^a-z0-9]/', '_', strtolower($domain));
            $sftpUser = 'flyne_' . substr($safeDomain, 0, 24);
            $sftpPass = bin2hex(random_bytes(12));
            
            $stmt = db()->prepare("SELECT * FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $existing = $stmt->fetch();
            
            $siteDir = SITES_DIR . "/$domain";
            
            if ($existing) {
                $sftpUser = $existing['username'];
                shell("usermod -U $sftpUser");
                exec("echo '$sftpUser:$sftpPass' | sudo /usr/sbin/chpasswd");
                db()->prepare("UPDATE sftp_access SET is_enabled = 1, expires_at = ?, updated_at = NOW() WHERE id = ?")->execute([$expiresAt, $existing['id']]);
            } else {
                shell("useradd -M -d $siteDir -s /usr/sbin/nologin -G siteusers $sftpUser");
                exec("echo '$sftpUser:$sftpPass' | sudo /usr/sbin/chpasswd");
                shell("chown root:root $siteDir");
                shell("chmod 755 $siteDir");
                shell("chown -R {$site['user_name']}:{$site['user_name']} $siteDir/public $siteDir/logs $siteDir/tmp");
                shell("chmod -R g+w $siteDir/public");
                shell("usermod -aG {$site['user_name']} $sftpUser");
                db()->prepare("INSERT INTO sftp_access (site_id, username, is_enabled, expires_at) VALUES (?, ?, 1, ?)")->execute([$site['id'], $sftpUser, $expiresAt]);
            }
            
            success([
                'host' => $_SERVER['SERVER_NAME'] ?? gethostname(),
                'port' => 22,
                'username' => $sftpUser,
                'password' => $sftpPass,
                'path' => '/public',
                'expires_at' => $expiresAt,
                'expire_in' => $expireIn
            ], 'SFTP access enabled');

        case 'sftp_disable':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            
            $stmt = db()->prepare("SELECT * FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            
            if (!$sftp) error('SFTP not configured');
            
            shell("usermod -L {$sftp['username']}");
            db()->prepare("UPDATE sftp_access SET is_enabled = 0 WHERE id = ?")->execute([$sftp['id']]);
            
            success([], 'SFTP access disabled');

        case 'sftp_status':
        case 'sftp_info':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            
            $stmt = db()->prepare("SELECT * FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            
            if (!$sftp) {
                success(['configured' => false, 'enabled' => false]);
            }
            
            success([
                'configured' => true,
                'enabled' => (bool)$sftp['is_enabled'],
                'username' => $sftp['username'],
                'host' => $_SERVER['SERVER_NAME'] ?? gethostname(),
                'port' => 22,
                'path' => '/public',
                'expires_at' => $sftp['expires_at'],
                'created_at' => $sftp['created_at']
            ]);

        case 'sftp_reset_password':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            
            $stmt = db()->prepare("SELECT * FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            
            if (!$sftp) error('SFTP not configured. Use sftp_enable first.');
            
            $newPass = bin2hex(random_bytes(12));
            exec("echo '{$sftp['username']}:$newPass' | sudo /usr/sbin/chpasswd");            
            $expireIn = $_POST['expire'] ?? null;
            $expiresAt = $sftp['expires_at'];
            if ($expireIn) {
                switch ($expireIn) {
                    case '1h': $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour')); break;
                    case '24h': $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours')); break;
                    case '7d': $expiresAt = date('Y-m-d H:i:s', strtotime('+7 days')); break;
                    case '30d': $expiresAt = date('Y-m-d H:i:s', strtotime('+30 days')); break;
                    case 'never': $expiresAt = null; break;
                }
                db()->prepare("UPDATE sftp_access SET expires_at = ? WHERE id = ?")->execute([$expiresAt, $sftp['id']]);
            }
            
            success(['username' => $sftp['username'], 'password' => $newPass, 'expires_at' => $expiresAt]);

        // ===== WP-CLI =====
        case 'wp_cli':
        case 'wpcli':
            $command = $_POST['command'] ?? '';
            if (empty($command)) error('Command required');
            $result = runWpCli($domain, $command);
            success($result);

        case 'wp_plugin_list':
            $result = runWpCli($domain, 'plugin list --format=json');
            success(['plugins' => json_decode($result['output'], true) ?? [], 'raw' => $result['output']]);

        case 'wp_plugin_install':
            $plugin = $_POST['plugin'] ?? '';
            if (empty($plugin)) error('Plugin slug required');
            $result = runWpCli($domain, "plugin install $plugin --activate");
            success($result);

        case 'wp_plugin_activate':
            $plugin = $_POST['plugin'] ?? '';
            if (empty($plugin)) error('Plugin slug required');
            $result = runWpCli($domain, "plugin activate $plugin");
            success($result);

        case 'wp_plugin_deactivate':
            $plugin = $_POST['plugin'] ?? '';
            if (empty($plugin)) error('Plugin slug required');
            $result = runWpCli($domain, "plugin deactivate $plugin");
            success($result);
case 'wp_plugin_search':
        case 'plugin_search':
            $query = trim($_POST['query'] ?? '');
            $page = max(1, intval($_POST['page'] ?? 1));
            $perPage = min(100, max(1, intval($_POST['per_page'] ?? 12)));
            if (strlen($query) < 2) error('Query too short');
            $result = fetchWpOrgPlugins(['search' => $query, 'page' => $page, 'per_page' => $perPage]);
            if (!$result || !isset($result['plugins'])) error('Failed to search plugins');
            success(['plugins' => $result['plugins'], 'total_pages' => $result['info']['pages'] ?? 1]);

        case 'wp_plugin_popular':
        case 'plugin_popular':
            $page = max(1, intval($_POST['page'] ?? 1));
            $perPage = min(100, max(1, intval($_POST['per_page'] ?? 12)));
            $result = fetchWpOrgPlugins(['browse' => 'popular', 'page' => $page, 'per_page' => $perPage]);
            if (!$result || !isset($result['plugins'])) error('Failed to fetch popular plugins');
            success(['plugins' => $result['plugins'], 'total_pages' => $result['info']['pages'] ?? 1]);

        case 'wp_plugin_update_all':
            $result = runWpCli($domain, 'plugin update --all');
            success($result);

        case 'wp_theme_list':
            $result = runWpCli($domain, 'theme list --format=json');
            success(['themes' => json_decode($result['output'], true) ?? [], 'raw' => $result['output']]);
case 'wp_theme_install':
            $theme = $_POST['theme'] ?? '';
            if (empty($theme)) error('Theme slug required');
            $result = runWpCli($domain, "theme install $theme");
            success($result);

        case 'wp_theme_delete':
            $theme = $_POST['theme'] ?? '';
            if (empty($theme)) error('Theme slug required');
            $result = runWpCli($domain, "theme delete $theme");
            success($result);

        case 'wp_theme_search':
        case 'theme_search':
            $query = trim($_POST['query'] ?? '');
            $page = max(1, intval($_POST['page'] ?? 1));
            $perPage = min(100, max(1, intval($_POST['per_page'] ?? 12)));
            if (strlen($query) < 2) error('Query too short');
            $result = fetchWpOrgThemes(['search' => $query, 'page' => $page, 'per_page' => $perPage]);
            if (!$result || !isset($result['themes'])) error('Failed to search themes');
            success(['themes' => $result['themes'], 'total_pages' => $result['info']['pages'] ?? 1]);

        case 'wp_theme_popular':
        case 'theme_popular':
            $page = max(1, intval($_POST['page'] ?? 1));
            $perPage = min(100, max(1, intval($_POST['per_page'] ?? 12)));
            $result = fetchWpOrgThemes(['browse' => 'popular', 'page' => $page, 'per_page' => $perPage]);
            if (!$result || !isset($result['themes'])) error('Failed to fetch popular themes');
            success(['themes' => $result['themes'], 'total_pages' => $result['info']['pages'] ?? 1]);

        case 'wp_theme_activate':
            $theme = $_POST['theme'] ?? '';
            if (empty($theme)) error('Theme slug required');
            $result = runWpCli($domain, "theme activate $theme");
            success($result);

        case 'wp_cache_flush':
            $result = runWpCli($domain, 'cache flush');
            shell("rm -rf /tmp/nginx-cache/*");
            success($result);

        case 'wp_core_update':
            $result = runWpCli($domain, 'core update');
            success($result);

        case 'wp_core_version':
            $result = runWpCli($domain, 'core version');
            success(['version' => trim($result['output'])]);

        case 'wp_db_optimize':
            $result = runWpCli($domain, 'db optimize');
            success($result);

        case 'wp_search_replace':
            $search = $_POST['search'] ?? '';
            $replace = $_POST['replace'] ?? '';
            $dryRun = ($_POST['dry_run'] ?? '1') === '1' ? '--dry-run' : '';
            if (empty($search) || empty($replace)) error('Search and replace required');
            $result = runWpCli($domain, "search-replace '$search' '$replace' $dryRun");
            success($result);

        case 'wp_user_list':
            $result = runWpCli($domain, 'user list --format=json');
            success(['users' => json_decode($result['output'], true) ?? []]);

        case 'wp_user_create':
            $username = $_POST['username'] ?? '';
            $email = $_POST['email'] ?? '';
            $role = $_POST['role'] ?? 'editor';
            if (empty($username) || empty($email)) error('Username and email required');
            $result = runWpCli($domain, "user create $username $email --role=$role");
            success($result);

    case 'plugin_list':
            $result = runWpCli($domain, 'plugin list --format=json');
            $plugins = json_decode($result['output'], true) ?? [];
            foreach ($plugins as &$plugin) {
                $slug = $plugin['name'] ?? '';
                if ($slug) {
                    $plugin['slug'] = $slug;
                    $plugin['icons'] = [
                        '1x' => "https://ps.w.org/{$slug}/assets/icon-128x128.png",
                        '2x' => "https://ps.w.org/{$slug}/assets/icon-256x256.png"
                    ];
                }
            }
            success(['plugins' => $plugins]);

        case 'plugin_activate':
            $plugin = $_POST['plugin'] ?? '';
            $result = runWpCli($domain, "plugin activate $plugin");
            success(['message' => $result['output']]);

        case 'plugin_deactivate':
            $plugin = $_POST['plugin'] ?? '';
            $result = runWpCli($domain, "plugin deactivate $plugin");
            success(['message' => $result['output']]);

        case 'plugin_install':
            $plugin = $_POST['plugin'] ?? '';
            $result = runWpCli($domain, "plugin install $plugin --activate");
            success(['message' => $result['output']]);

        case 'plugin_delete':
            $plugin = $_POST['plugin'] ?? '';
            $result = runWpCli($domain, "plugin delete $plugin");
            success(['message' => $result['output']]);

        case 'theme_list':
            $result = runWpCli($domain, 'theme list --format=json');
            $themes = json_decode($result['output'], true) ?? [];
            foreach ($themes as &$theme) {
                $themeName = $theme['name'] ?? '';
                $themePath = SITES_DIR . "/$domain/public/wp-content/themes/$themeName";
                $screenshot = null;
                foreach (['png', 'jpg', 'jpeg', 'gif'] as $ext) {
                    if (file_exists($themePath . '/screenshot.' . $ext)) {
                        $screenshot = "/wp-content/themes/$themeName/screenshot.$ext";
                        break;
                    }
                }
                $theme['screenshot'] = $screenshot ? "https://$domain$screenshot" : null;
                $theme['slug'] = $themeName;
            }
            success(['themes' => $themes]);

        case 'theme_activate':
            $theme = $_POST['theme'] ?? $_POST['slug'] ?? '';
            $result = runWpCli($domain, "theme activate $theme");
            success(['message' => $result['output']]);

        case 'theme_install':
            $theme = $_POST['theme'] ?? $_POST['slug'] ?? '';
            $result = runWpCli($domain, "theme install $theme");
            success(['message' => $result['output']]);

        case 'theme_delete':
            $theme = $_POST['theme'] ?? $_POST['slug'] ?? '';
            $result = runWpCli($domain, "theme delete $theme");
            success(['message' => $result['output']]);

        case 'user_list':
            $result = runWpCli($domain, 'user list --format=json');
            success(['users' => json_decode($result['output'], true) ?? []]);

        case 'user_create':
            $username = $_POST['username'] ?? '';
            $email = $_POST['email'] ?? '';
            $role = $_POST['role'] ?? 'editor';
            $result = runWpCli($domain, "user create $username $email --role=$role");
            success(['message' => $result['output']]);

        case 'cache_flush':
            $result = runWpCli($domain, 'cache flush');
            shell("rm -rf /tmp/nginx-cache/*");
            success([], 'Cache flushed');

        case 'db_info':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            success(['db_name' => $site['db_name'], 'db_user' => $site['db_user'], 'db_host' => 'localhost']);

        case 'pma_login':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            success(['db_name' => $site['db_name'], 'db_user' => $site['db_user'], 'db_pass' => $site['db_pass']]);

        case 'ssl_enable':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            $result = shell("certbot --nginx -d $domain --non-interactive --agree-tos");
            if ($result['success']) {
                db()->prepare("UPDATE sites SET ssl_enabled = 1 WHERE domain = ?")->execute([$domain]);
                success([], 'SSL enabled');
            }
            error('SSL failed: ' . $result['output']);

        case 'ssl_status':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            success(['ssl_enabled' => (bool)$site['ssl_enabled']]);

        case 'disk_usage':
            $site = getSite($domain);
            if (!$site) error('Site not found');
            $size = trim(shell("du -sm " . SITES_DIR . "/$domain | cut -f1")['output']);
            success(['used_mb' => (int)$size]);

case 'php_version':
case 'php_switch':
    $site = getSite($domain);
    if (!$site) error('Site not found');
    
    $newVersion = $_POST['version'] ?? '';
    $allowed = ['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'];
    if (!in_array($newVersion, $allowed)) {
        error('Invalid PHP version. Allowed: ' . implode(', ', $allowed));
    }
    
    $oldVersion = $site['php_version'];
    $siteDir = SITES_DIR . "/$domain";
    $logsDir = "$siteDir/logs";
    $safeUser = $site['user_name'];
    
    $versionNum = str_replace('.', '', $newVersion);
    $versionedSocket = "/run/php/php-{$domain}.php{$versionNum}.sock";
    $symlinkPath = "/run/php/php-{$domain}.sock";
    
    if ($oldVersion === $newVersion) {
        success(['version' => $newVersion], 'Already on this version');
    }
    
    $poolConf = "[{$domain}]
user = {$safeUser}
group = {$safeUser}
listen = {$versionedSocket}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[open_basedir] = {$siteDir}:/tmp:/usr/share/php
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 300
php_admin_value[error_log] = {$logsDir}/php-error.log
php_admin_flag[log_errors] = on
php_admin_value[disable_functions] = exec,shell_exec,system,passthru,popen,proc_open,proc_close,proc_get_status,proc_terminate,proc_nice,posix_kill,symlink,getmypid,getpwuid,posix_getpwuid,pcntl_signal,get_current_user,disk_total_space,disk_free_space,escapeshellcmd,escapeshellarg
";

    $newPoolFile = "/etc/php/{$newVersion}/fpm/pool.d/{$domain}.conf";
    file_put_contents($newPoolFile, $poolConf);
    chmod($newPoolFile, 0644);
    
    db()->prepare("UPDATE sites SET php_version = ? WHERE id = ?")->execute([$newVersion, $site['id']]);
    
    $escapedDomain = escapeshellarg($domain);
    $escapedOld = escapeshellarg($oldVersion);
    $escapedNew = escapeshellarg($newVersion);
    
    exec("sudo /opt/flyne/php-switch.sh $escapedDomain $escapedOld $escapedNew > /dev/null 2>&1 &");
    
    success([
        'old_version' => $oldVersion,
        'new_version' => $newVersion
    ], 'PHP version changed');

        default:
            error('Unknown action: ' . $action);
    }
} catch (Throwable $e) {
    error($e->getMessage());
}