<?php
/**
 * FLYNE ENGINE v4.0 - Production WordPress Hosting API
 * Complete rewrite with proper permission model
 * All operations delegated to flyne-agent via sudo
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', '/var/log/flyne/api.log');
set_time_limit(300);

// Configuration from environment (set by Nginx)
define('API_SECRET', $_SERVER['FLYNE_API_SECRET'] ?? '');
define('MYSQL_USER', $_SERVER['FLYNE_MYSQL_USER'] ?? 'flyne_admin');
define('MYSQL_PASS', $_SERVER['FLYNE_MYSQL_PASS'] ?? '');
define('REDIS_PASS', $_SERVER['FLYNE_REDIS_PASS'] ?? '');
define('SITES_DIR', '/var/www/sites');
define('FLYNE_DIR', '/opt/flyne');
define('SCRIPTS_DIR', FLYNE_DIR . '/scripts');

header('Content-Type: application/json; charset=utf-8');
header('X-Powered-By: Flyne Engine v4.0');

//=============================================================================
// DATABASE CONNECTION
//=============================================================================
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                'mysql:host=localhost;dbname=flyne_engine;charset=utf8mb4',
                MYSQL_USER,
                MYSQL_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            apiError('Database connection failed', 500);
        }
    }
    return $pdo;
}

//=============================================================================
// AUTHENTICATION
//=============================================================================
function authenticate(): bool {
    if (empty(API_SECRET)) {
        return false;
    }
    
    // Check Authorization header
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+(.+)$/i', $auth, $matches)) {
        if (hash_equals(API_SECRET, $matches[1])) {
            return true;
        }
    }
    
    // Check api_key parameter
    $key = $_POST['api_key'] ?? $_GET['api_key'] ?? '';
    if (!empty($key) && hash_equals(API_SECRET, $key)) {
        return true;
    }
    
    return false;
}

//=============================================================================
// RESPONSE HELPERS
//=============================================================================
function apiSuccess(array $data = [], string $message = 'OK'): never {
    echo json_encode([
        'success' => true,
        'message' => $message,
        'data' => $data
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function apiError(string $message, int $code = 400): never {
    http_response_code($code);
    echo json_encode([
        'success' => false,
        'error' => $message
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

//=============================================================================
// SCRIPT EXECUTION (runs as flyne-agent via sudo)
//=============================================================================
function runScript(string $script, array $args = []): array {
    $scriptPath = SCRIPTS_DIR . '/' . $script;
    
    if (!file_exists($scriptPath)) {
        return ['success' => false, 'error' => "Script not found: $script"];
    }
    
    // Escape all arguments
    $escapedArgs = array_map('escapeshellarg', $args);
    $argString = implode(' ', $escapedArgs);
    
    // Run as flyne-agent via sudo
    $cmd = "sudo -u flyne-agent {$scriptPath} {$argString} 2>&1";
    
    $output = [];
    $exitCode = 0;
    exec($cmd, $output, $exitCode);
    
    $outputStr = implode("\n", $output);
    
    // Try to parse JSON output from script
    $json = json_decode($outputStr, true);
    if (json_last_error() === JSON_ERROR_NONE && is_array($json)) {
        return $json;
    }
    
    // Return raw output if not JSON
    return [
        'success' => $exitCode === 0,
        'output' => $outputStr,
        'exit_code' => $exitCode
    ];
}

//=============================================================================
// SITE HELPERS
//=============================================================================
function getSite(string $domain): ?array {
    $stmt = db()->prepare("SELECT * FROM sites WHERE domain = ?");
    $stmt->execute([$domain]);
    return $stmt->fetch() ?: null;
}

function validateDomain(string $domain): bool {
    return (bool)preg_match('/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i', $domain);
}

function getSitePhpVersion(string $domain): string {
    $file = FLYNE_DIR . "/run/{$domain}.php";
    if (file_exists($file)) {
        return trim(file_get_contents($file));
    }
    $site = getSite($domain);
    return $site['php_version'] ?? '8.4';
}

function logActivity(int $siteId, string $action, array $details = []): void {
    try {
        $stmt = db()->prepare("INSERT INTO activity_logs (site_id, action, details, ip_address) VALUES (?, ?, ?, ?)");
        $stmt->execute([
            $siteId,
            $action,
            json_encode($details),
            $_SERVER['REMOTE_ADDR'] ?? null
        ]);
    } catch (Exception $e) {
        // Don't fail on logging errors
    }
}

//=============================================================================
// WP-CLI HELPER
//=============================================================================
function runWpCli(string $domain, string $command): array {
    $site = getSite($domain);
    if (!$site) {
        apiError('Site not found');
    }
    
    // Block dangerous commands
    $blocked = ['eval', 'eval-file', 'shell', 'db drop', 'db reset', 'db create'];
    foreach ($blocked as $b) {
        if (stripos($command, $b) !== false) {
            apiError("Command blocked: $b");
        }
    }
    
    // Whitelist main commands
    $cmdParts = preg_split('/\s+/', trim($command));
    $mainCmd = $cmdParts[0] ?? '';
    $allowed = ['plugin', 'theme', 'cache', 'option', 'post', 'user', 'db', 'search-replace', 
                'media', 'menu', 'widget', 'cron', 'transient', 'rewrite', 'term', 
                'comment', 'core', 'config', 'cap', 'role', 'language', 'maintenance-mode', 'site'];
    
    if (!in_array($mainCmd, $allowed)) {
        apiError("Command not allowed: $mainCmd");
    }
    
    $result = runScript('wp-cli.sh', [$domain, $command]);
    
    return $result;
}

//=============================================================================
// WORDPRESS.ORG API HELPERS
//=============================================================================
function fetchWpOrgApi(string $endpoint, array $params): ?array {
    $url = "https://api.wordpress.org/{$endpoint}/info/1.2/?" . http_build_query($params);
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'Flyne Engine/4.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        return null;
    }
    
    return json_decode($response, true);
}

function searchPlugins(string $query = '', string $browse = 'popular', int $page = 1, int $perPage = 12): ?array {
    $params = [
        'action' => 'query_plugins',
        'request[page]' => $page,
        'request[per_page]' => min(100, max(1, $perPage)),
        'request[fields][icons]' => 'true',
        'request[fields][active_installs]' => 'true',
        'request[fields][short_description]' => 'true',
        'request[fields][rating]' => 'true',
        'request[fields][num_ratings]' => 'true',
        'request[fields][tested]' => 'true',
        'request[fields][requires]' => 'true',
        'request[fields][sections]' => 'false',
        'request[fields][versions]' => 'false'
    ];
    
    if (!empty($query)) {
        $params['request[search]'] = $query;
    } else {
        $params['request[browse]'] = $browse;
    }
    
    return fetchWpOrgApi('plugins', $params);
}

function searchThemes(string $query = '', string $browse = 'popular', int $page = 1, int $perPage = 12): ?array {
    $params = [
        'action' => 'query_themes',
        'request[page]' => $page,
        'request[per_page]' => min(100, max(1, $perPage)),
        'request[fields][screenshot_url]' => 'true',
        'request[fields][active_installs]' => 'true',
        'request[fields][description]' => 'true',
        'request[fields][rating]' => 'true',
        'request[fields][num_ratings]' => 'true',
        'request[fields][sections]' => 'false',
        'request[fields][versions]' => 'false'
    ];
    
    if (!empty($query)) {
        $params['request[search]'] = $query;
    } else {
        $params['request[browse]'] = $browse;
    }
    
    return fetchWpOrgApi('themes', $params);
}

//=============================================================================
// MAIN ROUTER
//=============================================================================
if (!authenticate()) {
    apiError('Unauthorized', 401);
}

$action = $_POST['action'] ?? $_GET['action'] ?? '';
$domain = trim($_POST['domain'] ?? $_GET['domain'] ?? '');

try {
    switch ($action) {
        
        //=====================================================================
        // SITE MANAGEMENT
        //=====================================================================
        
        case 'create_site':
        case 'site_create':
            if (empty($domain)) {
                apiError('Domain required');
            }
            if (!validateDomain($domain)) {
                apiError('Invalid domain format');
            }
            if (getSite($domain)) {
                apiError('Site already exists');
            }
            
            $phpVersion = $_POST['php_version'] ?? '8.4';
            $adminEmail = $_POST['admin_email'] ?? "admin@{$domain}";
            $title = $_POST['title'] ?? $domain;
            $adminUser = $_POST['admin_user'] ?? 'admin';
            
            // Validate PHP version
            $allowedPhp = ['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'];
            if (!in_array($phpVersion, $allowedPhp)) {
                apiError('Invalid PHP version. Allowed: ' . implode(', ', $allowedPhp));
            }
            
            $result = runScript('create-site.sh', [$domain, $phpVersion, $adminEmail, $title, $adminUser]);
            
            if (!empty($result['success']) && !empty($result['data'])) {
                apiSuccess($result['data'], 'Site created successfully');
            } elseif (!empty($result['error'])) {
                apiError($result['error']);
            } else {
                apiError('Site creation failed: ' . ($result['output'] ?? 'Unknown error'));
            }
            break;
            
        case 'delete_site':
        case 'site_delete':
            if (empty($domain)) {
                apiError('Domain required');
            }
            if (!getSite($domain)) {
                apiError('Site not found');
            }
            
            $result = runScript('delete-site.sh', [$domain]);
            
            if (!empty($result['success'])) {
                apiSuccess([], $result['message'] ?? 'Site deleted');
            } else {
                apiError($result['error'] ?? 'Delete failed');
            }
            break;
            
        case 'site_list':
        case 'list_sites':
            $status = $_GET['status'] ?? null;
            
            $sql = "SELECT id, domain, php_version, status, ssl_enabled, redis_db, 
                           wp_admin_user, wp_admin_email, created_at, updated_at 
                    FROM sites";
            $params = [];
            
            if ($status) {
                $sql .= " WHERE status = ?";
                $params[] = $status;
            }
            
            $sql .= " ORDER BY created_at DESC";
            
            $stmt = db()->prepare($sql);
            $stmt->execute($params);
            $sites = $stmt->fetchAll();
            
            apiSuccess(['sites' => $sites, 'count' => count($sites)]);
            break;
            
        case 'site_info':
        case 'site_details':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            // Get disk usage
            $siteDir = SITES_DIR . "/{$domain}";
            $diskUsage = 0;
            if (is_dir($siteDir)) {
                exec("du -sm " . escapeshellarg($siteDir) . " | cut -f1", $output);
                $diskUsage = (int)($output[0] ?? 0);
            }
            
            // Get SFTP status
            $stmt = db()->prepare("SELECT sftp_user, is_enabled, expires_at FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            
            $site['disk_usage_mb'] = $diskUsage;
            $site['sftp'] = $sftp ?: null;
            
            // Remove sensitive data
            unset($site['db_pass']);
            
            apiSuccess(['site' => $site]);
            break;
            
        //=====================================================================
        // PHP VERSION MANAGEMENT
        //=====================================================================
        
        case 'php_switch':
        case 'php_version':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $version = $_POST['version'] ?? '';
            if (empty($version)) {
                // Just return current version
                $site = getSite($domain);
                if (!$site) apiError('Site not found');
                apiSuccess(['php_version' => $site['php_version']]);
            }
            
            $result = runScript('php-switch.sh', [$domain, $version]);
            
            if (!empty($result['success'])) {
                apiSuccess([
                    'old_version' => $result['old_version'] ?? null,
                    'new_version' => $result['new_version'] ?? $version
                ], $result['message'] ?? 'PHP version changed');
            } else {
                apiError($result['error'] ?? 'PHP switch failed');
            }
            break;
            
        //=====================================================================
        // SFTP MANAGEMENT
        //=====================================================================
        
        case 'sftp_enable':
        case 'sftp_create':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $expire = $_POST['expire'] ?? 'never';
            $result = runScript('sftp-enable.sh', [$domain, $expire]);
            
            if (!empty($result['success']) && !empty($result['data'])) {
                apiSuccess($result['data'], 'SFTP access enabled');
            } else {
                apiError($result['error'] ?? 'SFTP enable failed');
            }
            break;
            
        case 'sftp_disable':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runScript('sftp-disable.sh', [$domain]);
            
            if (!empty($result['success'])) {
                apiSuccess([], $result['message'] ?? 'SFTP access disabled');
            } else {
                apiError($result['error'] ?? 'SFTP disable failed');
            }
            break;
            
        case 'sftp_status':
        case 'sftp_info':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            $stmt = db()->prepare("SELECT * FROM sftp_access WHERE site_id = ?");
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            
            if (!$sftp) {
                apiSuccess([
                    'configured' => false,
                    'enabled' => false
                ]);
            }
            
            apiSuccess([
                'configured' => true,
                'enabled' => (bool)$sftp['is_enabled'],
                'username' => $sftp['sftp_user'],
                'host' => gethostname(),
                'port' => 22,
                'path' => '/public',
                'expires_at' => $sftp['expires_at'],
                'created_at' => $sftp['created_at']
            ]);
            break;
            
        case 'sftp_reset_password':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $expire = $_POST['expire'] ?? null;
            $result = runScript('sftp-enable.sh', [$domain, $expire ?? 'never']);
            
            if (!empty($result['success']) && !empty($result['data'])) {
                apiSuccess($result['data'], 'SFTP password reset');
            } else {
                apiError($result['error'] ?? 'Password reset failed');
            }
            break;
            
        //=====================================================================
        // CACHE MANAGEMENT
        //=====================================================================
        
        case 'cache_flush':
        case 'cache_purge':
        case 'wp_cache_flush':
            $result = runScript('cache-purge.sh', $domain ? [$domain] : []);
            
            if (!empty($result['success'])) {
                apiSuccess([], $result['message'] ?? 'Cache purged');
            } else {
                apiError($result['error'] ?? 'Cache purge failed');
            }
            break;
            
        //=====================================================================
        // WP-CLI COMMANDS
        //=====================================================================
        
        case 'wp_cli':
        case 'wpcli':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $command = trim($_POST['command'] ?? '');
            if (empty($command)) {
                apiError('Command required');
            }
            
            $result = runWpCli($domain, $command);
            apiSuccess($result);
            break;
            
        //=====================================================================
        // PLUGIN MANAGEMENT
        //=====================================================================
        
        case 'plugin_list':
        case 'wp_plugin_list':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'plugin list --format=json');
            $plugins = [];
            
            if (!empty($result['output'])) {
                $decoded = json_decode($result['output'], true);
                if (is_array($decoded)) {
                    $plugins = $decoded;
                    // Add icon URLs
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
                }
            }
            
            apiSuccess(['plugins' => $plugins]);
            break;
            
        case 'plugin_install':
        case 'wp_plugin_install':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $plugin = trim($_POST['plugin'] ?? $_POST['slug'] ?? '');
            if (empty($plugin)) {
                apiError('Plugin slug required');
            }
            
            $activate = ($_POST['activate'] ?? '1') === '1' ? '--activate' : '';
            $result = runWpCli($domain, "plugin install {$plugin} {$activate}");
            
            $site = getSite($domain);
            if ($site) {
                logActivity($site['id'], 'plugin_install', ['plugin' => $plugin]);
            }
            
            apiSuccess(['output' => $result['output'] ?? ''], 'Plugin installed');
            break;
            
        case 'plugin_activate':
        case 'wp_plugin_activate':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $plugin = trim($_POST['plugin'] ?? $_POST['slug'] ?? '');
            if (empty($plugin)) {
                apiError('Plugin slug required');
            }
            
            $result = runWpCli($domain, "plugin activate {$plugin}");
            apiSuccess(['output' => $result['output'] ?? ''], 'Plugin activated');
            break;
            
        case 'plugin_deactivate':
        case 'wp_plugin_deactivate':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $plugin = trim($_POST['plugin'] ?? $_POST['slug'] ?? '');
            if (empty($plugin)) {
                apiError('Plugin slug required');
            }
            
            $result = runWpCli($domain, "plugin deactivate {$plugin}");
            apiSuccess(['output' => $result['output'] ?? ''], 'Plugin deactivated');
            break;
            
        case 'plugin_delete':
        case 'wp_plugin_delete':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $plugin = trim($_POST['plugin'] ?? $_POST['slug'] ?? '');
            if (empty($plugin)) {
                apiError('Plugin slug required');
            }
            
            $result = runWpCli($domain, "plugin delete {$plugin}");
            apiSuccess(['output' => $result['output'] ?? ''], 'Plugin deleted');
            break;
            
        case 'plugin_update':
        case 'wp_plugin_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $plugin = trim($_POST['plugin'] ?? $_POST['slug'] ?? 'all');
            
            if ($plugin === 'all') {
                $result = runWpCli($domain, 'plugin update --all');
            } else {
                $result = runWpCli($domain, "plugin update {$plugin}");
            }
            
            apiSuccess(['output' => $result['output'] ?? ''], 'Plugin(s) updated');
            break;
            
        case 'plugin_search':
        case 'wp_plugin_search':
            $query = trim($_POST['query'] ?? $_GET['query'] ?? '');
            $page = max(1, (int)($_POST['page'] ?? $_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_POST['per_page'] ?? $_GET['per_page'] ?? 12)));
            
            if (strlen($query) < 2) {
                apiError('Query must be at least 2 characters');
            }
            
            $result = searchPlugins($query, 'popular', $page, $perPage);
            
            if (!$result || !isset($result['plugins'])) {
                apiError('Failed to search plugins');
            }
            
            apiSuccess([
                'plugins' => $result['plugins'],
                'total' => $result['info']['results'] ?? 0,
                'total_pages' => $result['info']['pages'] ?? 1,
                'page' => $page
            ]);
            break;
            
        case 'plugin_popular':
        case 'wp_plugin_popular':
            $page = max(1, (int)($_POST['page'] ?? $_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_POST['per_page'] ?? $_GET['per_page'] ?? 12)));
            
            $result = searchPlugins('', 'popular', $page, $perPage);
            
            if (!$result || !isset($result['plugins'])) {
                apiError('Failed to fetch popular plugins');
            }
            
            apiSuccess([
                'plugins' => $result['plugins'],
                'total_pages' => $result['info']['pages'] ?? 1,
                'page' => $page
            ]);
            break;
            
        //=====================================================================
        // THEME MANAGEMENT
        //=====================================================================
        
        case 'theme_list':
        case 'wp_theme_list':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'theme list --format=json');
            $themes = [];
            
            if (!empty($result['output'])) {
                $decoded = json_decode($result['output'], true);
                if (is_array($decoded)) {
                    $themes = $decoded;
                    // Add screenshot URLs
                    foreach ($themes as &$theme) {
                        $themeName = $theme['name'] ?? '';
                        $themePath = SITES_DIR . "/{$domain}/public/wp-content/themes/{$themeName}";
                        $screenshot = null;
                        
                        foreach (['png', 'jpg', 'jpeg', 'gif'] as $ext) {
                            if (file_exists("{$themePath}/screenshot.{$ext}")) {
                                $screenshot = "https://{$domain}/wp-content/themes/{$themeName}/screenshot.{$ext}";
                                break;
                            }
                        }
                        
                        $theme['slug'] = $themeName;
                        $theme['screenshot_url'] = $screenshot;
                    }
                }
            }
            
            apiSuccess(['themes' => $themes]);
            break;
            
        case 'theme_install':
        case 'wp_theme_install':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $theme = trim($_POST['theme'] ?? $_POST['slug'] ?? '');
            if (empty($theme)) {
                apiError('Theme slug required');
            }
            
            $result = runWpCli($domain, "theme install {$theme}");
            
            $site = getSite($domain);
            if ($site) {
                logActivity($site['id'], 'theme_install', ['theme' => $theme]);
            }
            
            apiSuccess(['output' => $result['output'] ?? ''], 'Theme installed');
            break;
            
        case 'theme_activate':
        case 'wp_theme_activate':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $theme = trim($_POST['theme'] ?? $_POST['slug'] ?? '');
            if (empty($theme)) {
                apiError('Theme slug required');
            }
            
            $result = runWpCli($domain, "theme activate {$theme}");
            apiSuccess(['output' => $result['output'] ?? ''], 'Theme activated');
            break;
            
        case 'theme_delete':
        case 'wp_theme_delete':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $theme = trim($_POST['theme'] ?? $_POST['slug'] ?? '');
            if (empty($theme)) {
                apiError('Theme slug required');
            }
            
            $result = runWpCli($domain, "theme delete {$theme}");
            apiSuccess(['output' => $result['output'] ?? ''], 'Theme deleted');
            break;
            
        case 'theme_update':
        case 'wp_theme_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $theme = trim($_POST['theme'] ?? $_POST['slug'] ?? 'all');
            
            if ($theme === 'all') {
                $result = runWpCli($domain, 'theme update --all');
            } else {
                $result = runWpCli($domain, "theme update {$theme}");
            }
            
            apiSuccess(['output' => $result['output'] ?? ''], 'Theme(s) updated');
            break;
            
        case 'theme_search':
        case 'wp_theme_search':
            $query = trim($_POST['query'] ?? $_GET['query'] ?? '');
            $page = max(1, (int)($_POST['page'] ?? $_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_POST['per_page'] ?? $_GET['per_page'] ?? 12)));
            
            if (strlen($query) < 2) {
                apiError('Query must be at least 2 characters');
            }
            
            $result = searchThemes($query, 'popular', $page, $perPage);
            
            if (!$result || !isset($result['themes'])) {
                apiError('Failed to search themes');
            }
            
            apiSuccess([
                'themes' => $result['themes'],
                'total' => $result['info']['results'] ?? 0,
                'total_pages' => $result['info']['pages'] ?? 1,
                'page' => $page
            ]);
            break;
            
        case 'theme_popular':
        case 'wp_theme_popular':
            $page = max(1, (int)($_POST['page'] ?? $_GET['page'] ?? 1));
            $perPage = min(100, max(1, (int)($_POST['per_page'] ?? $_GET['per_page'] ?? 12)));
            
            $result = searchThemes('', 'popular', $page, $perPage);
            
            if (!$result || !isset($result['themes'])) {
                apiError('Failed to fetch popular themes');
            }
            
            apiSuccess([
                'themes' => $result['themes'],
                'total_pages' => $result['info']['pages'] ?? 1,
                'page' => $page
            ]);
            break;
            
        //=====================================================================
        // USER MANAGEMENT
        //=====================================================================
        
        case 'user_list':
        case 'wp_user_list':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'user list --format=json');
            $users = [];
            
            if (!empty($result['output'])) {
                $decoded = json_decode($result['output'], true);
                if (is_array($decoded)) {
                    $users = $decoded;
                }
            }
            
            apiSuccess(['users' => $users]);
            break;
            
        case 'user_create':
        case 'wp_user_create':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $username = trim($_POST['username'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $role = trim($_POST['role'] ?? 'editor');
            $password = $_POST['password'] ?? '';
            
            if (empty($username) || empty($email)) {
                apiError('Username and email required');
            }
            
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                apiError('Invalid email format');
            }
            
            $allowedRoles = ['subscriber', 'contributor', 'author', 'editor', 'administrator'];
            if (!in_array($role, $allowedRoles)) {
                apiError('Invalid role. Allowed: ' . implode(', ', $allowedRoles));
            }
            
            $cmd = "user create {$username} {$email} --role={$role}";
            if (!empty($password)) {
                $cmd .= " --user_pass=" . escapeshellarg($password);
            }
            
            $result = runWpCli($domain, $cmd);
            apiSuccess(['output' => $result['output'] ?? ''], 'User created');
            break;
            
        case 'user_delete':
        case 'wp_user_delete':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $userId = trim($_POST['user_id'] ?? $_POST['user'] ?? '');
            $reassign = trim($_POST['reassign'] ?? '1');
            
            if (empty($userId)) {
                apiError('User ID required');
            }
            
            $result = runWpCli($domain, "user delete {$userId} --reassign={$reassign} --yes");
            apiSuccess(['output' => $result['output'] ?? ''], 'User deleted');
            break;
            
        case 'user_update':
        case 'wp_user_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $userId = trim($_POST['user_id'] ?? $_POST['user'] ?? '');
            if (empty($userId)) {
                apiError('User ID required');
            }
            
            $args = [];
            if (!empty($_POST['email'])) {
                $args[] = '--user_email=' . escapeshellarg($_POST['email']);
            }
            if (!empty($_POST['role'])) {
                $args[] = '--role=' . escapeshellarg($_POST['role']);
            }
            if (!empty($_POST['display_name'])) {
                $args[] = '--display_name=' . escapeshellarg($_POST['display_name']);
            }
            
            if (empty($args)) {
                apiError('No fields to update');
            }
            
            $result = runWpCli($domain, "user update {$userId} " . implode(' ', $args));
            apiSuccess(['output' => $result['output'] ?? ''], 'User updated');
            break;
            
        case 'user_reset_password':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $userId = trim($_POST['user_id'] ?? $_POST['user'] ?? '');
            $newPassword = $_POST['password'] ?? bin2hex(random_bytes(8));
            
            if (empty($userId)) {
                apiError('User ID required');
            }
            
            $result = runWpCli($domain, "user update {$userId} --user_pass=" . escapeshellarg($newPassword));
            apiSuccess([
                'output' => $result['output'] ?? '',
                'new_password' => $newPassword
            ], 'Password reset');
            break;
            
        //=====================================================================
        // WORDPRESS CORE
        //=====================================================================
        
        case 'wp_core_version':
        case 'core_version':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'core version');
            apiSuccess(['version' => trim($result['output'] ?? '')]);
            break;
            
        case 'wp_core_update':
        case 'core_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'core update');
            
            $site = getSite($domain);
            if ($site) {
                logActivity($site['id'], 'core_update', []);
            }
            
            apiSuccess(['output' => $result['output'] ?? ''], 'WordPress core updated');
            break;
            
        case 'wp_core_check_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'core check-update --format=json');
            $updates = [];
            
            if (!empty($result['output'])) {
                $decoded = json_decode($result['output'], true);
                if (is_array($decoded)) {
                    $updates = $decoded;
                }
            }
            
            apiSuccess(['updates' => $updates]);
            break;
            
        //=====================================================================
        // DATABASE MANAGEMENT
        //=====================================================================
        
        case 'db_info':
        case 'pma_login':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            apiSuccess([
                'db_name' => $site['db_name'],
                'db_user' => $site['db_user'],
                'db_pass' => $site['db_pass'],
                'db_host' => 'localhost'
            ]);
            break;
            
        case 'wp_db_optimize':
        case 'db_optimize':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'db optimize');
            apiSuccess(['output' => $result['output'] ?? ''], 'Database optimized');
            break;
            
        case 'wp_db_repair':
        case 'db_repair':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'db repair');
            apiSuccess(['output' => $result['output'] ?? ''], 'Database repaired');
            break;
            
        case 'wp_search_replace':
        case 'search_replace':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $search = $_POST['search'] ?? '';
            $replace = $_POST['replace'] ?? '';
            $dryRun = ($_POST['dry_run'] ?? '1') === '1';
            
            if (empty($search) || empty($replace)) {
                apiError('Search and replace values required');
            }
            
            $cmd = "search-replace " . escapeshellarg($search) . " " . escapeshellarg($replace);
            if ($dryRun) {
                $cmd .= ' --dry-run';
            }
            
            $result = runWpCli($domain, $cmd);
            apiSuccess([
                'output' => $result['output'] ?? '',
                'dry_run' => $dryRun
            ], $dryRun ? 'Dry run completed' : 'Search and replace completed');
            break;
            
        case 'wp_transient_delete':
        case 'transient_delete':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'transient delete --all');
            apiSuccess(['output' => $result['output'] ?? ''], 'Transients deleted');
            break;
            
        //=====================================================================
        // SSL MANAGEMENT
        //=====================================================================
        
        case 'ssl_enable':
        case 'ssl_install':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            $email = $_POST['email'] ?? $site['wp_admin_email'] ?? "admin@{$domain}";
            
            // Run certbot via script
            $cmd = "sudo -u flyne-agent sudo /usr/bin/certbot --nginx -d {$domain} --non-interactive --agree-tos --email {$email} --redirect 2>&1";
            exec($cmd, $output, $exitCode);
            
            if ($exitCode === 0) {
                db()->prepare("UPDATE sites SET ssl_enabled = 1 WHERE id = ?")->execute([$site['id']]);
                logActivity($site['id'], 'ssl_enabled', []);
                apiSuccess(['output' => implode("\n", $output)], 'SSL certificate installed');
            } else {
                apiError('SSL installation failed: ' . implode("\n", $output));
            }
            break;
            
        case 'ssl_status':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            // Check certificate expiry
            $expiry = null;
            $certFile = "/etc/letsencrypt/live/{$domain}/cert.pem";
            if (file_exists($certFile)) {
                $certData = openssl_x509_parse(file_get_contents($certFile));
                if ($certData && isset($certData['validTo_time_t'])) {
                    $expiry = date('Y-m-d H:i:s', $certData['validTo_time_t']);
                }
            }
            
            apiSuccess([
                'ssl_enabled' => (bool)$site['ssl_enabled'],
                'expires_at' => $expiry
            ]);
            break;
            
        //=====================================================================
        // DISK & RESOURCE USAGE
        //=====================================================================
        
        case 'disk_usage':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            $siteDir = SITES_DIR . "/{$domain}";
            
            // Get total usage
            exec("du -sm " . escapeshellarg($siteDir) . " | cut -f1", $output);
            $total = (int)($output[0] ?? 0);
            
            // Get breakdown
            $breakdown = [];
            $subdirs = ['public', 'logs', 'tmp'];
            foreach ($subdirs as $subdir) {
                $path = "{$siteDir}/{$subdir}";
                if (is_dir($path)) {
                    unset($output);
                    exec("du -sm " . escapeshellarg($path) . " | cut -f1", $output);
                    $breakdown[$subdir] = (int)($output[0] ?? 0);
                }
            }
            
            // Get uploads specifically
            $uploadsPath = "{$siteDir}/public/wp-content/uploads";
            if (is_dir($uploadsPath)) {
                unset($output);
                exec("du -sm " . escapeshellarg($uploadsPath) . " | cut -f1", $output);
                $breakdown['uploads'] = (int)($output[0] ?? 0);
            }
            
            apiSuccess([
                'total_mb' => $total,
                'quota_mb' => $site['disk_quota_mb'] ?? 10240,
                'breakdown' => $breakdown
            ]);
            break;
            
        //=====================================================================
        // MAINTENANCE MODE
        //=====================================================================
        
        case 'maintenance_enable':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'maintenance-mode activate');
            apiSuccess(['output' => $result['output'] ?? ''], 'Maintenance mode enabled');
            break;
            
        case 'maintenance_disable':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'maintenance-mode deactivate');
            apiSuccess(['output' => $result['output'] ?? ''], 'Maintenance mode disabled');
            break;
            
        case 'maintenance_status':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $result = runWpCli($domain, 'maintenance-mode status');
            $isActive = stripos($result['output'] ?? '', 'active') !== false;
            apiSuccess(['active' => $isActive]);
            break;
            
        //=====================================================================
        // OPTIONS
        //=====================================================================
        
        case 'option_get':
        case 'wp_option_get':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $option = trim($_POST['option'] ?? $_GET['option'] ?? '');
            if (empty($option)) {
                apiError('Option name required');
            }
            
            $result = runWpCli($domain, "option get {$option}");
            apiSuccess([
                'option' => $option,
                'value' => trim($result['output'] ?? '')
            ]);
            break;
            
        case 'option_update':
        case 'wp_option_update':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $option = trim($_POST['option'] ?? '');
            $value = $_POST['value'] ?? '';
            
            if (empty($option)) {
                apiError('Option name required');
            }
            
            $result = runWpCli($domain, "option update {$option} " . escapeshellarg($value));
            apiSuccess(['output' => $result['output'] ?? ''], 'Option updated');
            break;
            
        //=====================================================================
        // SITE HEALTH & STATUS
        //=====================================================================
        
        case 'site_health':
        case 'health_check':
            if (empty($domain)) {
                apiError('Domain required');
            }
            
            $site = getSite($domain);
            if (!$site) {
                apiError('Site not found');
            }
            
            $checks = [];
            
            // Check if site responds
            $ch = curl_init("https://{$domain}/");
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_SSL_VERIFYPEER => false
            ]);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $loadTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
            curl_close($ch);
            
            $checks['http_status'] = $httpCode;
            $checks['response_time_ms'] = round($loadTime * 1000);
            $checks['is_up'] = $httpCode >= 200 && $httpCode < 400;
            
            // Check PHP-FPM socket
            $domainHash = substr(sha1($domain), 0, 12);
            $socket = "/run/php/site-{$domainHash}.sock";
            $checks['php_fpm_socket'] = file_exists($socket);
            
            // Get WP version
            $wpVersion = runWpCli($domain, 'core version');
            $checks['wordpress_version'] = trim($wpVersion['output'] ?? '');
            
            // Check for updates
            $updateCheck = runWpCli($domain, 'core check-update --format=json');
            $checks['core_update_available'] = !empty($updateCheck['output']) && $updateCheck['output'] !== '[]';
            
            apiSuccess(['health' => $checks]);
            break;
            
        //=====================================================================
        // ACTIVITY LOGS
        //=====================================================================
        
        case 'activity_log':
        case 'logs':
            $siteId = null;
            
            if (!empty($domain)) {
                $site = getSite($domain);
                if (!$site) {
                    apiError('Site not found');
                }
                $siteId = $site['id'];
            }
            
            $limit = min(100, max(1, (int)($_GET['limit'] ?? 50)));
            $offset = max(0, (int)($_GET['offset'] ?? 0));
            
            $sql = "SELECT * FROM activity_logs";
            $params = [];
            
            if ($siteId) {
                $sql .= " WHERE site_id = ?";
                $params[] = $siteId;
            }
            
            $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = db()->prepare($sql);
            $stmt->execute($params);
            $logs = $stmt->fetchAll();
            
            // Parse JSON details
            foreach ($logs as &$log) {
                if (!empty($log['details'])) {
                    $log['details'] = json_decode($log['details'], true);
                }
            }
            
            apiSuccess(['logs' => $logs]);
            break;
            
        //=====================================================================
        // SYSTEM STATUS (for admin panel)
        //=====================================================================
        
        case 'system_status':
            // Get server info
            $info = [
                'hostname' => gethostname(),
                'php_version' => PHP_VERSION,
                'api_version' => '4.0'
            ];
            
            // Memory usage
            $memInfo = file_get_contents('/proc/meminfo');
            if (preg_match('/MemTotal:\s+(\d+)/', $memInfo, $m)) {
                $info['memory_total_mb'] = round($m[1] / 1024);
            }
            if (preg_match('/MemAvailable:\s+(\d+)/', $memInfo, $m)) {
                $info['memory_available_mb'] = round($m[1] / 1024);
            }
            
            // Disk usage
            $info['disk_total_gb'] = round(disk_total_space('/') / 1073741824, 1);
            $info['disk_free_gb'] = round(disk_free_space('/') / 1073741824, 1);
            
            // Load average
            $load = sys_getloadavg();
            $info['load_average'] = $load;
            
            // Site counts
            $counts = db()->query("SELECT status, COUNT(*) as count FROM sites GROUP BY status")->fetchAll();
            $info['sites'] = [];
            foreach ($counts as $row) {
                $info['sites'][$row['status']] = (int)$row['count'];
            }
            $info['sites']['total'] = array_sum($info['sites']);
            
            // Service status
            $services = ['nginx', 'mariadb', 'redis-server'];
            $info['services'] = [];
            foreach ($services as $svc) {
                exec("systemctl is-active {$svc} 2>/dev/null", $output, $code);
                $info['services'][$svc] = $code === 0 ? 'running' : 'stopped';
                unset($output);
            }
            
            // PHP-FPM pools
            $phpVersions = ['7.4', '8.0', '8.1', '8.2', '8.3', '8.4'];
            $info['php_fpm'] = [];
            foreach ($phpVersions as $v) {
                exec("systemctl is-active php{$v}-fpm 2>/dev/null", $output, $code);
                if ($code === 0) {
                    $info['php_fpm'][$v] = 'running';
                }
                unset($output);
            }
            
            apiSuccess($info);
            break;
            
        //=====================================================================
        // DEFAULT
        //=====================================================================
        
        default:
            if (empty($action)) {
                apiSuccess([
                    'name' => 'Flyne Engine API',
                    'version' => '4.0',
                    'status' => 'operational'
                ], 'Flyne Engine API is running');
            }
            apiError("Unknown action: {$action}", 400);
    }
    
} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    apiError('Database error', 500);
} catch (Throwable $e) {
    error_log("API error: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    apiError('Internal server error: ' . $e->getMessage(), 500);
}