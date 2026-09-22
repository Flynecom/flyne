<?php
/**
 * FLYNE ENGINE v5.0 - Control Plane API
 *
 * Runs as the unprivileged `flyne-api` user inside its own PHP-FPM master.
 * Every privileged operation goes through ONE root-owned dispatcher
 * (/opt/flyne/bin/flyne-agent) with a fixed action allowlist; arguments are
 * always passed as a real argv - never as a shell string.
 *
 * Authentication: `Authorization: Bearer <secret>` only (no query-string keys),
 * optional client IP allowlist, TLS enforced once the panel certificate exists.
 * All action names from v4 are kept for panel compatibility.
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
set_time_limit(900);

const FLYNE_VERSION = '5.0';
const AGENT_BIN     = '/opt/flyne/bin/flyne-agent';
const CONFIG_FILE   = '/etc/flyne/api/config.php';
const AUTH_LOG      = '/var/log/flyne/auth.log';
const PHP_SOCK_DIR  = '/run/flyne-php';
const RE_DOMAIN     = '/^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/';

header_remove('X-Powered-By');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

//=============================================================================
// RESPONSE HELPERS
//=============================================================================
function apiSuccess(array $data = [], string $message = 'OK'): never {
    echo json_encode(['success' => true, 'message' => $message, 'data' => $data],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function apiError(string $message, int $code = 400): never {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $message],
        JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

//=============================================================================
// CONFIGURATION
//=============================================================================
$CFG = is_readable(CONFIG_FILE) ? require CONFIG_FILE : null;
if (!is_array($CFG) || empty($CFG['api_secret']) || empty($CFG['db_dsn'])) {
    error_log('Flyne API: ' . CONFIG_FILE . ' is missing or incomplete');
    apiError('Control plane is not configured', 500);
}

//=============================================================================
// AUTHENTICATION
//=============================================================================
function clientIp(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function ipInCidr(string $ip, string $cidr): bool {
    if (!str_contains($cidr, '/')) {
        return inet_pton($ip) !== false && inet_pton($cidr) !== false && inet_pton($ip) === inet_pton($cidr);
    }
    [$net, $bits] = explode('/', $cidr, 2);
    $ipBin = inet_pton($ip); $netBin = inet_pton($net);
    if ($ipBin === false || $netBin === false || strlen($ipBin) !== strlen($netBin) || !ctype_digit($bits)) return false;
    $bits = (int)$bits; $maxBits = strlen($ipBin) * 8;
    if ($bits < 0 || $bits > $maxBits) return false;
    $bytes = intdiv($bits, 8); $rem = $bits % 8;
    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) return false;
    if ($rem === 0) return true;
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return ((ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask));
}

function authFail(string $reason): void {
    @file_put_contents(AUTH_LOG, sprintf("%s AUTH-FAIL ip=%s reason=%s\n", date('c'), clientIp(), $reason), FILE_APPEND | LOCK_EX);
}

function isHttps(): bool {
    $h = strtolower((string)($_SERVER['HTTPS'] ?? ''));
    return ($h !== '' && $h !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
}

function authenticate(array $cfg): void {
    if (!empty($cfg['require_tls']) && !isHttps()) {
        apiError('TLS is required for the control plane API', 403);
    }
    if (!empty($cfg['allowed_ips']) && is_array($cfg['allowed_ips'])) {
        $ok = false;
        foreach ($cfg['allowed_ips'] as $cidr) {
            if (ipInCidr(clientIp(), (string)$cidr)) { $ok = true; break; }
        }
        if (!$ok) { authFail('ip'); apiError('Forbidden', 403); }
    }
    $auth = trim((string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
    if (preg_match('/^Bearer\s+([A-Za-z0-9._\-]{16,256})$/i', $auth, $m) && hash_equals((string)$cfg['api_secret'], $m[1])) {
        return;
    }
    authFail('key');
    usleep(random_int(150000, 450000));
    apiError('Unauthorized', 401);
}

//=============================================================================
// INPUT
//=============================================================================
$JSON_BODY = [];
if (stripos((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== false) {
    $decoded = json_decode((string)file_get_contents('php://input'), true);
    if (is_array($decoded)) $JSON_BODY = $decoded;
}

function param(string $key, ?string $default = null): ?string {
    global $JSON_BODY;
    $v = $JSON_BODY[$key] ?? $_POST[$key] ?? $_GET[$key] ?? null;
    if ($v === null) return $default;
    if (is_bool($v)) return $v ? '1' : '0';
    if (is_array($v)) return $default;
    return trim((string)$v);
}
function paramInt(string $key, int $default, int $min, int $max): int {
    $v = param($key);
    if ($v === null || $v === '' || !preg_match('/^-?\d{1,9}$/', $v)) return $default;
    return max($min, min($max, (int)$v));
}
function flag(string $key, bool $default): bool {
    $v = param($key);
    if ($v === null || $v === '') return $default;
    return in_array(strtolower($v), ['1', 'true', 'yes', 'on'], true);
}

//=============================================================================
// VALIDATORS (every value that reaches the agent passes one of these)
//=============================================================================
function vDomain(): string {
    $d = strtolower((string)param('domain', ''));
    if ($d === '') apiError('Domain required');
    if (!preg_match(RE_DOMAIN, $d)) apiError('Invalid domain format');
    return $d;
}
function vSlug(string $v, string $what): string {
    if (!preg_match('/^[a-z0-9][a-z0-9._-]{0,127}$/i', $v)) apiError("Invalid {$what}");
    return $v;
}
function vPackageRef(string $v, string $what): string {
    if (preg_match('/^[a-z0-9][a-z0-9._-]{0,127}$/i', $v)) return $v;
    if (preg_match('#^https://[a-z0-9.-]+(?::\d{2,5})?/[^\s"\'<>]{1,512}$#i', $v)) return $v;
    apiError("Invalid {$what}: expected a wordpress.org slug or an https URL");
}
function vUserRef(string $v): string {
    if (!preg_match('/^[a-zA-Z0-9._@+-]{1,100}$/', $v)) apiError('Invalid user reference');
    return $v;
}
function vOptionName(string $v): string {
    if (!preg_match('/^[a-zA-Z0-9_.:\-]{1,191}$/', $v)) apiError('Invalid option name');
    return $v;
}
function vPhp(string $v): string {
    global $CFG;
    $installed = is_array($CFG['php_versions'] ?? null) ? $CFG['php_versions'] : [];
    if (!in_array($v, $installed, true)) apiError('Invalid PHP version. Installed: ' . implode(', ', $installed));
    return $v;
}
function vNoFlag(string $v, string $what): string {
    if ($v === '' || $v[0] === '-') apiError("Invalid {$what}");
    if (strlen($v) > 4096 || str_contains($v, "\0")) apiError("Invalid {$what}");
    return $v;
}

//=============================================================================
// DATABASE (read/write on flyne_engine only; least-privilege user)
//=============================================================================
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        global $CFG;
        try {
            $pdo = new PDO((string)$CFG['db_dsn'], (string)$CFG['db_user'], (string)($CFG['db_pass'] ?? ''), [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            error_log('Flyne API: database connection failed: ' . $e->getMessage());
            apiError('Database connection failed', 500);
        }
    }
    return $pdo;
}
function getSite(string $domain): ?array {
    $stmt = db()->prepare('SELECT * FROM sites WHERE domain = ?');
    $stmt->execute([$domain]);
    $row = $stmt->fetch();
    return $row ?: null;
}
function requireSite(string $domain): array {
    $site = getSite($domain);
    if (!$site) apiError('Site not found', 404);
    return $site;
}
function publicSite(array $site): array {
    unset($site['db_pass']);
    foreach (['id','redis_db','cpu_quota','memory_max_mb','php_max_children','php_memory_limit_mb','redis_max_mb',
              'disk_quota_mb','disk_used_mb','db_used_mb','db_max_connections','ssl_enabled'] as $k) {
        if (isset($site[$k])) $site[$k] = (int)$site[$k];
    }
    return $site;
}
function logActivity(?int $siteId, string $action, array $details = []): void {
    try {
        $stmt = db()->prepare('INSERT INTO activity_logs (site_id, action, details, ip_address) VALUES (?, ?, ?, ?)');
        $stmt->execute([$siteId, $action, json_encode($details, JSON_UNESCAPED_SLASHES), clientIp()]);
    } catch (Throwable $e) {
        error_log('Flyne API: activity log failed: ' . $e->getMessage());
    }
}

//=============================================================================
// AGENT (root dispatcher) EXECUTION - argv only, with timeout and size caps
//=============================================================================
function agent(string $action, array $args = [], int $timeout = 600): array {
    $cmd = array_merge(['/usr/bin/sudo', '-n', AGENT_BIN, $action], array_map('strval', $args));
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open($cmd, $spec, $pipes, '/', ['PATH' => '/usr/bin:/bin', 'LANG' => 'C.UTF-8']);
    if (!is_resource($proc)) {
        error_log("Flyne API: unable to start agent for {$action}");
        return ['success' => false, 'error' => 'Unable to start the privileged agent'];
    }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = ''; $err = ''; $timedOut = false; $deadline = microtime(true) + $timeout;
    while (true) {
        $read = [];
        if (!feof($pipes[1])) $read[] = $pipes[1];
        if (!feof($pipes[2])) $read[] = $pipes[2];
        if (!$read) break;
        $w = null; $e = null;
        $n = @stream_select($read, $w, $e, 1);
        if ($n === false) break;
        foreach ($read as $s) {
            $chunk = fread($s, 65536);
            if ($chunk === false || $chunk === '') continue;
            if ($s === $pipes[1]) $out .= $chunk; else $err .= $chunk;
        }
        if (microtime(true) > $deadline) { $timedOut = true; proc_terminate($proc, 9); break; }
        if (strlen($out) > 8000000) { proc_terminate($proc, 9); break; }
    }
    fclose($pipes[1]); fclose($pipes[2]);
    $rc = proc_close($proc);
    if ($timedOut) {
        error_log("Flyne API: agent {$action} timed out after {$timeout}s");
        return ['success' => false, 'error' => "Operation timed out after {$timeout}s"];
    }
    $trim = trim($out);
    $json = $trim !== '' ? json_decode($trim, true) : null;
    if (!is_array($json)) {
        $lines = array_values(array_filter(array_map('trim', explode("\n", $trim)), 'strlen'));
        $last = $lines ? end($lines) : '';
        $json = $last !== '' ? json_decode($last, true) : null;
    }
    if (!is_array($json)) {
        error_log("Flyne API: agent {$action} returned non-JSON (rc={$rc}): " . substr($trim, 0, 400) . ' | stderr: ' . substr($err, 0, 400));
        return ['success' => false, 'error' => 'The privileged agent returned an invalid response', 'exit_code' => $rc];
    }
    return $json;
}
function agentOrFail(string $action, array $args, string $fallback, int $timeout = 600): array {
    $r = agent($action, $args, $timeout);
    if (empty($r['success'])) apiError((string)($r['error'] ?? $fallback), 500);
    return is_array($r['data'] ?? null) ? $r['data'] : [];
}
function agentData(array $r): array { return is_array($r['data'] ?? null) ? $r['data'] : []; }

//=============================================================================
// WP-CLI (runs as the site user with the site's PHP; argv only)
//=============================================================================
function wp(string $domain, array $args, int $timeout = 600): array {
    foreach ($args as $a) {
        $a = (string)$a;
        if (preg_match('/^--(require|exec|ssh|http|path|config|prompt)(=|$)/', $a)) apiError('WP-CLI argument not permitted');
        if (str_contains($a, "\0") || strlen($a) > 8192) apiError('Invalid WP-CLI argument');
    }
    return agent('wp-cli', array_merge([$domain], array_map('strval', $args)), $timeout);
}
function wpOutput(array $r): string { return (string)($r['output'] ?? ''); }
function wpJson(array $r): array {
    $d = json_decode(trim(wpOutput($r)), true);
    return is_array($d) ? $d : [];
}
function wpRequire(array $r, string $what): void {
    if (!empty($r['success'])) return;
    $msg = trim(wpOutput($r));
    if ($msg === '') $msg = (string)($r['error'] ?? 'unknown error');
    apiError("{$what} failed: " . substr($msg, 0, 2000));
}
/** Minimal shell-like tokenizer (quotes + backslash), no expansion of any kind. */
function tokenize(string $cmd): array {
    $tokens = []; $cur = ''; $quote = null; $has = false; $len = strlen($cmd);
    for ($i = 0; $i < $len; $i++) {
        $c = $cmd[$i];
        if ($quote !== null) {
            if ($c === $quote) { $quote = null; }
            elseif ($c === '\\' && $quote === '"' && $i + 1 < $len) { $cur .= $cmd[++$i]; }
            else { $cur .= $c; }
            continue;
        }
        if ($c === '"' || $c === "'") { $quote = $c; $has = true; continue; }
        if ($c === '\\' && $i + 1 < $len) { $cur .= $cmd[++$i]; $has = true; continue; }
        if (ctype_space($c)) { if ($cur !== '' || $has) { $tokens[] = $cur; $cur = ''; $has = false; } continue; }
        $cur .= $c; $has = true;
    }
    if ($quote !== null) apiError('Unbalanced quotes in command');
    if ($cur !== '' || $has) $tokens[] = $cur;
    return $tokens;
}
function runWpCommand(string $domain, string $command): array {
    $blockedPhrases = ['eval', 'eval-file', 'shell', 'db drop', 'db reset', 'db clean', 'db create', 'package', 'cli '];
    foreach ($blockedPhrases as $b) {
        if (stripos(' ' . $command . ' ', ' ' . $b . ' ') !== false) apiError("Command blocked: {$b}");
    }
    $argv = tokenize($command);
    if (!$argv) apiError('Command required');
    $allowed = ['plugin', 'theme', 'cache', 'option', 'post', 'user', 'db', 'search-replace', 'media', 'menu', 'widget',
                'cron', 'transient', 'rewrite', 'term', 'comment', 'core', 'config', 'cap', 'role', 'language',
                'maintenance-mode', 'site', 'sidebar', 'taxonomy', 'post-type', 'export', 'import', 'redis', 'nginx-helper'];
    if (!in_array($argv[0], $allowed, true)) apiError("Command not allowed: {$argv[0]}");
    return wp($domain, $argv);
}

//=============================================================================
// WORDPRESS.ORG DIRECTORY
//=============================================================================
function fetchWpOrgApi(string $type, array $params): ?array {
    $url = "https://api.wordpress.org/{$type}/info/1.2/?" . http_build_query($params);
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_USERAGENT => 'Flyne Engine/' . FLYNE_VERSION, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode !== 200 || !is_string($response)) return null;
    $d = json_decode($response, true);
    return is_array($d) ? $d : null;
}
function searchDirectory(string $type, string $query, int $page, int $perPage): ?array {
    $params = [
        'action' => $type === 'plugins' ? 'query_plugins' : 'query_themes',
        'request[page]' => $page, 'request[per_page]' => $perPage,
        'request[fields][active_installs]' => 'true', 'request[fields][rating]' => 'true',
        'request[fields][num_ratings]' => 'true', 'request[fields][sections]' => 'false',
        'request[fields][versions]' => 'false',
    ];
    if ($type === 'plugins') {
        $params += ['request[fields][icons]' => 'true', 'request[fields][short_description]' => 'true',
                    'request[fields][tested]' => 'true', 'request[fields][requires]' => 'true'];
    } else {
        $params += ['request[fields][screenshot_url]' => 'true', 'request[fields][description]' => 'true'];
    }
    if ($query !== '') $params['request[search]'] = $query; else $params['request[browse]'] = 'popular';
    return fetchWpOrgApi($type, $params);
}

//=============================================================================
// LOCAL (unprivileged) SYSTEM INFO
//=============================================================================
function readProcFile(string $path): string {
    $c = @file_get_contents($path);
    return is_string($c) ? $c : '';
}
function siteHttpCheck(string $domain, bool $ssl): array {
    $scheme = $ssl ? 'https' : 'http';
    $port = $ssl ? 443 : 80;
    $ch = curl_init("{$scheme}://{$domain}/");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 12, CURLOPT_NOBODY => false,
        CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RESOLVE => ["{$domain}:{$port}:127.0.0.1", "{$domain}:443:127.0.0.1", "{$domain}:80:127.0.0.1"],
        CURLOPT_USERAGENT => 'Flyne-HealthCheck/' . FLYNE_VERSION,
    ]);
    curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $time = (float)curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);
    return ['http_status' => $code, 'response_time_ms' => (int)round($time * 1000), 'is_up' => $code >= 200 && $code < 400];
}
function fpmStatus(string $domain, bool $ssl): ?array {
    $scheme = $ssl ? 'https' : 'http';
    $ch = curl_init("{$scheme}://{$domain}/flyne-fpm-status?json");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RESOLVE => ["{$domain}:443:127.0.0.1", "{$domain}:80:127.0.0.1"],
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200 || !is_string($body)) return null;
    $d = json_decode($body, true);
    if (!is_array($d)) return null;
    return [
        'pool' => $d['pool'] ?? null, 'process_manager' => $d['process manager'] ?? null,
        'active_processes' => $d['active processes'] ?? null, 'idle_processes' => $d['idle processes'] ?? null,
        'total_processes' => $d['total processes'] ?? null, 'max_children_reached' => $d['max children reached'] ?? null,
        'slow_requests' => $d['slow requests'] ?? null, 'accepted_conn' => $d['accepted conn'] ?? null,
        'listen_queue' => $d['listen queue'] ?? null,
    ];
}

//=============================================================================
// MAIN ROUTER
//=============================================================================
authenticate($CFG);

$action = (string)param('action', '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$MUTATING = [
    'create_site', 'site_create', 'delete_site', 'site_delete', 'php_restart',
    'sftp_enable', 'sftp_create', 'sftp_disable', 'sftp_reset_password',
    'cache_flush', 'cache_purge', 'wp_cache_flush', 'wp_cli', 'wpcli',
    'plugin_install', 'wp_plugin_install', 'plugin_activate', 'wp_plugin_activate', 'plugin_deactivate', 'wp_plugin_deactivate',
    'plugin_delete', 'wp_plugin_delete', 'plugin_update', 'wp_plugin_update',
    'theme_install', 'wp_theme_install', 'theme_activate', 'wp_theme_activate', 'theme_delete', 'wp_theme_delete', 'theme_update', 'wp_theme_update',
    'user_create', 'wp_user_create', 'user_delete', 'wp_user_delete', 'user_update', 'wp_user_update', 'user_reset_password',
    'wp_core_update', 'core_update', 'wp_db_optimize', 'db_optimize', 'wp_db_repair', 'db_repair',
    'wp_search_replace', 'search_replace', 'wp_transient_delete', 'transient_delete',
    'ssl_enable', 'ssl_install', 'ssl_renew', 'maintenance_enable', 'maintenance_disable', 'option_update', 'wp_option_update',
    'site_suspend', 'site_unsuspend', 'site_limits_set', 'backup_create', 'backup_restore', 'backup_delete', 'site_render',
];
if (in_array($action, $MUTATING, true) && $method !== 'POST') {
    apiError('This action requires a POST request', 405);
}

try {
    switch ($action) {

        //=====================================================================
        // SITE MANAGEMENT
        //=====================================================================
        case 'create_site':
        case 'site_create':
            $domain = vDomain();
            if (getSite($domain)) apiError('Site already exists', 409);
            $phpVersion = vPhp((string)param('php_version', (string)($CFG['default_php'] ?? '8.4')));
            $adminEmail = (string)param('admin_email', "admin@{$domain}");
            $title      = (string)param('title', $domain);
            $adminUser  = (string)param('admin_user', 'admin');
            $plan       = (string)param('plan', 'standard');
            if (!filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) apiError('Invalid admin email');
            if (!preg_match('/^[a-zA-Z0-9._@-]{1,60}$/', $adminUser)) apiError('Invalid admin username');
            if (strlen($title) > 200 || str_contains($title, "\0")) apiError('Invalid title');
            if (!preg_match('/^[a-z0-9_-]{1,32}$/', $plan)) apiError('Invalid plan');

            $result = agent('create-site', [$domain, $phpVersion, $adminEmail, $title, $adminUser, $plan], 900);
            if (!empty($result['success'])) {
                $site = getSite($domain);
                logActivity($site['id'] ?? null, 'site_created', ['domain' => $domain, 'php' => $phpVersion]);
                apiSuccess(agentData($result), 'Site created successfully');
            }
            apiError((string)($result['error'] ?? 'Site creation failed'), 500);

        case 'delete_site':
        case 'site_delete':
            $domain = vDomain();
            $site = requireSite($domain);
            $args = [$domain];
            if (flag('keep_backups', false)) $args[] = '--keep-backups';
            if (flag('final_backup', false)) $args[] = '--final-backup';
            $result = agent('delete-site', $args, 900);
            if (!empty($result['success'])) {
                logActivity(null, 'site_deleted', ['domain' => $domain]);
                apiSuccess([], (string)($result['message'] ?? 'Site deleted'));
            }
            apiError((string)($result['error'] ?? 'Delete failed'), 500);

        case 'site_list':
        case 'list_sites':
            $status = param('status');
            $sql = 'SELECT id, domain, php_version, status, ssl_enabled, plan, wp_admin_user, wp_admin_email,
                           cpu_quota, memory_max_mb, php_max_children, disk_quota_mb, disk_used_mb, db_used_mb,
                           created_at, updated_at FROM sites';
            $params = [];
            if ($status !== null && $status !== '') {
                if (!in_array($status, ['creating', 'active', 'suspended', 'error', 'deleting'], true)) apiError('Invalid status filter');
                $sql .= ' WHERE status = ?';
                $params[] = $status;
            }
            $sql .= ' ORDER BY created_at DESC';
            $stmt = db()->prepare($sql);
            $stmt->execute($params);
            $sites = array_map('publicSite', $stmt->fetchAll());
            apiSuccess(['sites' => $sites, 'count' => count($sites)]);

        case 'site_info':
        case 'site_details':
            $domain = vDomain();
            $site = requireSite($domain);
            $stmt = db()->prepare('SELECT sftp_user, is_enabled, expires_at FROM sftp_access WHERE site_id = ?');
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            $out = publicSite($site);
            $out['disk_usage_mb'] = (int)$site['disk_used_mb'];
            if (flag('live', false)) {
                $usage = agent('site-inspect', [$domain, 'disk-usage'], 120);
                if (!empty($usage['success'])) {
                    $out['disk_usage_mb'] = (int)(agentData($usage)['total_mb'] ?? $out['disk_usage_mb']);
                    $out['usage'] = agentData($usage);
                }
            }
            $out['sftp'] = $sftp ? ['sftp_user' => $sftp['sftp_user'], 'is_enabled' => (bool)$sftp['is_enabled'], 'expires_at' => $sftp['expires_at']] : null;
            $out['php_socket'] = PHP_SOCK_DIR . "/{$domain}/php.sock";
            $out['url'] = ($site['ssl_enabled'] ? 'https' : 'http') . "://{$domain}";
            apiSuccess(['site' => $out]);

        case 'site_render':
            $domain = vDomain(); requireSite($domain);
            $data = agentOrFail('render-site', [$domain], 'Render failed', 300);
            apiSuccess($data, 'Site configuration regenerated');

        case 'site_suspend':
            $domain = vDomain(); $site = requireSite($domain);
            $reason = substr((string)param('reason', 'manual'), 0, 200);
            if (!preg_match('/^[\w .,:;()\-]*$/u', $reason)) apiError('Invalid reason');
            $data = agentOrFail('site-suspend', [$domain, $reason], 'Suspend failed', 300);
            logActivity((int)$site['id'], 'site_suspended', ['reason' => $reason]);
            apiSuccess($data, 'Site suspended');

        case 'site_unsuspend':
            $domain = vDomain(); $site = requireSite($domain);
            $data = agentOrFail('site-unsuspend', [$domain], 'Unsuspend failed', 300);
            logActivity((int)$site['id'], 'site_unsuspended', []);
            apiSuccess($data, 'Site reactivated');

        case 'site_limits':
        case 'site_limits_set':
            $domain = vDomain(); $site = requireSite($domain);
            $keys = ['cpu_quota', 'memory_max_mb', 'php_max_children', 'php_memory_limit_mb', 'php_opcache_mb',
                     'php_upload_mb', 'php_max_execution', 'php_pm', 'php_allow_exec', 'redis_max_mb',
                     'disk_quota_mb', 'db_max_connections', 'xmlrpc', 'cache_enabled', 'cache_ttl'];
            $pairs = [];
            if ($method === 'POST') {
                foreach ($keys as $k) {
                    $v = param($k);
                    if ($v === null || $v === '') continue;
                    if (!preg_match('/^[a-z0-9]{1,12}$/', $v)) apiError("Invalid value for {$k}");
                    $pairs[] = "{$k}={$v}";
                }
            }
            $data = agentOrFail('site-limits', array_merge([$domain], $pairs), 'Applying limits failed', 300);
            if ($pairs) logActivity((int)$site['id'], 'site_limits_changed', ['changes' => $pairs]);
            apiSuccess($data, $pairs ? 'Limits applied' : 'Current limits');

        //=====================================================================
        // PHP VERSION MANAGEMENT
        //=====================================================================
        case 'php_switch':
        case 'php_version':
            $domain = vDomain();
            $site = requireSite($domain);
            $version = (string)param('version', '');
            if ($version === '' || $method !== 'POST') {
                apiSuccess(['php_version' => $site['php_version'], 'available' => $CFG['php_versions'] ?? []]);
            }
            vPhp($version);
            $result = agent('php-switch', [$domain, $version], 180);
            if (!empty($result['success'])) {
                logActivity((int)$site['id'], 'php_switched', ['from' => $site['php_version'], 'to' => $version]);
                $d = agentData($result);
                apiSuccess(['old_version' => $d['old_version'] ?? $site['php_version'], 'new_version' => $d['new_version'] ?? $version],
                    (string)($result['message'] ?? 'PHP version changed'));
            }
            apiError((string)($result['error'] ?? 'PHP switch failed'), 500);

        case 'php_restart':
            $domain = vDomain(); $site = requireSite($domain);
            $args = [$domain];
            if (flag('hard', false)) $args[] = '--hard';
            $data = agentOrFail('php-restart', $args, 'PHP restart failed', 120);
            logActivity((int)$site['id'], 'php_restarted', $data);
            apiSuccess($data, 'PHP-FPM restarted');

        //=====================================================================
        // SFTP MANAGEMENT
        //=====================================================================
        case 'sftp_enable':
        case 'sftp_create':
        case 'sftp_reset_password':
            $domain = vDomain(); $site = requireSite($domain);
            $expire = (string)param('expire', 'never');
            if (!preg_match('/^(never|\d{1,4}[hd])$/', $expire)) apiError('Invalid expiry (never, 1h, 24h, 7d, 30d)');
            $data = agentOrFail('sftp-enable', [$domain, $expire], 'SFTP enable failed', 120);
            logActivity((int)$site['id'], $action === 'sftp_reset_password' ? 'sftp_password_reset' : 'sftp_enabled', ['expire' => $expire]);
            apiSuccess($data, $action === 'sftp_reset_password' ? 'SFTP password reset' : 'SFTP access enabled');

        case 'sftp_disable':
            $domain = vDomain(); $site = requireSite($domain);
            agentOrFail('sftp-disable', [$domain], 'SFTP disable failed', 120);
            logActivity((int)$site['id'], 'sftp_disabled', []);
            apiSuccess([], 'SFTP access disabled');

        case 'sftp_status':
        case 'sftp_info':
            $domain = vDomain(); $site = requireSite($domain);
            $stmt = db()->prepare('SELECT * FROM sftp_access WHERE site_id = ?');
            $stmt->execute([$site['id']]);
            $sftp = $stmt->fetch();
            if (!$sftp) apiSuccess(['configured' => false, 'enabled' => false]);
            apiSuccess([
                'configured' => true, 'enabled' => (bool)$sftp['is_enabled'], 'username' => $sftp['sftp_user'],
                'host' => $CFG['server_ip'] ?? gethostname(), 'hostname' => $CFG['hostname'] ?? gethostname(),
                'port' => 22, 'path' => '/public', 'expires_at' => $sftp['expires_at'], 'created_at' => $sftp['created_at'],
            ]);

        //=====================================================================
        // CACHE
        //=====================================================================
        case 'cache_flush':
        case 'cache_purge':
        case 'wp_cache_flush':
            $domainRaw = (string)param('domain', '');
            if ($domainRaw === '') {
                $data = agentOrFail('cache-purge', [], 'Cache purge failed', 120);
                logActivity(null, 'cache_purged_all', []);
                apiSuccess($data, 'Page cache purged for all sites');
            }
            $domain = vDomain(); $site = requireSite($domain);
            $data = agentOrFail('cache-purge', [$domain], 'Cache purge failed', 120);
            logActivity((int)$site['id'], 'cache_flushed', []);
            apiSuccess($data, 'Cache purged');

        //=====================================================================
        // GENERIC WP-CLI
        //=====================================================================
        case 'wp_cli':
        case 'wpcli':
            $domain = vDomain(); $site = requireSite($domain);
            $command = (string)param('command', '');
            if ($command === '') apiError('Command required');
            if (strlen($command) > 8192) apiError('Command too long');
            $result = runWpCommand($domain, $command);
            apiSuccess(['success' => !empty($result['success']), 'exit_code' => $result['exit_code'] ?? null, 'output' => wpOutput($result)]);

        //=====================================================================
        // PLUGINS
        //=====================================================================
        case 'plugin_list':
        case 'wp_plugin_list':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['plugin', 'list', '--format=json', '--fields=name,status,update,version,update_version,title,auto_update']);
            wpRequire($r, 'Plugin list');
            $plugins = wpJson($r);
            foreach ($plugins as &$p) {
                $slug = (string)($p['name'] ?? '');
                if ($slug !== '' && preg_match('/^[a-z0-9._-]+$/i', $slug)) {
                    $p['slug'] = $slug;
                    $p['icons'] = ['1x' => "https://ps.w.org/{$slug}/assets/icon-128x128.png", '2x' => "https://ps.w.org/{$slug}/assets/icon-256x256.png"];
                }
            }
            unset($p);
            apiSuccess(['plugins' => $plugins]);

        case 'plugin_install':
        case 'wp_plugin_install':
            $domain = vDomain(); $site = requireSite($domain);
            $plugin = vPackageRef((string)param('plugin', (string)param('slug', '')), 'plugin');
            $args = ['plugin', 'install', $plugin];
            if (flag('activate', true)) $args[] = '--activate';
            if (flag('force', false)) $args[] = '--force';
            $r = wp($domain, $args, 300);
            wpRequire($r, 'Plugin install');
            logActivity((int)$site['id'], 'plugin_install', ['plugin' => $plugin]);
            apiSuccess(['output' => wpOutput($r)], 'Plugin installed');

        case 'plugin_activate':
        case 'wp_plugin_activate':
        case 'plugin_deactivate':
        case 'wp_plugin_deactivate':
        case 'plugin_delete':
        case 'wp_plugin_delete':
            $domain = vDomain(); $site = requireSite($domain);
            $plugin = vSlug((string)param('plugin', (string)param('slug', '')), 'plugin slug');
            $verb = str_contains($action, 'deactivate') ? 'deactivate' : (str_contains($action, 'delete') ? 'delete' : 'activate');
            $r = wp($domain, ['plugin', $verb, $plugin]);
            wpRequire($r, 'Plugin ' . $verb);
            logActivity((int)$site['id'], 'plugin_' . $verb, ['plugin' => $plugin]);
            apiSuccess(['output' => wpOutput($r)], "Plugin {$verb}d");

        case 'plugin_update':
        case 'wp_plugin_update':
            $domain = vDomain(); $site = requireSite($domain);
            $plugin = (string)param('plugin', (string)param('slug', 'all'));
            $args = $plugin === 'all' ? ['plugin', 'update', '--all'] : ['plugin', 'update', vSlug($plugin, 'plugin slug')];
            $r = wp($domain, $args, 600);
            wpRequire($r, 'Plugin update');
            logActivity((int)$site['id'], 'plugin_update', ['plugin' => $plugin]);
            agent('cache-purge', [$domain], 60);
            apiSuccess(['output' => wpOutput($r)], 'Plugin(s) updated');

        case 'plugin_search':
        case 'wp_plugin_search':
        case 'plugin_popular':
        case 'wp_plugin_popular':
            $query = str_contains($action, 'popular') ? '' : (string)param('query', '');
            $page = paramInt('page', 1, 1, 1000);
            $perPage = paramInt('per_page', 12, 1, 100);
            if (!str_contains($action, 'popular') && strlen($query) < 2) apiError('Query must be at least 2 characters');
            $result = searchDirectory('plugins', $query, $page, $perPage);
            if (!$result || !isset($result['plugins'])) apiError('Failed to query the WordPress.org plugin directory', 502);
            apiSuccess(['plugins' => $result['plugins'], 'total' => $result['info']['results'] ?? 0,
                        'total_pages' => $result['info']['pages'] ?? 1, 'page' => $page]);

        //=====================================================================
        // THEMES
        //=====================================================================
        case 'theme_list':
        case 'wp_theme_list':
            $domain = vDomain(); $site = requireSite($domain);
            $r = wp($domain, ['theme', 'list', '--format=json', '--fields=name,status,update,version,update_version,title,auto_update']);
            wpRequire($r, 'Theme list');
            $themes = wpJson($r);
            $shots = agentData(agent('site-inspect', [$domain, 'theme-screenshots'], 60))['screenshots'] ?? [];
            foreach ($themes as &$t) {
                $name = (string)($t['name'] ?? '');
                $t['slug'] = $name;
                $t['screenshot_url'] = $shots[$name] ?? null;
            }
            unset($t);
            apiSuccess(['themes' => $themes]);

        case 'theme_install':
        case 'wp_theme_install':
            $domain = vDomain(); $site = requireSite($domain);
            $theme = vPackageRef((string)param('theme', (string)param('slug', '')), 'theme');
            $args = ['theme', 'install', $theme];
            if (flag('activate', false)) $args[] = '--activate';
            $r = wp($domain, $args, 300);
            wpRequire($r, 'Theme install');
            logActivity((int)$site['id'], 'theme_install', ['theme' => $theme]);
            apiSuccess(['output' => wpOutput($r)], 'Theme installed');

        case 'theme_activate':
        case 'wp_theme_activate':
        case 'theme_delete':
        case 'wp_theme_delete':
            $domain = vDomain(); $site = requireSite($domain);
            $theme = vSlug((string)param('theme', (string)param('slug', '')), 'theme slug');
            $verb = str_contains($action, 'delete') ? 'delete' : 'activate';
            $r = wp($domain, ['theme', $verb, $theme]);
            wpRequire($r, 'Theme ' . $verb);
            logActivity((int)$site['id'], 'theme_' . $verb, ['theme' => $theme]);
            if ($verb === 'activate') agent('cache-purge', [$domain], 60);
            apiSuccess(['output' => wpOutput($r)], "Theme {$verb}d");

        case 'theme_update':
        case 'wp_theme_update':
            $domain = vDomain(); $site = requireSite($domain);
            $theme = (string)param('theme', (string)param('slug', 'all'));
            $args = $theme === 'all' ? ['theme', 'update', '--all'] : ['theme', 'update', vSlug($theme, 'theme slug')];
            $r = wp($domain, $args, 600);
            wpRequire($r, 'Theme update');
            logActivity((int)$site['id'], 'theme_update', ['theme' => $theme]);
            agent('cache-purge', [$domain], 60);
            apiSuccess(['output' => wpOutput($r)], 'Theme(s) updated');

        case 'theme_search':
        case 'wp_theme_search':
        case 'theme_popular':
        case 'wp_theme_popular':
            $query = str_contains($action, 'popular') ? '' : (string)param('query', '');
            $page = paramInt('page', 1, 1, 1000);
            $perPage = paramInt('per_page', 12, 1, 100);
            if (!str_contains($action, 'popular') && strlen($query) < 2) apiError('Query must be at least 2 characters');
            $result = searchDirectory('themes', $query, $page, $perPage);
            if (!$result || !isset($result['themes'])) apiError('Failed to query the WordPress.org theme directory', 502);
            apiSuccess(['themes' => $result['themes'], 'total' => $result['info']['results'] ?? 0,
                        'total_pages' => $result['info']['pages'] ?? 1, 'page' => $page]);

        //=====================================================================
        // USERS
        //=====================================================================
        case 'user_list':
        case 'wp_user_list':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['user', 'list', '--format=json', '--fields=ID,user_login,display_name,user_email,user_registered,roles']);
            wpRequire($r, 'User list');
            apiSuccess(['users' => wpJson($r)]);

        case 'user_create':
        case 'wp_user_create':
            $domain = vDomain(); $site = requireSite($domain);
            $username = (string)param('username', '');
            $email = (string)param('email', '');
            $role = (string)param('role', 'editor');
            $password = (string)param('password', '');
            if ($username === '' || $email === '') apiError('Username and email required');
            if (!preg_match('/^[a-zA-Z0-9 _.\-@]{1,60}$/', $username)) apiError('Invalid username');
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) apiError('Invalid email format');
            $allowedRoles = ['subscriber', 'contributor', 'author', 'editor', 'administrator', 'shop_manager', 'customer'];
            if (!in_array($role, $allowedRoles, true)) apiError('Invalid role. Allowed: ' . implode(', ', $allowedRoles));
            $generated = false;
            if ($password === '') { $password = bin2hex(random_bytes(10)); $generated = true; }
            if (strlen($password) < 8 || strlen($password) > 128) apiError('Password must be 8-128 characters');
            $r = wp($domain, ['user', 'create', $username, $email, "--role={$role}", "--user_pass={$password}", '--porcelain']);
            wpRequire($r, 'User create');
            logActivity((int)$site['id'], 'user_create', ['username' => $username, 'role' => $role]);
            $out = ['output' => wpOutput($r), 'user_id' => (int)trim(wpOutput($r))];
            if ($generated) $out['password'] = $password;
            apiSuccess($out, 'User created');

        case 'user_delete':
        case 'wp_user_delete':
            $domain = vDomain(); $site = requireSite($domain);
            $userId = vUserRef((string)param('user_id', (string)param('user', '')));
            $reassign = (string)param('reassign', '');
            $args = ['user', 'delete', $userId, '--yes'];
            if ($reassign !== '') { if (!ctype_digit($reassign)) apiError('reassign must be a user ID'); $args[] = "--reassign={$reassign}"; }
            $r = wp($domain, $args);
            wpRequire($r, 'User delete');
            logActivity((int)$site['id'], 'user_delete', ['user' => $userId]);
            apiSuccess(['output' => wpOutput($r)], 'User deleted');

        case 'user_update':
        case 'wp_user_update':
            $domain = vDomain(); $site = requireSite($domain);
            $userId = vUserRef((string)param('user_id', (string)param('user', '')));
            $args = ['user', 'update', $userId];
            $email = (string)param('email', '');
            if ($email !== '') { if (!filter_var($email, FILTER_VALIDATE_EMAIL)) apiError('Invalid email'); $args[] = "--user_email={$email}"; }
            $role = (string)param('role', '');
            if ($role !== '') { if (!preg_match('/^[a-z_]{1,40}$/', $role)) apiError('Invalid role'); $args[] = "--role={$role}"; }
            $display = (string)param('display_name', '');
            if ($display !== '') { if (strlen($display) > 120 || str_contains($display, "\0")) apiError('Invalid display name'); $args[] = "--display_name={$display}"; }
            if (count($args) === 3) apiError('No fields to update');
            $r = wp($domain, $args);
            wpRequire($r, 'User update');
            logActivity((int)$site['id'], 'user_update', ['user' => $userId]);
            apiSuccess(['output' => wpOutput($r)], 'User updated');

        case 'user_reset_password':
            $domain = vDomain(); $site = requireSite($domain);
            $userId = vUserRef((string)param('user_id', (string)param('user', '')));
            $newPassword = (string)param('password', '');
            if ($newPassword === '') $newPassword = bin2hex(random_bytes(10));
            if (strlen($newPassword) < 8 || strlen($newPassword) > 128) apiError('Password must be 8-128 characters');
            $r = wp($domain, ['user', 'update', $userId, "--user_pass={$newPassword}", '--skip-email']);
            wpRequire($r, 'Password reset');
            logActivity((int)$site['id'], 'user_password_reset', ['user' => $userId]);
            apiSuccess(['output' => wpOutput($r), 'new_password' => $newPassword], 'Password reset');

        //=====================================================================
        // WORDPRESS CORE
        //=====================================================================
        case 'wp_core_version':
        case 'core_version':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['core', 'version']);
            wpRequire($r, 'Core version');
            apiSuccess(['version' => trim(wpOutput($r))]);

        case 'wp_core_update':
        case 'core_update':
            $domain = vDomain(); $site = requireSite($domain);
            $args = ['core', 'update'];
            $version = (string)param('version', '');
            if ($version !== '') { if (!preg_match('/^\d+\.\d+(\.\d+)?$/', $version)) apiError('Invalid version'); $args[] = "--version={$version}"; }
            $r = wp($domain, $args, 600);
            wpRequire($r, 'Core update');
            $r2 = wp($domain, ['core', 'update-db'], 600);
            logActivity((int)$site['id'], 'core_update', ['version' => $version ?: 'latest']);
            agent('cache-purge', [$domain], 60);
            apiSuccess(['output' => wpOutput($r) . "\n" . wpOutput($r2)], 'WordPress core updated');

        case 'wp_core_check_update':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['core', 'check-update', '--format=json']);
            apiSuccess(['updates' => wpJson($r)]);

        //=====================================================================
        // DATABASE
        //=====================================================================
        case 'db_info':
        case 'pma_login':
            $domain = vDomain(); $site = requireSite($domain);
            logActivity((int)$site['id'], 'db_credentials_viewed', []);
            apiSuccess([
                'db_name' => $site['db_name'], 'db_user' => $site['db_user'], 'db_pass' => $site['db_pass'],
                'db_host' => 'localhost', 'db_size_mb' => (int)$site['db_used_mb'],
                'pma_url' => !empty($CFG['pma_domain']) ? 'https://' . $CFG['pma_domain'] . '/' : null,
            ]);

        case 'wp_db_optimize':
        case 'db_optimize':
        case 'wp_db_repair':
        case 'db_repair':
            $domain = vDomain(); $site = requireSite($domain);
            $verb = str_contains($action, 'repair') ? 'repair' : 'optimize';
            $r = wp($domain, ['db', $verb], 600);
            wpRequire($r, 'Database ' . $verb);
            logActivity((int)$site['id'], 'db_' . $verb, []);
            apiSuccess(['output' => wpOutput($r)], "Database {$verb} completed");

        case 'wp_search_replace':
        case 'search_replace':
            $domain = vDomain(); $site = requireSite($domain);
            $search = vNoFlag((string)param('search', ''), 'search value');
            $replace = vNoFlag((string)param('replace', ''), 'replace value');
            $dryRun = flag('dry_run', true);
            $args = ['search-replace', $search, $replace, '--all-tables-with-prefix', '--skip-columns=guid', '--report-changed-only'];
            if ($dryRun) $args[] = '--dry-run';
            $r = wp($domain, $args, 900);
            wpRequire($r, 'Search-replace');
            if (!$dryRun) { logActivity((int)$site['id'], 'search_replace', ['search' => $search, 'replace' => $replace]); agent('cache-purge', [$domain], 60); }
            apiSuccess(['output' => wpOutput($r), 'dry_run' => $dryRun], $dryRun ? 'Dry run completed' : 'Search and replace completed');

        case 'wp_transient_delete':
        case 'transient_delete':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['transient', 'delete', '--all']);
            wpRequire($r, 'Transient delete');
            apiSuccess(['output' => wpOutput($r)], 'Transients deleted');

        //=====================================================================
        // SSL
        //=====================================================================
        case 'ssl_enable':
        case 'ssl_install':
        case 'ssl_renew':
            $domain = vDomain(); $site = requireSite($domain);
            $result = agent('ssl-issue', [$domain], 300);
            if (!empty($result['success'])) {
                logActivity((int)$site['id'], 'ssl_enabled', []);
                apiSuccess(agentData($result), (string)($result['message'] ?? 'SSL certificate installed'));
            }
            apiError((string)($result['error'] ?? 'SSL installation failed'), 500);

        case 'ssl_status':
            $domain = vDomain(); $site = requireSite($domain);
            $data = agentOrFail('ssl-status', [$domain], 'SSL status failed', 60);
            apiSuccess($data);

        //=====================================================================
        // DISK / RESOURCES
        //=====================================================================
        case 'disk_usage':
            $domain = vDomain(); $site = requireSite($domain);
            $d = agentOrFail('site-inspect', [$domain, 'disk-usage'], 'Disk usage failed', 180);
            apiSuccess(['total_mb' => (int)($d['total_mb'] ?? 0), 'quota_mb' => (int)($d['quota_mb'] ?? $site['disk_quota_mb']),
                        'db_mb' => (int)($d['db_mb'] ?? 0), 'backups_mb' => (int)($d['backups_mb'] ?? 0), 'breakdown' => $d['breakdown'] ?? []]);

        case 'site_logs':
            $domain = vDomain(); requireSite($domain);
            $type = (string)param('type', 'error');
            if (!in_array($type, ['access', 'error', 'php-error', 'php-slow', 'php-fpm', 'wp-cron'], true)) apiError('Invalid log type');
            $lines = paramInt('lines', 100, 1, 2000);
            $data = agentOrFail('site-inspect', [$domain, 'logs', $type, (string)$lines], 'Log read failed', 60);
            apiSuccess($data);

        //=====================================================================
        // BACKUPS
        //=====================================================================
        case 'backup_create':
            $domain = vDomain(); $site = requireSite($domain);
            $type = (string)param('type', 'full');
            if (!in_array($type, ['full', 'files', 'database'], true)) apiError('Invalid backup type');
            $note = substr((string)param('note', 'manual'), 0, 200);
            if (!preg_match('/^[A-Za-z0-9._ -]*$/', $note)) apiError('Invalid note');
            $data = agentOrFail('backup-create', [$domain, $type, $note], 'Backup failed', 900);
            logActivity((int)$site['id'], 'backup_created', ['type' => $type, 'backup_id' => $data['backup_id'] ?? null]);
            apiSuccess($data, 'Backup completed');

        case 'backup_list':
            $domain = vDomain(); requireSite($domain);
            apiSuccess(agentOrFail('backup-list', [$domain], 'Backup list failed', 60));

        case 'backup_restore':
            $domain = vDomain(); $site = requireSite($domain);
            $id = paramInt('backup_id', 0, 1, PHP_INT_MAX);
            if ($id < 1) apiError('backup_id required');
            $scope = (string)param('scope', 'full');
            if (!in_array($scope, ['full', 'files', 'database'], true)) apiError('Invalid restore scope');
            $data = agentOrFail('backup-restore', [$domain, (string)$id, $scope], 'Restore failed', 900);
            logActivity((int)$site['id'], 'backup_restored', ['backup_id' => $id, 'scope' => $scope]);
            apiSuccess($data, 'Backup restored');

        case 'backup_delete':
            $domain = vDomain(); $site = requireSite($domain);
            $id = paramInt('backup_id', 0, 1, PHP_INT_MAX);
            if ($id < 1) apiError('backup_id required');
            $data = agentOrFail('backup-delete', [$domain, (string)$id], 'Backup delete failed', 60);
            logActivity((int)$site['id'], 'backup_deleted', ['backup_id' => $id]);
            apiSuccess($data, 'Backup deleted');

        //=====================================================================
        // MAINTENANCE MODE
        //=====================================================================
        case 'maintenance_enable':
        case 'maintenance_disable':
            $domain = vDomain(); $site = requireSite($domain);
            $verb = $action === 'maintenance_enable' ? 'activate' : 'deactivate';
            $r = wp($domain, ['maintenance-mode', $verb]);
            wpRequire($r, 'Maintenance mode');
            logActivity((int)$site['id'], 'maintenance_' . $verb, []);
            agent('cache-purge', [$domain], 60);
            apiSuccess(['output' => wpOutput($r)], $verb === 'activate' ? 'Maintenance mode enabled' : 'Maintenance mode disabled');

        case 'maintenance_status':
            $domain = vDomain(); requireSite($domain);
            $r = wp($domain, ['maintenance-mode', 'status']);
            apiSuccess(['active' => stripos(wpOutput($r), 'is active') !== false]);

        //=====================================================================
        // OPTIONS
        //=====================================================================
        case 'option_get':
        case 'wp_option_get':
            $domain = vDomain(); requireSite($domain);
            $option = vOptionName((string)param('option', ''));
            $r = wp($domain, ['option', 'get', $option, '--format=json']);
            $raw = trim(wpOutput($r));
            $decoded = json_decode($raw, true);
            apiSuccess(['option' => $option, 'value' => json_last_error() === JSON_ERROR_NONE ? $decoded : $raw, 'found' => !empty($r['success'])]);

        case 'option_update':
        case 'wp_option_update':
            $domain = vDomain(); $site = requireSite($domain);
            $option = vOptionName((string)param('option', ''));
            $value = vNoFlag((string)param('value', ''), 'value');
            $args = ['option', 'update', $option, $value];
            if (flag('json', false)) $args[] = '--format=json';
            $r = wp($domain, $args);
            wpRequire($r, 'Option update');
            logActivity((int)$site['id'], 'option_update', ['option' => $option]);
            apiSuccess(['output' => wpOutput($r)], 'Option updated');

        //=====================================================================
        // HEALTH
        //=====================================================================
        case 'site_health':
        case 'health_check':
            $domain = vDomain(); $site = requireSite($domain);
            $ssl = (bool)$site['ssl_enabled'];
            $checks = siteHttpCheck($domain, $ssl);
            $checks['php_fpm_socket'] = file_exists(PHP_SOCK_DIR . "/{$domain}/php.sock");
            $checks['php_fpm'] = fpmStatus($domain, $ssl);
            $checks['status'] = $site['status'];
            $checks['php_version'] = $site['php_version'];
            if ($site['status'] === 'active') {
                $v = wp($domain, ['core', 'version'], 60);
                $checks['wordpress_version'] = trim(wpOutput($v));
                $u = wp($domain, ['core', 'check-update', '--format=json'], 60);
                $checks['core_update_available'] = count(wpJson($u)) > 0;
            }
            apiSuccess(['health' => $checks]);

        //=====================================================================
        // ACTIVITY LOGS
        //=====================================================================
        case 'activity_log':
        case 'logs':
            $siteId = null;
            $domainRaw = (string)param('domain', '');
            if ($domainRaw !== '') { $siteId = (int)requireSite(vDomain())['id']; }
            $limit = paramInt('limit', 50, 1, 500);
            $offset = paramInt('offset', 0, 0, 1000000);
            $sql = 'SELECT id, site_id, action, details, ip_address, created_at FROM activity_logs';
            $params = [];
            if ($siteId !== null) { $sql .= ' WHERE site_id = ?'; $params[] = $siteId; }
            $sql .= ' ORDER BY id DESC LIMIT ? OFFSET ?';
            $stmt = db()->prepare($sql);
            $i = 1;
            foreach ($params as $p) $stmt->bindValue($i++, $p, PDO::PARAM_INT);
            $stmt->bindValue($i++, $limit, PDO::PARAM_INT);
            $stmt->bindValue($i, $offset, PDO::PARAM_INT);
            $stmt->execute();
            $logs = $stmt->fetchAll();
            foreach ($logs as &$log) {
                if (!empty($log['details'])) { $d = json_decode((string)$log['details'], true); $log['details'] = $d ?? $log['details']; }
            }
            unset($log);
            apiSuccess(['logs' => $logs]);

        //=====================================================================
        // SYSTEM STATUS
        //=====================================================================
        case 'system_status':
            $info = ['hostname' => $CFG['hostname'] ?? gethostname(), 'server_ip' => $CFG['server_ip'] ?? null,
                     'api_version' => FLYNE_VERSION, 'api_php_version' => PHP_VERSION];
            $mem = [];
            foreach (explode("\n", readProcFile('/proc/meminfo')) as $line) {
                if (preg_match('/^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)/', $line, $m)) $mem[$m[1]] = (int)$m[2];
            }
            $info['memory_total_mb'] = intdiv($mem['MemTotal'] ?? 0, 1024);
            $info['memory_available_mb'] = intdiv($mem['MemAvailable'] ?? 0, 1024);
            $info['memory_used_mb'] = $info['memory_total_mb'] - $info['memory_available_mb'];
            $info['swap_used_mb'] = intdiv(($mem['SwapTotal'] ?? 0) - ($mem['SwapFree'] ?? 0), 1024);
            $load = explode(' ', trim(readProcFile('/proc/loadavg')));
            $info['load_average'] = [(float)($load[0] ?? 0), (float)($load[1] ?? 0), (float)($load[2] ?? 0)];
            $info['cpu_cores'] = preg_match_all('/^processor\s*:/m', readProcFile('/proc/cpuinfo'));
            $info['uptime_seconds'] = (int)(float)(explode(' ', readProcFile('/proc/uptime'))[0] ?? 0);
            $info['disk_total_gb'] = round((float)@disk_total_space('/') / 1073741824, 1);
            $info['disk_free_gb'] = round((float)@disk_free_space('/') / 1073741824, 1);
            $info['sites_dir_total_gb'] = round((float)@disk_total_space('/var/www') / 1073741824, 1);
            $info['sites_dir_free_gb'] = round((float)@disk_free_space('/var/www') / 1073741824, 1);
            try {
                $counts = db()->query('SELECT status, COUNT(*) AS c FROM sites GROUP BY status')->fetchAll();
                $info['sites'] = [];
                foreach ($counts as $row) $info['sites'][$row['status']] = (int)$row['c'];
                $info['sites']['total'] = array_sum($info['sites']);
            } catch (Throwable $e) {
                $info['sites'] = ['total' => 0];
            }
            $sys = agent('system-check', [], 60);
            if (!empty($sys['success'])) $info = array_merge($info, agentData($sys));
            $info['php_versions_available'] = $CFG['php_versions'] ?? [];
            apiSuccess($info);

        //=====================================================================
        // DEFAULT
        //=====================================================================
        default:
            if ($action === '') {
                apiSuccess(['name' => 'Flyne Engine API', 'version' => FLYNE_VERSION, 'status' => 'operational'], 'Flyne Engine API is running');
            }
            apiError('Unknown action', 400);
    }
} catch (PDOException $e) {
    error_log('Flyne API database error: ' . $e->getMessage());
    apiError('Database error', 500);
} catch (Throwable $e) {
    error_log('Flyne API error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    apiError('Internal server error', 500);
}
