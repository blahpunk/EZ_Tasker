<?php
declare(strict_types=1);

const ENC_PREFIX = 'enc:v1:';
const EMAIL_PATTERN = '/^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/';

load_dotenv(__DIR__ . '/.env');

$baseDir = __DIR__;
$dataDir = env_string('DATA_DIR', '/var/lib/ez_tasker');
$dbPath = env_string('DB_PATH', $dataDir . '/tasks.db');
$staticAssetVersion = env_string('STATIC_ASSET_VERSION', '');
$runtimeCacheBustToken = $staticAssetVersion !== '' ? $staticAssetVersion : (string) time();

$secretKey = env_string('SECRET_KEY', '');
$secureAuthSecret = env_string('SECURE_AUTH_SECRET', '');
$secureAuthPreviousSecrets = parse_csv_values(env_string('SECURE_AUTH_PREVIOUS_SECRETS', ''));
$userIdSecret = env_string('USER_ID_SECRET', '');
$userIdPreviousSecrets = parse_csv_values(env_string('USER_ID_PREVIOUS_SECRETS', ''));
$dataEncryptionKey = env_string('DATA_ENCRYPTION_KEY', '');
$dataEncryptionPreviousKeys = parse_csv_values(env_string('DATA_ENCRYPTION_PREVIOUS_KEYS', ''));
$bootstrapAudience = strtolower(env_string('BOOTSTRAP_COOKIE_AUDIENCE', 'tasks.blahpunk.com'));
$bootstrapMaxAgeSeconds = env_int('BOOTSTRAP_COOKIE_MAX_AGE_SECONDS', 300);
$bootstrapClockSkewSeconds = env_int('BOOTSTRAP_COOKIE_CLOCK_SKEW_SECONDS', 60);
$appEnv = strtolower(env_string('APP_ENV', 'production'));
$authMode = strtolower(env_string('AUTH_MODE', 'oauth'));
$devUserEmail = env_string('DEV_USER_EMAIL', 'dev@localhost.test');

$currentDataKeyParts = decode_fernet_key_parts($dataEncryptionKey);
$fernetKeyring = [];
if (is_array($currentDataKeyParts)) {
    $fernetKeyring[] = $currentDataKeyParts;
}
foreach ($dataEncryptionPreviousKeys as $i => $k) {
    $parts = decode_fernet_key_parts($k);
    if (!is_array($parts)) {
        server_misconfigured('DATA_ENCRYPTION_PREVIOUS_KEYS contains an invalid key at index ' . (string) $i . '.');
    }

    $alreadyIncluded = false;
    foreach ($fernetKeyring as $existing) {
        if (($existing['signing'] ?? '') === ($parts['signing'] ?? '') &&
            ($existing['encryption'] ?? '') === ($parts['encryption'] ?? '')) {
            $alreadyIncluded = true;
            break;
        }
    }
    if (!$alreadyIncluded) {
        $fernetKeyring[] = $parts;
    }
}

$CONFIG = [
    'base_dir' => $baseDir,
    'data_dir' => $dataDir,
    'db_path' => $dbPath,
    'static_asset_version' => $staticAssetVersion,
    'runtime_cache_bust_token' => $runtimeCacheBustToken,
    'secret_key' => $secretKey,
    'secure_auth_secret' => $secureAuthSecret,
    'secure_auth_previous_secrets' => $secureAuthPreviousSecrets,
    'user_id_secret' => $userIdSecret,
    'user_id_previous_secrets' => $userIdPreviousSecrets,
    'data_encryption_key' => $dataEncryptionKey,
    'data_encryption_previous_keys' => $dataEncryptionPreviousKeys,
    'bootstrap_cookie_audience' => $bootstrapAudience,
    'bootstrap_cookie_max_age_seconds' => $bootstrapMaxAgeSeconds,
    'bootstrap_cookie_clock_skew_seconds' => $bootstrapClockSkewSeconds,
    'app_env' => $appEnv,
    'auth_mode' => $authMode,
    'dev_user_email' => $devUserEmail,
    'fernet_keyring' => $fernetKeyring,
    'fernet_signing_key' => is_array($currentDataKeyParts) ? (string) ($currentDataKeyParts['signing'] ?? '') : '',
    'fernet_encryption_key' => is_array($currentDataKeyParts) ? (string) ($currentDataKeyParts['encryption'] ?? '') : '',
];

if (!is_array($currentDataKeyParts)) {
    server_misconfigured('DATA_ENCRYPTION_KEY must be a valid 32-byte Fernet key.');
}
if ($secretKey === '' || $secretKey === 'change-me') {
    server_misconfigured('SECRET_KEY must be set to a non-default value.');
}
if ($userIdSecret === '') {
    server_misconfigured('USER_ID_SECRET must be set.');
}
if ($bootstrapAudience === '') {
    server_misconfigured('BOOTSTRAP_COOKIE_AUDIENCE must be set.');
}
if (!in_array($authMode, ['oauth', 'dev'], true)) {
    server_misconfigured('AUTH_MODE must be oauth or dev.');
}
if ($authMode === 'dev' && !is_dev_runtime_allowed()) {
    server_misconfigured('AUTH_MODE=dev is only allowed for local hostnames or APP_ENV=development.');
}
if ($authMode === 'dev' && !is_valid_email(normalize_email($devUserEmail))) {
    server_misconfigured('DEV_USER_EMAIL must be a valid email when AUTH_MODE=dev.');
}

start_session();
init_db();
load_user_from_cookie();

dispatch_request();

function cfg(string $key): mixed
{
    global $CONFIG;
    return $CONFIG[$key] ?? null;
}

function env_string(string $name, string $default = ''): string
{
    $val = getenv($name);
    if ($val === false) {
        return trim($default);
    }
    return trim((string) $val);
}

function env_int(string $name, int $default): int
{
    $raw = env_string($name, (string) $default);
    if ($raw === '' || !preg_match('/^-?\d+$/', $raw)) {
        return $default;
    }
    return (int) $raw;
}

function parse_csv_values(string $raw): array
{
    if (trim($raw) === '') {
        return [];
    }
    $parts = array_map('trim', explode(',', $raw));
    $parts = array_values(array_filter($parts, static fn(string $s): bool => $s !== ''));
    return array_values(array_unique($parts));
}

function decode_fernet_key_parts(string $key): ?array
{
    $decoded = base64url_decode(trim($key));
    if (!is_string($decoded) || strlen($decoded) !== 32) {
        return null;
    }

    return [
        'signing' => substr($decoded, 0, 16),
        'encryption' => substr($decoded, 16, 16),
    ];
}

function load_dotenv(string $path): void
{
    if (!is_file($path)) {
        return;
    }

    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $parts = explode('=', $line, 2);
        if (count($parts) !== 2) {
            continue;
        }
        $name = trim($parts[0]);
        $value = trim($parts[1]);
        if ($name === '') {
            continue;
        }
        if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
            (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
            $value = substr($value, 1, -1);
        }

        if (getenv($name) === false) {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}

function server_misconfigured(string $message): never
{
    send_security_headers();
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Server misconfigured.';
    error_log('tasks.blahpunk.com misconfiguration: ' . $message);
    exit;
}

function start_session(): void
{
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
        (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_start();
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dataDir = (string) cfg('data_dir');
    if (!is_dir($dataDir)) {
        @mkdir($dataDir, 0770, true);
    }

    $dbPath = (string) cfg('db_path');
    $pdo = new PDO('sqlite:' . $dbPath);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON;');
    return $pdo;
}

function init_db(): void
{
    $db = db();

    $db->exec(
        'CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description_html TEXT NOT NULL,
            description_text TEXT NOT NULL,
            due_date TEXT NULL,
            priority INTEGER NOT NULL DEFAULT 1,
            completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0
        );'
    );

    $db->exec('CREATE INDEX IF NOT EXISTS idx_tasks_user_sort ON tasks(user_id, sort_order);');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_tasks_user_completed ON tasks(user_id, completed);');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_tasks_user_due ON tasks(user_id, due_date);');

    $db->exec(
        'CREATE TABLE IF NOT EXISTS tags (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, name)
        );'
    );

    $db->exec(
        'CREATE TABLE IF NOT EXISTS task_tags (
            task_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            PRIMARY KEY(task_id, tag_id),
            FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
            FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
        );'
    );

    $db->exec('CREATE INDEX IF NOT EXISTS idx_task_tags_task ON task_tags(task_id);');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_task_tags_tag ON task_tags(tag_id);');

    $db->exec('CREATE TABLE IF NOT EXISTS app_meta (meta_key TEXT PRIMARY KEY, meta_value TEXT NOT NULL);');

    $stmt = $db->prepare('SELECT meta_value FROM app_meta WHERE meta_key = ?;');
    $stmt->execute(['task_content_encrypted_v1']);
    $row = $stmt->fetch();
    if (!$row || ($row['meta_value'] ?? '') !== '1') {
        encrypt_existing_task_content($db);
        $upsert = $db->prepare(
            'INSERT INTO app_meta (meta_key, meta_value) VALUES (?, ?)
             ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value;'
        );
        $upsert->execute(['task_content_encrypted_v1', '1']);
    }
}

function encrypt_existing_task_content(PDO $db): void
{
    $rows = $db->query('SELECT id, title, description_html, description_text FROM tasks;')->fetchAll();
    if (!$rows) {
        return;
    }

    $db->beginTransaction();
    try {
        $update = $db->prepare(
            'UPDATE tasks
             SET title = ?, description_html = ?, description_text = ?
             WHERE id = ?;'
        );

        foreach ($rows as $row) {
            $title = (string) ($row['title'] ?? '');
            $descriptionHtml = (string) ($row['description_html'] ?? '');
            $descriptionText = (string) ($row['description_text'] ?? '');

            $newTitle = is_encrypted_value($title) ? $title : encrypt_text($title);
            $newDescriptionHtml = is_encrypted_value($descriptionHtml) ? $descriptionHtml : encrypt_text($descriptionHtml);
            $newDescriptionText = is_encrypted_value($descriptionText) ? $descriptionText : encrypt_text($descriptionText);

            if ($newTitle !== $title || $newDescriptionHtml !== $descriptionHtml || $newDescriptionText !== $descriptionText) {
                $update->execute([$newTitle, $newDescriptionHtml, $newDescriptionText, $row['id']]);
            }
        }

        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $e;
    }
}

function dispatch_request(): never
{
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === '') {
        $path = '/';
    }

    if ($method === 'GET' && $path === '/') {
        handle_index();
    }
    if ($method === 'GET' && $path === '/login') {
        handle_login_prompt();
    }
    if ($method === 'GET' && $path === '/dev-login') {
        handle_dev_login();
    }
    if ($method === 'GET' && $path === '/logout') {
        handle_logout();
    }

    if ($path === '/api/v1/tasks' && $method === 'GET') {
        api_list_tasks();
    }
    if ($path === '/api/v1/tasks' && $method === 'POST') {
        api_create_task();
    }
    if ($path === '/api/v1/tasks/reorder' && $method === 'POST') {
        api_reorder_tasks();
    }
    if ($path === '/api/v1/tags' && $method === 'GET') {
        api_list_tags();
    }
    if (preg_match('#^/api/v1/tasks/([^/]+)$#', $path, $m) === 1) {
        $taskId = rawurldecode($m[1]);
        if ($method === 'PUT') {
            api_update_task($taskId);
        }
        if ($method === 'DELETE') {
            api_delete_task($taskId);
        }
    }

    if ($path === '/api/tasks' && $method === 'GET') {
        compat_get_tasks();
    }
    if ($path === '/api/tasks' && $method === 'POST') {
        compat_add_task();
    }
    if ($path === '/api/tasks/order' && $method === 'POST') {
        compat_save_order();
    }

    send_security_headers();
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Not found';
    exit;
}

function send_security_headers(): void
{
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains', false);
    header('X-Content-Type-Options: nosniff', false);
    header('X-Frame-Options: DENY', false);
    header('Referrer-Policy: strict-origin-when-cross-origin', false);
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function asset_version(string $filename): string
{
    $staticAssetVersion = (string) cfg('static_asset_version');
    if ($staticAssetVersion !== '') {
        return $staticAssetVersion;
    }

    $path = rtrim((string) cfg('base_dir'), '/') . '/static/' . ltrim($filename, '/');
    if (is_file($path)) {
        $mtime = @filemtime($path);
        if ($mtime !== false) {
            return (string) $mtime;
        }
    }
    return '1';
}

function handle_index(): never
{
    if (!is_logged_in()) {
        redirect('/login');
    }

    $isDevAuth = is_dev_auth_enabled();
    $csrf = ensure_csrf_token();
    $stylesVersion = rawurlencode(asset_version('css/styles.css'));
    $scriptsVersion = rawurlencode(asset_version('js/scripts.js'));
    $cacheBustToken = rawurlencode((string) cfg('runtime_cache_bust_token'));

    send_security_headers();
    header('Content-Type: text/html; charset=UTF-8');

    echo "<!DOCTYPE html>\n";
    echo "<html lang=\"en\">\n";
    echo "<head>\n";
    echo "    <meta charset=\"UTF-8\">\n";
    echo '    <meta name="csrf-token" content="' . h($csrf) . '">' . "\n";
    echo "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    echo "    <title>EZ Tasker</title>\n\n";
    echo "    <link href=\"https://cdn.jsdelivr.net/npm/quill@2/dist/quill.snow.css\" rel=\"stylesheet\">\n";
    echo '    <link rel="stylesheet" href="/tasks/static/css/styles.css?v=' . h($stylesVersion) . '">' . "\n";
    echo "</head>\n";
    echo "<body>\n";
    echo "    <div class=\"container\">\n";
    echo "        <header>\n";
    echo "            <div class=\"header-top\">\n";
    echo "                <h1>EZ Tasker";
    if ($isDevAuth) {
        echo " <span class=\"dev-mode-badge\">DEV MODE</span>";
    }
    echo "</h1>\n";
    echo "                <div class=\"header-buttons\">\n";
    echo "                    <a href=\"https://blahpunk.com\"><button class=\"btn btn-secondary\">Home</button></a>\n";
    echo "                    <a href=\"/logout\"><button class=\"btn\">Logout</button></a>\n";
    echo "                </div>\n";
    echo "            </div>\n\n";
    echo "            <div class=\"toolbar\">\n";
    echo "                <input id=\"searchInput\" type=\"search\" placeholder=\"Search tasks...\" autocomplete=\"off\">\n\n";
    echo "                <select id=\"statusSelect\">\n";
    echo "                    <option value=\"all\">All</option>\n";
    echo "                    <option value=\"active\">Active</option>\n";
    echo "                    <option value=\"completed\">Completed</option>\n";
    echo "                </select>\n\n";
    echo "                <select id=\"specialSelect\">\n";
    echo "                    <option value=\"\">No special filter</option>\n";
    echo "                    <option value=\"overdue\">Overdue</option>\n";
    echo "                    <option value=\"dueSoon\">Due soon (7 days)</option>\n";
    echo "                </select>\n\n";
    echo "                <select id=\"sortSelect\">\n";
    echo "                    <option value=\"manual\">Manual</option>\n";
    echo "                    <option value=\"due\">Due date</option>\n";
    echo "                    <option value=\"priority\">Priority</option>\n";
    echo "                    <option value=\"updated\">Recently updated</option>\n";
    echo "                    <option value=\"created\">Recently created</option>\n";
    echo "                    <option value=\"title\">Title</option>\n";
    echo "                </select>\n\n";
    echo "                <label class=\"checkbox\">\n";
    echo "                    <input id=\"hideCompleted\" type=\"checkbox\">\n";
    echo "                    <span>Hide completed</span>\n";
    echo "                </label>\n";
    echo "            </div>\n";
    echo "        </header>\n\n";
    echo "        <button id=\"addTaskBtn\" class=\"fab\">+ Add Task</button>\n\n";
    echo "        <main>\n";
    echo "            <section id=\"taskForm\" class=\"panel is-hidden\">\n";
    echo "                <div class=\"form-row\">\n";
    echo "                    <input type=\"text\" id=\"taskTitle\" placeholder=\"Task Title\">\n";
    echo "                </div>\n\n";
    echo "                <div class=\"form-row form-grid\">\n";
    echo "                    <div class=\"field\">\n";
    echo "                        <label>Due date</label>\n";
    echo "                        <input type=\"date\" id=\"taskDueDate\">\n";
    echo "                    </div>\n\n";
    echo "                    <div class=\"field\">\n";
    echo "                        <label>Priority</label>\n";
    echo "                        <select id=\"taskPriority\">\n";
    echo "                            <option value=\"0\">Low</option>\n";
    echo "                            <option value=\"1\" selected>Medium</option>\n";
    echo "                            <option value=\"2\">High</option>\n";
    echo "                        </select>\n";
    echo "                    </div>\n\n";
    echo "                    <div class=\"field\">\n";
    echo "                        <label>Tags</label>\n";
    echo "                        <input type=\"text\" id=\"taskTags\" placeholder=\"comma-separated (e.g., bills, errands)\">\n";
    echo "                    </div>\n";
    echo "                </div>\n\n";
    echo "                <div class=\"form-row\">\n";
    echo "                    <div id=\"editor-container\"></div>\n";
    echo "                </div>\n\n";
    echo "                <div class=\"form-actions\">\n";
    echo "                    <button id=\"cancelTaskBtn\" class=\"btn btn-secondary\" type=\"button\">Cancel</button>\n";
    echo "                    <button id=\"saveTaskBtn\" class=\"btn btn-primary\" type=\"button\">Save</button>\n";
    echo "                </div>\n";
    echo "            </section>\n\n";
    echo "            <section id=\"taskListWrap\">\n";
    echo "                <p id=\"noTasksMessage\" class=\"empty is-hidden\">\n";
    echo "                    No tasks yet. Click \"Add Task\" to get started.\n";
    echo "                </p>\n";
    echo "                <div id=\"taskList\"></div>\n";
    echo "            </section>\n";
    echo "        </main>\n";
    echo "    </div>\n\n";
    echo '    <script src="https://cdn.jsdelivr.net/npm/quill@2/dist/quill.js?v=' . h($cacheBustToken) . '"></script>' . "\n";
    echo '    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.14.0/Sortable.min.js?v=' . h($cacheBustToken) . '"></script>' . "\n";
    echo '    <script src="/tasks/static/js/scripts.js?v=' . h($scriptsVersion) . '"></script>' . "\n";
    echo "</body>\n";
    echo "</html>\n";
    exit;
}

function handle_login_prompt(): never
{
    $useDevAuth = is_dev_auth_enabled();
    $loginUrl = build_login_url();
    $devLoginUrl = build_dev_login_url();
    $cssVersion = rawurlencode(asset_version('css/login_prompt.css'));

    send_security_headers();
    header('Content-Type: text/html; charset=UTF-8');

    echo "<!DOCTYPE html>\n";
    echo "<html lang=\"en\">\n";
    echo "<head>\n";
    echo "    <meta charset=\"UTF-8\">\n";
    echo "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    echo "    <title>Login Required</title>\n";
    echo '    <link rel="stylesheet" href="/tasks/static/css/login_prompt.css?v=' . h($cssVersion) . '">' . "\n";
    echo "</head>\n";
    echo "<body>\n";
    echo "    <div class=\"login-card\">\n";
    echo "        <h1>You are not logged in.</h1>\n";
    if ($useDevAuth) {
        echo "        <p>Development auth mode is enabled. Continue with a local dev account.</p>\n";
    } else {
        echo "        <p>Please log in to view your tasks.</p>\n";
    }
    echo "        <div class=\"login-actions\">\n";
    echo "            <a href=\"https://blahpunk.com\" class=\"btn btn-secondary\">Home</a>\n";
    if ($useDevAuth) {
        echo '            <a href="' . h($devLoginUrl) . '" class="btn btn-primary">Continue (Dev Mode)</a>' . "\n";
    } else {
        echo '            <a href="' . h($loginUrl) . '" class="btn btn-primary">Login with Google</a>' . "\n";
    }
    echo "        </div>\n";
    echo "    </div>\n";
    echo "</body>\n";
    echo "</html>\n";
    exit;
}

function handle_dev_login(): never
{
    if (!is_dev_auth_enabled()) {
        send_security_headers();
        http_response_code(404);
        header('Content-Type: text/plain; charset=UTF-8');
        echo 'Not found';
        exit;
    }

    $requested = trim((string) ($_GET['email'] ?? ''));
    $email = normalize_email($requested !== '' ? $requested : (string) cfg('dev_user_email'));
    if (!is_valid_email($email)) {
        send_security_headers();
        http_response_code(400);
        header('Content-Type: text/plain; charset=UTF-8');
        echo 'Invalid dev user email.';
        exit;
    }

    $_SESSION['google_id'] = $email;
    ensure_csrf_token();
    redirect('/');
}

function handle_logout(): never
{
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
        $name = session_name();
        session_destroy();
        setcookie($name, '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    setcookie('user', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '.blahpunk.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    setcookie('user_sig', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '.blahpunk.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    redirect('/login');
}

function build_login_url(): string
{
    if (is_dev_auth_enabled()) {
        return build_dev_login_url();
    }

    $query = http_build_query([
        'next' => 'https://tasks.blahpunk.com',
        'aud' => (string) cfg('bootstrap_cookie_audience'),
        'max_age' => (string) cfg('bootstrap_cookie_max_age_seconds'),
    ]);
    return 'https://secure.blahpunk.com/oauth_login?' . $query;
}

function build_dev_login_url(): string
{
    $email = normalize_email((string) cfg('dev_user_email'));
    return '/dev-login?email=' . rawurlencode($email);
}

function auth_mode(): string
{
    $mode = strtolower(trim((string) cfg('auth_mode')));
    return in_array($mode, ['oauth', 'dev'], true) ? $mode : 'oauth';
}

function is_dev_auth_enabled(): bool
{
    return auth_mode() === 'dev';
}

function is_dev_runtime_allowed(): bool
{
    $appEnv = strtolower(trim((string) cfg('app_env')));
    if (in_array($appEnv, ['dev', 'development', 'local'], true)) {
        return true;
    }
    return is_local_request_host();
}

function is_local_request_host(): bool
{
    $rawHost = strtolower(trim((string) ($_SERVER['HTTP_HOST'] ?? '')));
    if ($rawHost === '') {
        return false;
    }

    $host = $rawHost;
    if (str_starts_with($host, '[')) {
        $end = strpos($host, ']');
        if ($end !== false) {
            $host = substr($host, 1, $end - 1);
        }
    } else {
        $host = explode(':', $host)[0];
    }

    if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
        return true;
    }

    return str_ends_with($host, '.local') || str_ends_with($host, '.test');
}


function redirect(string $location): never
{
    send_security_headers();
    header('Location: ' . $location, true, 302);
    exit;
}

function json_response(mixed $data, int $status = 200): never
{
    send_security_headers();
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function no_content_response(int $status = 204): never
{
    send_security_headers();
    http_response_code($status);
    exit;
}

function get_json_payload(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || trim($raw) === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function is_logged_in(): bool
{
    $email = $_SESSION['google_id'] ?? '';
    return is_string($email) && $email !== '';
}

function ensure_web_login_or_redirect(): void
{
    if (!is_logged_in()) {
        redirect('/login');
    }
}

function ensure_api_login_or_401(): void
{
    if (!is_logged_in()) {
        json_response(['error' => 'not_authenticated'], 401);
    }
}

function ensure_csrf_token(): string
{
    $token = $_SESSION['csrf_token'] ?? '';
    if (!is_string($token) || $token === '') {
        $token = bin2hex(random_bytes(16));
        $_SESSION['csrf_token'] = $token;
    }
    return $token;
}

function ensure_csrf_or_403(): void
{
    $token = $_SESSION['csrf_token'] ?? '';
    $header = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($token) || $token === '' || !is_string($header) || $header === '' || !hash_equals($token, $header)) {
        json_response(['error' => 'csrf_failed'], 403);
    }
}

function load_user_from_cookie(): void
{
    if (is_logged_in()) {
        return;
    }

    if (is_dev_auth_enabled()) {
        return;
    }

    $userCookie = $_COOKIE['user'] ?? '';
    if (!is_string($userCookie) || $userCookie === '') {
        return;
    }
    $userSig = $_COOKIE['user_sig'] ?? null;
    if (!verify_user_cookie_signature($userCookie, is_string($userSig) ? $userSig : null)) {
        return;
    }

    $userInfo = decode_user_cookie($userCookie);
    if (!is_array($userInfo)) {
        return;
    }

    $email = normalize_email((string) ($userInfo['email'] ?? ''));
    if (!is_valid_email($email)) {
        return;
    }

    [$claimsOk, ] = validate_bootstrap_claims($userInfo);
    if (!$claimsOk) {
        return;
    }

    $_SESSION['google_id'] = $email;
    ensure_csrf_token();
}

function verify_user_cookie_signature(string $userCookie, ?string $userSig): bool
{
    if ($userCookie === '' || $userSig === null || $userSig === '') {
        return false;
    }

    $secrets = [];
    $current = (string) cfg('secure_auth_secret');
    if ($current !== '') {
        $secrets[] = $current;
    }

    $previous = cfg('secure_auth_previous_secrets');
    if (is_array($previous)) {
        foreach ($previous as $candidate) {
            if (is_string($candidate) && trim($candidate) !== '') {
                $secrets[] = trim($candidate);
            }
        }
    }

    $secrets = array_values(array_unique($secrets));
    if (!$secrets) {
        return false;
    }

    foreach ($secrets as $secret) {
        $expected = hash_hmac('sha256', $userCookie, $secret);
        if (hash_equals($expected, $userSig)) {
            return true;
        }
    }

    return false;
}

function decode_user_cookie(string $userCookie): ?array
{
    $decoded = base64url_decode($userCookie);
    if (!is_string($decoded)) {
        return null;
    }

    $parsed = json_decode($decoded, true);
    if (!is_array($parsed)) {
        return null;
    }
    return $parsed;
}

function parse_epoch_seconds(mixed $value): ?int
{
    if (is_bool($value) || $value === null) {
        return null;
    }
    if (is_int($value)) {
        return $value;
    }
    if (is_float($value)) {
        return (int) $value;
    }
    if (is_string($value)) {
        $s = trim($value);
        if ($s !== '' && preg_match('/^-?\d+$/', $s) === 1) {
            return (int) $s;
        }
    }
    return null;
}

function audience_matches(mixed $audClaim, string $expected): bool
{
    $expectedNormalized = strtolower(trim($expected));
    if ($expectedNormalized === '') {
        return false;
    }

    if (is_string($audClaim)) {
        return strtolower(trim($audClaim)) === $expectedNormalized;
    }

    if (is_array($audClaim)) {
        foreach ($audClaim as $part) {
            if (is_string($part) && strtolower(trim($part)) === $expectedNormalized) {
                return true;
            }
        }
    }

    return false;
}

function validate_bootstrap_claims(array $userInfo): array
{
    $now = time();
    $skew = max(0, (int) cfg('bootstrap_cookie_clock_skew_seconds'));
    $maxAge = max(30, (int) cfg('bootstrap_cookie_max_age_seconds'));

    $aud = $userInfo['aud'] ?? null;
    if (!audience_matches($aud, (string) cfg('bootstrap_cookie_audience'))) {
        return [false, 'audience_mismatch'];
    }

    $exp = parse_epoch_seconds($userInfo['exp'] ?? null);
    $iat = parse_epoch_seconds($userInfo['iat'] ?? null);
    $nbf = parse_epoch_seconds($userInfo['nbf'] ?? null);

    if ($exp === null || $iat === null) {
        return [false, 'missing_required_time_claims'];
    }
    if ($exp <= $iat) {
        return [false, 'invalid_claim_window'];
    }
    if ($iat > $now + $skew) {
        return [false, 'token_issued_in_future'];
    }
    if ($nbf !== null && ($now + $skew) < $nbf) {
        return [false, 'token_not_yet_valid'];
    }
    if ($exp < ($now - $skew)) {
        return [false, 'token_expired'];
    }
    if (($exp - $iat) > ($maxAge + $skew)) {
        return [false, 'token_ttl_too_long'];
    }
    if (($now - $iat) > ($maxAge + $skew)) {
        return [false, 'token_too_old'];
    }

    return [true, ''];
}

function normalize_email(string $email): string
{
    return strtolower(trim($email));
}

function is_valid_email(string $email): bool
{
    return preg_match(EMAIL_PATTERN, normalize_email($email)) === 1;
}

function current_user_email(): string
{
    $email = $_SESSION['google_id'] ?? '';
    return is_string($email) ? $email : '';
}

function legacy_user_storage_id(string $email): string
{
    return hash('sha256', normalize_email($email));
}

function user_storage_id_for_secret(string $email, string $secret): string
{
    return hash_hmac('sha256', normalize_email($email), $secret);
}

function user_storage_id(string $email): string
{
    $secret = (string) cfg('user_id_secret');
    return user_storage_id_for_secret($email, $secret);
}

function previous_user_storage_ids(string $email): array
{
    $emailNormalized = normalize_email($email);
    if (!is_valid_email($emailNormalized)) {
        return [];
    }

    $secrets = cfg('user_id_previous_secrets');
    if (!is_array($secrets)) {
        return [];
    }

    $ids = [];
    foreach ($secrets as $secret) {
        if (!is_string($secret) || trim($secret) === '') {
            continue;
        }
        $ids[] = user_storage_id_for_secret($emailNormalized, trim($secret));
    }

    return array_values(array_unique($ids));
}

function current_user_id(): string
{
    $email = current_user_email();
    migrate_user_namespace_if_needed($email);
    return user_storage_id($email);
}

function migrate_user_namespace_if_needed(string $email): void
{
    $emailNormalized = normalize_email($email);
    if (!is_valid_email($emailNormalized)) {
        return;
    }

    $newUserId = user_storage_id($emailNormalized);
    $candidateOldIds = previous_user_storage_ids($emailNormalized);

    $legacyId = legacy_user_storage_id($emailNormalized);
    if ($legacyId !== $newUserId) {
        $candidateOldIds[] = $legacyId;
    }
    $candidateOldIds = array_values(array_unique(array_filter(
        $candidateOldIds,
        static fn(string $id): bool => $id !== '' && $id !== $newUserId
    )));

    if (!$candidateOldIds) {
        return;
    }

    foreach ($candidateOldIds as $oldUserId) {
        migrate_single_user_namespace($oldUserId, $newUserId);
    }
}

function migrate_single_user_namespace(string $oldUserId, string $newUserId): void
{
    if ($oldUserId === '' || $newUserId === '' || $oldUserId === $newUserId) {
        return;
    }

    $db = db();
    $hasOld = $db->prepare('SELECT 1 FROM tasks WHERE user_id = ? LIMIT 1;');
    $hasOld->execute([$oldUserId]);
    if ($hasOld->fetch() === false) {
        return;
    }

    $db->beginTransaction();
    try {
        $updateTasks = $db->prepare('UPDATE tasks SET user_id = ? WHERE user_id = ?;');
        $updateTasks->execute([$newUserId, $oldUserId]);

        merge_tags_user_namespace($db, $oldUserId, $newUserId);

        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $e;
    }
}

function merge_tags_user_namespace(PDO $db, string $oldUserId, string $newUserId): void
{
    $oldTagsStmt = $db->prepare('SELECT id, name FROM tags WHERE user_id = ?;');
    $oldTagsStmt->execute([$oldUserId]);
    $oldTags = $oldTagsStmt->fetchAll();
    if (!$oldTags) {
        return;
    }

    $newByNameStmt = $db->prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? LIMIT 1;');
    $moveTaskTagsStmt = $db->prepare('UPDATE OR IGNORE task_tags SET tag_id = ? WHERE tag_id = ?;');
    $deleteOldTaskTagRowsStmt = $db->prepare('DELETE FROM task_tags WHERE tag_id = ?;');
    $deleteTagStmt = $db->prepare('DELETE FROM tags WHERE id = ?;');
    $moveTagOwnerStmt = $db->prepare('UPDATE tags SET user_id = ? WHERE id = ?;');

    foreach ($oldTags as $tagRow) {
        $oldTagId = (string) ($tagRow['id'] ?? '');
        $name = (string) ($tagRow['name'] ?? '');
        if ($oldTagId === '' || $name === '') {
            continue;
        }

        $newByNameStmt->execute([$newUserId, $name]);
        $newTagRow = $newByNameStmt->fetch();
        if ($newTagRow && isset($newTagRow['id'])) {
            $newTagId = (string) $newTagRow['id'];
            if ($newTagId !== '') {
                $moveTaskTagsStmt->execute([$newTagId, $oldTagId]);
            }
            $deleteOldTaskTagRowsStmt->execute([$oldTagId]);
            $deleteTagStmt->execute([$oldTagId]);
            continue;
        }

        $moveTagOwnerStmt->execute([$newUserId, $oldTagId]);
    }
}

function legacy_tasks_file_for_email(string $email): ?string
{
    $emailNormalized = normalize_email($email);
    if (!is_valid_email($emailNormalized)) {
        return null;
    }
    return rtrim((string) cfg('data_dir'), '/') . '/tasks_' . $emailNormalized . '.json';
}

function user_has_any_tasks(string $userId): bool
{
    $db = db();
    $stmt = $db->prepare('SELECT 1 FROM tasks WHERE user_id = ? LIMIT 1;');
    $stmt->execute([$userId]);
    return $stmt->fetch() !== false;
}

function parse_legacy_due_to_iso(?string $due): ?string
{
    if ($due === null) {
        return null;
    }

    $s = trim($due);
    if ($s === '') {
        return null;
    }

    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $s) === 1 && is_valid_iso_date($s)) {
        return $s;
    }

    $formats = ['m/d/Y', 'n/j/Y', 'm/d/y'];
    foreach ($formats as $fmt) {
        $dt = DateTimeImmutable::createFromFormat($fmt, $s);
        if ($dt instanceof DateTimeImmutable) {
            return $dt->format('Y-m-d');
        }
    }

    return null;
}

function migrate_legacy_tasks_if_needed(string $userEmail): void
{
    $userId = user_storage_id($userEmail);
    if (user_has_any_tasks($userId)) {
        return;
    }

    $legacyPath = legacy_tasks_file_for_email($userEmail);
    if (!is_string($legacyPath) || !is_file($legacyPath)) {
        return;
    }

    $raw = @file_get_contents($legacyPath);
    if (!is_string($raw) || trim($raw) === '') {
        return;
    }

    $legacyTasks = json_decode($raw, true);
    if (!is_array($legacyTasks)) {
        return;
    }

    usort($legacyTasks, function (mixed $a, mixed $b): int {
        $ai = 0;
        $bi = 0;
        if (is_array($a) && isset($a['index']) && is_numeric($a['index'])) {
            $ai = (int) $a['index'];
        }
        if (is_array($b) && isset($b['index']) && is_numeric($b['index'])) {
            $bi = (int) $b['index'];
        }
        return $ai <=> $bi;
    });

    $db = db();
    $now = utc_now_iso();

    $insert = $db->prepare(
        'INSERT INTO tasks
         (id, user_id, title, description_html, description_text, due_date, priority, completed, completed_at, created_at, updated_at, sort_order)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?);'
    );

    $db->beginTransaction();
    try {
        foreach ($legacyTasks as $i => $task) {
            if (!is_array($task)) {
                continue;
            }
            $title = trim((string) ($task['title'] ?? ''));
            $descriptionHtml = trim((string) ($task['description'] ?? ''));
            if ($title === '') {
                continue;
            }

            $safeHtml = sanitize_html($descriptionHtml);
            $descriptionText = html_to_text($safeHtml);
            $dueIso = parse_legacy_due_to_iso(is_string($task['dueDate'] ?? null) ? $task['dueDate'] : null);

            $insert->execute([
                uuid_v4(),
                $userId,
                encrypt_text($title),
                encrypt_text($safeHtml),
                encrypt_text($descriptionText),
                $dueIso,
                1,
                $now,
                $now,
                $i,
            ]);
        }
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $e;
    }
}

function normalize_tag_name(string $name): string
{
    return strtolower(trim(preg_replace('/\s+/', ' ', $name) ?? ''));
}

function upsert_tags(string $userId, array $tagNames): array
{
    $db = db();
    $now = utc_now_iso();
    $ids = [];

    $select = $db->prepare('SELECT id FROM tags WHERE user_id = ? AND name = ?;');
    $insert = $db->prepare('INSERT INTO tags (id, user_id, name, created_at) VALUES (?, ?, ?, ?);');

    foreach ($tagNames as $raw) {
        $name = normalize_tag_name((string) $raw);
        if ($name === '') {
            continue;
        }

        $select->execute([$userId, $name]);
        $row = $select->fetch();
        if ($row && isset($row['id'])) {
            $ids[] = (string) $row['id'];
            continue;
        }

        $tagId = uuid_v4();
        try {
            $insert->execute([$tagId, $userId, $name, $now]);
            $ids[] = $tagId;
        } catch (PDOException) {
            $select->execute([$userId, $name]);
            $retry = $select->fetch();
            if ($retry && isset($retry['id'])) {
                $ids[] = (string) $retry['id'];
            }
        }
    }

    return $ids;
}

function set_task_tags(string $taskId, string $userId, array $tagNames): void
{
    $db = db();
    $tagIds = upsert_tags($userId, $tagNames);

    $delete = $db->prepare('DELETE FROM task_tags WHERE task_id = ?;');
    $delete->execute([$taskId]);

    if (!$tagIds) {
        return;
    }

    $insert = $db->prepare('INSERT OR IGNORE INTO task_tags (task_id, tag_id) VALUES (?, ?);');
    foreach ($tagIds as $tagId) {
        $insert->execute([$taskId, $tagId]);
    }
}

function get_task_tags(string $taskId, string $userId): array
{
    $db = db();
    $stmt = $db->prepare(
        'SELECT t.name
         FROM tags t
         JOIN task_tags tt ON tt.tag_id = t.id
         WHERE tt.task_id = ? AND t.user_id = ?
         ORDER BY t.name ASC;'
    );
    $stmt->execute([$taskId, $userId]);
    $rows = $stmt->fetchAll();

    $tags = [];
    foreach ($rows as $row) {
        if (isset($row['name'])) {
            $tags[] = (string) $row['name'];
        }
    }
    return $tags;
}

function row_to_task(array $row, string $userId): array
{
    return [
        'id' => (string) ($row['id'] ?? ''),
        'title' => decrypt_text((string) ($row['title'] ?? '')),
        'description_html' => decrypt_text((string) ($row['description_html'] ?? '')),
        'due_date' => isset($row['due_date']) ? ($row['due_date'] !== null ? (string) $row['due_date'] : null) : null,
        'priority' => (int) ($row['priority'] ?? 1),
        'completed' => ((int) ($row['completed'] ?? 0)) === 1,
        'completed_at' => isset($row['completed_at']) ? ($row['completed_at'] !== null ? (string) $row['completed_at'] : null) : null,
        'created_at' => (string) ($row['created_at'] ?? ''),
        'updated_at' => (string) ($row['updated_at'] ?? ''),
        'sort_order' => (int) ($row['sort_order'] ?? 0),
        'tags' => get_task_tags((string) ($row['id'] ?? ''), $userId),
    ];
}

function parse_priority(mixed $value): int
{
    if (!is_int($value) && !is_string($value) && !is_float($value)) {
        return 1;
    }
    $p = (int) $value;
    if ($p < 0) {
        return 0;
    }
    if ($p > 2) {
        return 2;
    }
    return $p;
}

function parse_tags(mixed $value): array
{
    if ($value === null) {
        return [];
    }

    if (is_array($value)) {
        return array_values(array_filter(array_map(static fn($x) => (string) $x, $value), static fn($x) => trim($x) !== ''));
    }

    if (is_string($value)) {
        $parts = array_map('trim', explode(',', $value));
        return array_values(array_filter($parts, static fn($x) => $x !== ''));
    }

    return [];
}

function api_list_tasks(): never
{
    ensure_api_login_or_401();

    $email = current_user_email();
    $userId = current_user_id();
    migrate_legacy_tasks_if_needed($email);

    $q = mb_strtolower(trim((string) ($_GET['q'] ?? '')));
    $status = mb_strtolower(trim((string) ($_GET['status'] ?? 'all')));
    $special = mb_strtolower(trim((string) ($_GET['special'] ?? '')));
    $sort = mb_strtolower(trim((string) ($_GET['sort'] ?? 'manual')));
    $hideCompleted = trim((string) ($_GET['hide_completed'] ?? '0')) === '1';

    $where = ['user_id = ?'];
    $params = [$userId];

    if ($status === 'active') {
        $where[] = 'completed = 0';
    } elseif ($status === 'completed') {
        $where[] = 'completed = 1';
    }

    if ($hideCompleted) {
        $where[] = 'completed = 0';
    }

    $today = local_today_iso();
    if ($special === 'overdue') {
        $where[] = 'completed = 0';
        $where[] = 'due_date IS NOT NULL AND due_date < ?';
        $params[] = $today;
    } elseif ($special === 'duesoon') {
        $where[] = 'completed = 0';
        $where[] = 'due_date IS NOT NULL AND due_date >= ? AND due_date <= ?';
        $params[] = $today;
        $params[] = date('Y-m-d', strtotime($today . ' +7 days'));
    }

    $whereSql = implode(' AND ', $where);

    if ($sort === 'due') {
        $orderSql = 'CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date ASC, sort_order ASC';
    } elseif ($sort === 'created') {
        $orderSql = 'created_at DESC, sort_order ASC';
    } elseif ($sort === 'updated') {
        $orderSql = 'updated_at DESC, sort_order ASC';
    } elseif ($sort === 'priority') {
        $orderSql = 'priority DESC, CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date ASC, sort_order ASC';
    } else {
        $orderSql = 'sort_order ASC';
    }

    $db = db();
    $stmt = $db->prepare("SELECT * FROM tasks WHERE {$whereSql} ORDER BY {$orderSql};");
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $tasks = [];
    foreach ($rows as $row) {
        $task = row_to_task($row, $userId);
        if ($q !== '') {
            $titleLower = mb_strtolower((string) ($task['title'] ?? ''));
            $descLower = mb_strtolower(decrypt_text((string) ($row['description_text'] ?? '')));
            if (!str_contains($titleLower, $q) && !str_contains($descLower, $q)) {
                continue;
            }
        }
        $tasks[] = $task;
    }

    if ($sort === 'title') {
        usort($tasks, static function (array $a, array $b): int {
            $aTitle = mb_strtolower((string) ($a['title'] ?? ''));
            $bTitle = mb_strtolower((string) ($b['title'] ?? ''));
            $cmp = strcmp($aTitle, $bTitle);
            if ($cmp !== 0) {
                return $cmp;
            }
            return ((int) ($a['sort_order'] ?? 0)) <=> ((int) ($b['sort_order'] ?? 0));
        });
    }

    json_response($tasks);
}

function api_create_task(): never
{
    ensure_api_login_or_401();
    ensure_csrf_or_403();

    $userId = current_user_id();
    $payload = get_json_payload();

    $title = trim((string) ($payload['title'] ?? ''));
    $descriptionHtml = trim((string) ($payload['description_html'] ?? ''));
    $dueDate = trim((string) ($payload['due_date'] ?? ''));
    $priority = parse_priority($payload['priority'] ?? null);
    $tags = parse_tags($payload['tags'] ?? null);

    if ($title === '') {
        json_response(['error' => 'title_required'], 400);
    }

    $dueDateOrNull = $dueDate === '' ? null : $dueDate;
    if ($dueDateOrNull !== null && !is_valid_iso_date($dueDateOrNull)) {
        json_response(['error' => 'invalid_due_date'], 400);
    }

    $safeHtml = sanitize_html($descriptionHtml);
    $descText = html_to_text($safeHtml);

    $db = db();
    $now = utc_now_iso();
    $taskId = uuid_v4();

    try {
        $db->beginTransaction();

        $shift = $db->prepare('UPDATE tasks SET sort_order = sort_order + 1 WHERE user_id = ?;');
        $shift->execute([$userId]);

        $insert = $db->prepare(
            'INSERT INTO tasks
             (id, user_id, title, description_html, description_text, due_date, priority, completed, completed_at, created_at, updated_at, sort_order)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, 0);'
        );
        $insert->execute([
            $taskId,
            $userId,
            encrypt_text($title),
            encrypt_text($safeHtml),
            encrypt_text($descText),
            $dueDateOrNull,
            $priority,
            $now,
            $now,
        ]);

        set_task_tags($taskId, $userId, $tags);

        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        json_response(['error' => 'db_error'], 500);
    }

    $stmt = $db->prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?;');
    $stmt->execute([$taskId, $userId]);
    $row = $stmt->fetch();
    if (!$row) {
        json_response(['error' => 'not_found'], 404);
    }

    json_response(row_to_task($row, $userId), 201);
}

function api_update_task(string $taskId): never
{
    ensure_api_login_or_401();
    ensure_csrf_or_403();

    $userId = current_user_id();
    $payload = get_json_payload();

    $db = db();
    $stmt = $db->prepare('SELECT * FROM tasks WHERE id = ? AND user_id = ?;');
    $stmt->execute([$taskId, $userId]);
    $existing = $stmt->fetch();
    if (!$existing) {
        json_response(['error' => 'not_found'], 404);
    }

    $existingTitle = decrypt_text((string) ($existing['title'] ?? ''));
    $existingDescriptionHtml = decrypt_text((string) ($existing['description_html'] ?? ''));

    $title = array_key_exists('title', $payload)
        ? trim((string) ($payload['title'] ?? ''))
        : trim($existingTitle);

    $descriptionHtml = array_key_exists('description_html', $payload)
        ? (string) ($payload['description_html'] ?? '')
        : $existingDescriptionHtml;

    $dueDate = array_key_exists('due_date', $payload)
        ? trim((string) ($payload['due_date'] ?? ''))
        : (string) ($existing['due_date'] ?? '');
    $dueDateOrNull = $dueDate === '' ? null : $dueDate;

    $priority = array_key_exists('priority', $payload)
        ? parse_priority($payload['priority'])
        : parse_priority($existing['priority'] ?? 1);

    $completed = array_key_exists('completed', $payload)
        ? (bool) $payload['completed']
        : ((int) ($existing['completed'] ?? 0)) === 1;

    $tags = array_key_exists('tags', $payload)
        ? parse_tags($payload['tags'])
        : get_task_tags($taskId, $userId);

    if ($title === '') {
        json_response(['error' => 'title_required'], 400);
    }

    if ($dueDateOrNull !== null && !is_valid_iso_date($dueDateOrNull)) {
        json_response(['error' => 'invalid_due_date'], 400);
    }

    $safeHtml = sanitize_html($descriptionHtml);
    $descText = html_to_text($safeHtml);

    $now = utc_now_iso();
    $completedAt = $existing['completed_at'] ?? null;
    $wasCompleted = ((int) ($existing['completed'] ?? 0)) === 1;

    if ($completed && !$wasCompleted) {
        $completedAt = $now;
    }
    if (!$completed) {
        $completedAt = null;
    }

    try {
        $db->beginTransaction();

        $update = $db->prepare(
            'UPDATE tasks
             SET title = ?, description_html = ?, description_text = ?,
                 due_date = ?, priority = ?, completed = ?, completed_at = ?,
                 updated_at = ?
             WHERE id = ? AND user_id = ?;'
        );
        $update->execute([
            encrypt_text($title),
            encrypt_text($safeHtml),
            encrypt_text($descText),
            $dueDateOrNull,
            $priority,
            $completed ? 1 : 0,
            $completedAt,
            $now,
            $taskId,
            $userId,
        ]);

        set_task_tags($taskId, $userId, $tags);

        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        json_response(['error' => 'db_error'], 500);
    }

    $stmt->execute([$taskId, $userId]);
    $row = $stmt->fetch();
    if (!$row) {
        json_response(['error' => 'not_found'], 404);
    }

    json_response(row_to_task($row, $userId));
}

function api_delete_task(string $taskId): never
{
    ensure_api_login_or_401();
    ensure_csrf_or_403();

    $userId = current_user_id();
    $db = db();

    $stmt = $db->prepare('SELECT sort_order FROM tasks WHERE id = ? AND user_id = ?;');
    $stmt->execute([$taskId, $userId]);
    $row = $stmt->fetch();
    if (!$row) {
        json_response(['error' => 'not_found'], 404);
    }

    $deletedOrder = (int) ($row['sort_order'] ?? 0);

    try {
        $db->beginTransaction();

        $delete = $db->prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?;');
        $delete->execute([$taskId, $userId]);

        $compact = $db->prepare('UPDATE tasks SET sort_order = sort_order - 1 WHERE user_id = ? AND sort_order > ?;');
        $compact->execute([$userId, $deletedOrder]);

        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        json_response(['error' => 'db_error'], 500);
    }

    no_content_response(204);
}

function api_reorder_tasks(): never
{
    ensure_api_login_or_401();
    ensure_csrf_or_403();

    $userId = current_user_id();
    $payload = get_json_payload();
    $orderedIds = $payload['ordered_ids'] ?? null;

    if (!is_array($orderedIds)) {
        json_response(['error' => 'ordered_ids_required'], 400);
    }

    foreach ($orderedIds as $id) {
        if (!is_string($id)) {
            json_response(['error' => 'ordered_ids_required'], 400);
        }
    }

    if (count($orderedIds) === 0) {
        no_content_response(204);
    }

    $db = db();

    $placeholders = implode(',', array_fill(0, count($orderedIds), '?'));
    $sql = "SELECT id FROM tasks WHERE user_id = ? AND id IN ({$placeholders});";
    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$userId], $orderedIds));
    $rows = $stmt->fetchAll();

    $found = [];
    foreach ($rows as $row) {
        $found[(string) ($row['id'] ?? '')] = true;
    }

    $orderedSet = [];
    foreach ($orderedIds as $id) {
        $orderedSet[$id] = true;
    }

    if (count($orderedSet) !== count($found)) {
        json_response(['error' => 'invalid_task_ids'], 400);
    }
    foreach ($orderedSet as $id => $_) {
        if (!isset($found[$id])) {
            json_response(['error' => 'invalid_task_ids'], 400);
        }
    }

    $update = $db->prepare('UPDATE tasks SET sort_order = ?, updated_at = ? WHERE id = ? AND user_id = ?;');

    $db->beginTransaction();
    try {
        foreach ($orderedIds as $i => $taskId) {
            $update->execute([(int) $i, utc_now_iso(), $taskId, $userId]);
        }
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        json_response(['error' => 'db_error'], 500);
    }

    no_content_response(204);
}

function api_list_tags(): never
{
    ensure_api_login_or_401();
    $userId = current_user_id();

    $db = db();
    $stmt = $db->prepare('SELECT name FROM tags WHERE user_id = ? ORDER BY name ASC;');
    $stmt->execute([$userId]);
    $rows = $stmt->fetchAll();

    $tags = [];
    foreach ($rows as $row) {
        $tags[] = (string) ($row['name'] ?? '');
    }

    json_response($tags);
}

function compat_get_tasks(): never
{
    ensure_web_login_or_redirect();
    api_list_tasks();
}

function compat_add_task(): never
{
    ensure_web_login_or_redirect();
    api_create_task();
}

function compat_save_order(): never
{
    ensure_web_login_or_redirect();
    api_reorder_tasks();
}

function utc_now_iso(): string
{
    $dt = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    return $dt->format('Y-m-d\\TH:i:sP');
}

function local_today_iso(): string
{
    $dt = new DateTimeImmutable('now');
    return $dt->format('Y-m-d');
}

function is_valid_iso_date(string $value): bool
{
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) !== 1) {
        return false;
    }
    $dt = DateTimeImmutable::createFromFormat('Y-m-d', $value);
    return $dt instanceof DateTimeImmutable && $dt->format('Y-m-d') === $value;
}

function sanitize_html(string $html): string
{
    $allowedTags = [
        'p', 'br', 'strong', 'em', 'u', 's',
        'ul', 'ol', 'li',
        'blockquote',
        'h1', 'h2', 'h3',
        'a',
        'code', 'pre',
        'span',
    ];

    $allowedAttributes = [
        'a' => ['href', 'title', 'target', 'rel'],
        'li' => ['data-list', 'class'],
        'span' => ['class'],
    ];

    $allowedProtocols = ['http', 'https', 'mailto'];

    $doc = new DOMDocument('1.0', 'UTF-8');
    $wrapped = '<div>' . $html . '</div>';

    libxml_use_internal_errors(true);
    $flags = LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD | LIBXML_NOERROR | LIBXML_NOWARNING;
    $loaded = $doc->loadHTML('<?xml encoding="utf-8" ?>' . $wrapped, $flags);
    if (!$loaded) {
        libxml_clear_errors();
        return '';
    }

    $root = $doc->getElementsByTagName('div')->item(0);
    if (!$root instanceof DOMElement) {
        libxml_clear_errors();
        return '';
    }

    sanitize_dom_children($root, $doc, $allowedTags, $allowedAttributes, $allowedProtocols);

    $out = '';
    $children = [];
    foreach ($root->childNodes as $child) {
        $children[] = $child;
    }
    foreach ($children as $child) {
        $out .= $doc->saveHTML($child) ?: '';
    }

    libxml_clear_errors();
    return $out;
}

function sanitize_dom_children(
    DOMNode $parent,
    DOMDocument $doc,
    array $allowedTags,
    array $allowedAttributes,
    array $allowedProtocols
): void {
    $children = [];
    foreach ($parent->childNodes as $child) {
        $children[] = $child;
    }

    foreach ($children as $node) {
        if ($node instanceof DOMComment) {
            $parent->removeChild($node);
            continue;
        }

        if ($node instanceof DOMElement) {
            $tag = strtolower($node->tagName);
            if (!in_array($tag, $allowedTags, true)) {
                while ($node->firstChild) {
                    $parent->insertBefore($node->firstChild, $node);
                }
                $parent->removeChild($node);
                continue;
            }

            $attrNames = [];
            foreach ($node->attributes as $attr) {
                $attrNames[] = $attr->name;
            }

            foreach ($attrNames as $attrName) {
                $attrLower = strtolower($attrName);
                $allowed = $allowedAttributes[$tag] ?? [];
                if (!in_array($attrLower, $allowed, true)) {
                    $node->removeAttribute($attrName);
                    continue;
                }

                $value = $node->getAttribute($attrName);
                if ($attrLower === 'href') {
                    $value = trim($value);
                    if ($value === '') {
                        $node->removeAttribute($attrName);
                        continue;
                    }
                    $scheme = parse_url($value, PHP_URL_SCHEME);
                    if (is_string($scheme) && $scheme !== '') {
                        if (!in_array(strtolower($scheme), $allowedProtocols, true)) {
                            $node->removeAttribute($attrName);
                            continue;
                        }
                    }
                }

                if ($attrLower === 'class') {
                    $sanitized = preg_replace('/[^a-zA-Z0-9_\-\s]/', '', $value) ?? '';
                    $sanitized = trim(preg_replace('/\s+/', ' ', $sanitized) ?? '');
                    if ($sanitized === '') {
                        $node->removeAttribute($attrName);
                    } else {
                        $node->setAttribute($attrName, $sanitized);
                    }
                }
            }

            sanitize_dom_children($node, $doc, $allowedTags, $allowedAttributes, $allowedProtocols);
        }
    }
}

function html_to_text(string $html): string
{
    $safe = sanitize_html($html);
    $text = strip_tags($safe);
    $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = preg_replace('/\s+/u', ' ', $text) ?? '';
    return trim($text);
}

function is_encrypted_value(mixed $value): bool
{
    return is_string($value) && str_starts_with($value, ENC_PREFIX);
}

function encrypt_text(?string $value): string
{
    $keyring = fernet_keyring();
    $active = $keyring[0] ?? null;
    if (!is_array($active)) {
        return ENC_PREFIX;
    }

    $signing = (string) ($active['signing'] ?? '');
    $encryption = (string) ($active['encryption'] ?? '');
    if (strlen($signing) !== 16 || strlen($encryption) !== 16) {
        return ENC_PREFIX;
    }

    $plaintext = $value ?? '';
    $iv = random_bytes(16);
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-128-cbc',
        $encryption,
        OPENSSL_RAW_DATA,
        $iv
    );

    if (!is_string($ciphertext)) {
        return ENC_PREFIX;
    }

    $timestamp = pack_uint64_be(time());
    $body = "\x80" . $timestamp . $iv . $ciphertext;
    $hmac = hash_hmac('sha256', $body, $signing, true);
    return ENC_PREFIX . base64url_encode($body . $hmac);
}

function decrypt_text(?string $value): string
{
    if ($value === null) {
        return '';
    }
    if (!is_encrypted_value($value)) {
        return $value;
    }

    $token = substr($value, strlen(ENC_PREFIX));
    $raw = base64url_decode($token);
    if (!is_string($raw)) {
        return '';
    }

    $minLen = 1 + 8 + 16 + 32;
    if (strlen($raw) < $minLen) {
        return '';
    }

    if (ord($raw[0]) !== 0x80) {
        return '';
    }

    $hmac = substr($raw, -32);
    $body = substr($raw, 0, -32);
    if (!is_string($hmac) || !is_string($body)) {
        return '';
    }

    foreach (fernet_keyring() as $parts) {
        $signing = (string) ($parts['signing'] ?? '');
        $encryption = (string) ($parts['encryption'] ?? '');
        if (strlen($signing) !== 16 || strlen($encryption) !== 16) {
            continue;
        }

        $expected = hash_hmac('sha256', $body, $signing, true);
        if (!hash_equals($expected, $hmac)) {
            continue;
        }

        $iv = substr($raw, 9, 16);
        $ciphertext = substr($raw, 25, -32);
        if (!is_string($iv) || !is_string($ciphertext)) {
            return '';
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-128-cbc',
            $encryption,
            OPENSSL_RAW_DATA,
            $iv
        );
        return is_string($plaintext) ? $plaintext : '';
    }

    return '';
}

function fernet_keyring(): array
{
    $ring = cfg('fernet_keyring');
    if (is_array($ring) && count($ring) > 0) {
        return $ring;
    }

    $signing = (string) cfg('fernet_signing_key');
    $encryption = (string) cfg('fernet_encryption_key');
    if (strlen($signing) === 16 && strlen($encryption) === 16) {
        return [['signing' => $signing, 'encryption' => $encryption]];
    }

    return [];
}

function pack_uint64_be(int $value): string
{
    $high = intdiv($value, 4294967296);
    $low = $value % 4294967296;
    return pack('N2', $high, $low);
}

function base64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode(string $data): ?string
{
    if ($data === '') {
        return '';
    }

    $normalized = strtr($data, '-_', '+/');
    $remainder = strlen($normalized) % 4;
    if ($remainder !== 0) {
        $normalized .= str_repeat('=', 4 - $remainder);
    }

    $decoded = base64_decode($normalized, true);
    return is_string($decoded) ? $decoded : null;
}

function uuid_v4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}
