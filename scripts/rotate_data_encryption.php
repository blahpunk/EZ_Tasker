<?php
declare(strict_types=1);

/**
 * Re-encrypt task content using the active DATA_ENCRYPTION_KEY.
 *
 * Usage:
 *   php scripts/rotate_data_encryption.php [--dry-run]
 */

const ENC_PREFIX = 'enc:v1:';

$baseDir = dirname(__DIR__);
$envPath = $baseDir . '/.env';
load_dotenv($envPath);

$dataDir = env_string('DATA_DIR', '/var/lib/ez_tasker');
$dbPath = env_string('DB_PATH', $dataDir . '/tasks.db');
$currentKey = env_string('DATA_ENCRYPTION_KEY', '');
$previousKeys = parse_csv_values(env_string('DATA_ENCRYPTION_PREVIOUS_KEYS', ''));
$dryRun = in_array('--dry-run', $argv, true);

$currentParts = decode_fernet_key_parts($currentKey);
if (!is_array($currentParts)) {
    fwrite(STDERR, "ERROR: DATA_ENCRYPTION_KEY is invalid; expected URL-safe base64 32-byte key.\n");
    exit(1);
}

$keyring = [$currentParts];
foreach ($previousKeys as $i => $k) {
    $parts = decode_fernet_key_parts($k);
    if (!is_array($parts)) {
        fwrite(STDERR, "ERROR: DATA_ENCRYPTION_PREVIOUS_KEYS contains an invalid key at index {$i}.\n");
        exit(1);
    }

    $dupe = false;
    foreach ($keyring as $existing) {
        if ($existing['signing'] === $parts['signing'] && $existing['encryption'] === $parts['encryption']) {
            $dupe = true;
            break;
        }
    }
    if (!$dupe) {
        $keyring[] = $parts;
    }
}

if (!is_file($dbPath)) {
    fwrite(STDERR, "ERROR: DB_PATH does not exist: {$dbPath}\n");
    exit(1);
}

$db = new PDO('sqlite:' . $dbPath);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON;');

$rows = $db->query('SELECT id, title, description_html, description_text FROM tasks;')->fetchAll();
if (!$rows) {
    fwrite(STDOUT, "No tasks found. Nothing to rotate.\n");
    exit(0);
}

$updated = 0;
$skipped = 0;
$failed = 0;

$update = $db->prepare(
    'UPDATE tasks
     SET title = ?, description_html = ?, description_text = ?
     WHERE id = ?;'
);

if (!$dryRun) {
    $db->beginTransaction();
}

try {
    foreach ($rows as $row) {
        $id = (string) ($row['id'] ?? '');
        if ($id === '') {
            $skipped++;
            continue;
        }

        $titleCipher = (string) ($row['title'] ?? '');
        $htmlCipher = (string) ($row['description_html'] ?? '');
        $textCipher = (string) ($row['description_text'] ?? '');

        $titlePlain = decrypt_text_with_keyring($titleCipher, $keyring);
        $htmlPlain = decrypt_text_with_keyring($htmlCipher, $keyring);
        $textPlain = decrypt_text_with_keyring($textCipher, $keyring);

        if ($titlePlain === null || $htmlPlain === null || $textPlain === null) {
            $failed++;
            fwrite(STDERR, "WARN: could not decrypt all fields for task {$id}; left unchanged.\n");
            continue;
        }

        $newTitle = encrypt_with_parts($titlePlain, $currentParts);
        $newHtml = encrypt_with_parts($htmlPlain, $currentParts);
        $newText = encrypt_with_parts($textPlain, $currentParts);

        if ($newTitle === $titleCipher && $newHtml === $htmlCipher && $newText === $textCipher) {
            $skipped++;
            continue;
        }

        if (!$dryRun) {
            $update->execute([$newTitle, $newHtml, $newText, $id]);
        }
        $updated++;
    }

    if (!$dryRun) {
        $db->commit();
    }
} catch (Throwable $e) {
    if (!$dryRun && $db->inTransaction()) {
        $db->rollBack();
    }
    throw $e;
}

fwrite(STDOUT, sprintf(
    "%s complete. updated=%d skipped=%d failed=%d\n",
    $dryRun ? 'Dry run' : 'Rotation',
    $updated,
    $skipped,
    $failed
));

if ($failed > 0) {
    exit(2);
}

exit(0);

function env_string(string $name, string $default = ''): string
{
    $val = getenv($name);
    if ($val === false) {
        return trim($default);
    }
    return trim((string) $val);
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

function decrypt_text_with_keyring(string $value, array $keyring): ?string
{
    if (!str_starts_with($value, ENC_PREFIX)) {
        return $value;
    }

    $token = substr($value, strlen(ENC_PREFIX));
    $raw = base64url_decode($token);
    if (!is_string($raw)) {
        return null;
    }

    $minLen = 1 + 8 + 16 + 32;
    if (strlen($raw) < $minLen || ord($raw[0]) !== 0x80) {
        return null;
    }

    $hmac = substr($raw, -32);
    $body = substr($raw, 0, -32);
    if (!is_string($hmac) || !is_string($body)) {
        return null;
    }

    $iv = substr($raw, 9, 16);
    $ciphertext = substr($raw, 25, -32);
    if (!is_string($iv) || !is_string($ciphertext)) {
        return null;
    }

    foreach ($keyring as $parts) {
        $signing = (string) ($parts['signing'] ?? '');
        $encryption = (string) ($parts['encryption'] ?? '');
        if (strlen($signing) !== 16 || strlen($encryption) !== 16) {
            continue;
        }

        $expected = hash_hmac('sha256', $body, $signing, true);
        if (!hash_equals($expected, $hmac)) {
            continue;
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-128-cbc',
            $encryption,
            OPENSSL_RAW_DATA,
            $iv
        );

        return is_string($plaintext) ? $plaintext : null;
    }

    return null;
}

function encrypt_with_parts(string $plaintext, array $parts): string
{
    $signing = (string) ($parts['signing'] ?? '');
    $encryption = (string) ($parts['encryption'] ?? '');
    if (strlen($signing) !== 16 || strlen($encryption) !== 16) {
        return ENC_PREFIX;
    }

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
