<?php
declare(strict_types=1);

/**
 * Single-file server file manager.
 * Requires PHP 8.1+. Upload this file and open it over HTTPS.
 * The first visit creates the administrator. Secrets stay in .fmdata/.
 */

const FM_VERSION = '1.0.0';
const FM_DATA = '.fmdata';

final class FmException extends RuntimeException
{
    public function __construct(string $message, int $status = 422)
    {
        parent::__construct($message, $status);
    }
}

final class FmCrypto
{
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function randomHex(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    public static function hashPassword(string $password): string
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $hash = password_hash($password, $algo);
        if ($hash === false) {
            throw new FmException('Password hashing is unavailable.', 500);
        }
        return $hash;
    }

    public static function passwordOk(string $password, string $hash): bool
    {
        return $hash !== '' && password_verify($password, $hash);
    }

    public static function encrypt(string $plain, string $keyHex): string
    {
        $key = hash('sha256', $keyHex, true);
        if (function_exists('sodium_crypto_secretbox')) {
            $skey = sodium_crypto_generichash($key, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            return 's1:' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $skey));
        }
        if (!function_exists('openssl_encrypt')) {
            throw new FmException('Encryption is unavailable on this server.', 500);
        }
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ct === false || strlen($tag) !== 16) {
            throw new FmException('Encryption failed.', 500);
        }
        return 'g1:' . base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $payload, string $keyHex): string
    {
        $key = hash('sha256', $keyHex, true);
        if (str_starts_with($payload, 's1:') && function_exists('sodium_crypto_secretbox_open')) {
            $raw = base64_decode(substr($payload, 3), true);
            $n = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
            if ($raw === false || strlen($raw) <= $n) {
                throw new FmException('Stored secret could not be read.', 500);
            }
            $skey = sodium_crypto_generichash($key, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
            $plain = sodium_crypto_secretbox_open(substr($raw, $n), substr($raw, 0, $n), $skey);
            if ($plain === false) {
                throw new FmException('Stored secret could not be read.', 500);
            }
            return $plain;
        }
        if (!str_starts_with($payload, 'g1:') || !function_exists('openssl_decrypt')) {
            throw new FmException('Stored secret could not be read.', 500);
        }
        $raw = base64_decode(substr($payload, 3), true);
        if ($raw === false || strlen($raw) < 29) {
            throw new FmException('Stored secret could not be read.', 500);
        }
        $plain = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
        if ($plain === false) {
            throw new FmException('Stored secret could not be read.', 500);
        }
        return $plain;
    }

    public static function base32Encode(string $bin): string
    {
        $bits = '';
        $len = strlen($bin);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($bin[$i])), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $out .= self::B32[bindec($chunk)];
        }
        return $out;
    }

    public static function base32Decode(string $text): string
    {
        $text = strtoupper((string)preg_replace('/[^A-Za-z2-7]/', '', $text));
        $bits = '';
        $len = strlen($text);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::B32, $text[$i]);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }

    public static function totp(string $secret, ?int $time = null, int $digits = 6, int $period = 30): string
    {
        $counter = intdiv($time ?? time(), $period);
        $key = self::base32Decode($secret);
        if ($key === '') {
            return '';
        }
        $high = ($counter >> 32) & 0xFFFFFFFF;
        $low = $counter & 0xFFFFFFFF;
        $hash = hash_hmac('sha1', pack('N2', $high, $low), $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF)
        ) % (10 ** $digits);
        return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
    }

    public static function totpValid(string $secret, string $code, int $window = 1): bool
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }
        $now = time();
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals(self::totp($secret, $now + ($i * 30)), $code)) {
                return true;
            }
        }
        return false;
    }

    public static function recoveryCode(): string
    {
        $raw = strtoupper(bin2hex(random_bytes(10)));
        return implode('-', str_split($raw, 5));
    }

    public static function normalizeRecovery(string $code): string
    {
        return strtoupper((string)preg_replace('/[^A-Fa-f0-9]/', '', $code));
    }
}

final class FmStore
{
    public string $dir;
    public string $configFile;

    public function __construct(string $scriptDir)
    {
        $this->dir = $scriptDir . DIRECTORY_SEPARATOR . FM_DATA;
        $this->configFile = $this->dir . DIRECTORY_SEPARATOR . 'config.php';
    }

    public function ensureLayout(): void
    {
        foreach ([$this->dir, $this->dir . DIRECTORY_SEPARATOR . 'sessions', $this->dir . DIRECTORY_SEPARATOR . 'tmp'] as $dir) {
            if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new FmException('The data directory is not writable.', 500);
            }
        }
        $ht = $this->dir . DIRECTORY_SEPARATOR . '.htaccess';
        if (!is_file($ht)) {
            file_put_contents($ht, "Require all denied\nDeny from all\n");
        }
        $web = $this->dir . DIRECTORY_SEPARATOR . 'web.config';
        if (!is_file($web)) {
            file_put_contents($web, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><security><authorization><remove users=\"*\" roles=\"\" verbs=\"\" /><add accessType=\"Deny\" users=\"*\" /></authorization></security></system.webServer></configuration>\n");
        }
        $index = $this->dir . DIRECTORY_SEPARATOR . 'index.php';
        if (!is_file($index)) {
            file_put_contents($index, "<?php\nhttp_response_code(404);\nexit;\n");
        }
        @chmod($this->dir, 0700);
    }

    public function installed(): bool
    {
        return is_file($this->configFile);
    }

    public function load(): array
    {
        if (!$this->installed()) {
            throw new FmException('Setup is required.', 401);
        }
        $cfg = include $this->configFile;
        if (!is_array($cfg) || empty($cfg['user']['password_hash']) || empty($cfg['app_key'])) {
            throw new FmException('Configuration could not be read.', 500);
        }
        $cfg['settings'] = array_merge(self::defaults(), is_array($cfg['settings'] ?? null) ? $cfg['settings'] : []);
        return $cfg;
    }

    public function save(array $cfg): void
    {
        $export = var_export($cfg, true);
        $php = "<?php\n";
        $php .= "if (realpath((string)(\$_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {\n";
        $php .= "    http_response_code(404);\n    exit;\n}\n";
        $php .= "return {$export};\n";
        $tmp = $this->configFile . '.tmp';
        if (file_put_contents($tmp, $php, LOCK_EX) === false) {
            throw new FmException('Configuration could not be saved.', 500);
        }
        @chmod($tmp, 0600);
        $this->replaceFile($tmp, $this->configFile);
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($this->configFile, true);
        }
    }

    public function lock(callable $fn): mixed
    {
        $lockPath = $this->dir . DIRECTORY_SEPARATOR . 'write.lock';
        $fh = fopen($lockPath, 'c');
        if ($fh === false) {
            throw new FmException('Could not lock configuration.', 500);
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                throw new FmException('Could not lock configuration.', 500);
            }
            return $fn();
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    public function audit(array $row): void
    {
        $file = $this->dir . DIRECTORY_SEPARATOR . 'audit.log';
        if (is_file($file) && filesize($file) > 2000000) {
            @unlink($file . '.1');
            @rename($file, $file . '.1');
        }
        $line = json_encode($row, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($line === false) {
            return;
        }
        file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
        @chmod($file, 0600);
    }

    public function tail(string $file, int $maxBytes = 131072, int $maxLines = 200): string
    {
        if (!is_file($file) || !is_readable($file)) {
            return '';
        }
        $size = filesize($file);
        if ($size === false) {
            return '';
        }
        $fh = fopen($file, 'rb');
        if ($fh === false) {
            return '';
        }
        $start = max(0, $size - $maxBytes);
        fseek($fh, $start);
        $data = stream_get_contents($fh) ?: '';
        fclose($fh);
        if ($start > 0) {
            $nl = strpos($data, "\n");
            if ($nl !== false) {
                $data = substr($data, $nl + 1);
            }
        }
        $lines = preg_split("/\r\n|\n|\r/", $data) ?: [];
        if (count($lines) > $maxLines) {
            $lines = array_slice($lines, -$maxLines);
        }
        return implode("\n", $lines);
    }

    public function ratePath(): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . 'rate.json';
    }

    public function cleanTmp(int $maxAge = 3600): void
    {
        $tmp = $this->dir . DIRECTORY_SEPARATOR . 'tmp';
        foreach (glob($tmp . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_file($file) && (time() - (int)filemtime($file)) > $maxAge) {
                @unlink($file);
            }
        }
    }

    private function replaceFile(string $from, string $to): void
    {
        if (PHP_OS_FAMILY === 'Windows' && is_file($to)) {
            $bak = $to . '.bak';
            @unlink($bak);
            if (!rename($to, $bak)) {
                @unlink($from);
                throw new FmException('Configuration could not be saved.', 500);
            }
            if (!rename($from, $to)) {
                @rename($bak, $to);
                throw new FmException('Configuration could not be saved.', 500);
            }
            @unlink($bak);
            return;
        }
        if (!rename($from, $to)) {
            @unlink($from);
            throw new FmException('Configuration could not be saved.', 500);
        }
    }

    public static function defaults(): array
    {
        return [
            'session_timeout' => 1800,
            'max_upload_mb' => 32,
            'editor_max_kb' => 256,
            'allowed_extensions' => [],
            'blocked_extensions' => ['svg', 'env', 'ini', 'exe', 'dll', 'so', 'bat', 'cmd', 'sh', 'bash', 'ps1'],
            'theme' => 'system',
            'language' => 'en',
            'timezone' => 'UTC',
            'default_directory' => '',
            'show_hidden' => false,
            'terminal_enabled' => false,
            'terminal_allowlist' => ['ls', 'pwd', 'df', 'du', 'free', 'uptime', 'whoami', 'date', 'uname', 'id', 'ps', 'hostname', 'nproc', 'stat', 'wc'],
            'login_max_attempts' => 5,
            'login_lock_minutes' => 15,
            'audit_enabled' => true,
            'brand_name' => 'File Manager',
            'root_path' => '',
            'extra_logs' => [],
        ];
    }

    public static function hardBlocked(): array
    {
        return [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht', 'phps', 'inc',
            'cgi', 'pl', 'asp', 'aspx', 'jsp', 'jspx', 'shtml', 'htaccess', 'htpasswd',
        ];
    }

    public static function dangerousBasename(string $name): bool
    {
        $base = strtolower(basename(str_replace('\\', '/', $name)));
        return in_array($base, ['.htaccess', '.user.ini', '.htpasswd', '.php.ini', 'web.config'], true);
    }
}

final class FmPath
{
    public function __construct(private string $root)
    {
        $real = realpath($root);
        if ($real === false || !is_dir($real)) {
            throw new FmException('Root directory is not available.', 500);
        }
        $this->root = $real;
    }

    public function root(): string
    {
        return $this->root;
    }

    public static function validName(string $name): bool
    {
        if ($name === '' || $name === '.' || $name === '..' || strlen($name) > 255) {
            return false;
        }
        if (preg_match('/[\x00-\x1F\/\\\\]/', $name)) {
            return false;
        }
        if ($name !== trim($name) || str_ends_with($name, '.') || str_ends_with($name, ' ')) {
            return false;
        }
        return !preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i', $name);
    }

    public function lexical(string $relative): string
    {
        $relative = str_replace("\0", '', $relative);
        $relative = str_replace('\\', '/', $relative);
        $relative = trim($relative);
        if ($relative === '' || $relative === '.' || $relative === '/') {
            return $this->root;
        }
        if (str_contains($relative, ':') || str_starts_with($relative, '/')) {
            throw new FmException('Absolute paths are not allowed.', 403);
        }
        $parts = [];
        foreach (explode('/', $relative) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                if ($parts === []) {
                    throw new FmException('Path is outside the root.', 403);
                }
                array_pop($parts);
                continue;
            }
            if (!self::validName($part)) {
                throw new FmException('Invalid file name.', 422);
            }
            $parts[] = $part;
        }
        if ($parts === []) {
            return $this->root;
        }
        return $this->root . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    }

    public function resolve(string $relative, bool $mustExist = true, bool $follow = true): string
    {
        $full = $this->lexical($relative);
        if ($full === $this->root) {
            $this->assertInside($this->root);
            return $this->root;
        }
        if (!$follow) {
            $parent = dirname($full);
            $realParent = realpath($parent);
            if ($realParent === false || !is_dir($realParent)) {
                throw new FmException('Path not found.', 404);
            }
            $this->assertInside($realParent);
            $path = $realParent . DIRECTORY_SEPARATOR . basename($full);
            $this->assertInside($path);
            if ($mustExist && !file_exists($path) && !is_link($path)) {
                throw new FmException('Path not found.', 404);
            }
            return $path;
        }
        if ($mustExist || file_exists($full) || is_link($full)) {
            $real = realpath($full);
            if ($real === false) {
                throw new FmException('Path not found.', 404);
            }
            $this->assertInside($real);
            return $real;
        }
        $parent = dirname($full);
        $realParent = realpath($parent);
        if ($realParent === false || !is_dir($realParent)) {
            throw new FmException('Parent directory not found.', 404);
        }
        $this->assertInside($realParent);
        $path = $realParent . DIRECTORY_SEPARATOR . basename($full);
        $this->assertInside($path);
        return $path;
    }

    public function assertInside(string $path): void
    {
        if (!$this->isInside($path)) {
            throw new FmException('Path is outside the root.', 403);
        }
    }

    public function isInside(string $path): bool
    {
        return self::within($path, $this->root);
    }

    public static function within(string $path, string $root): bool
    {
        $path = rtrim(str_replace('\\', '/', $path), '/');
        $root = rtrim(str_replace('\\', '/', $root), '/');
        if ($path === '' || $root === '') {
            return false;
        }
        if (PHP_OS_FAMILY === 'Windows') {
            $path = strtolower($path);
            $root = strtolower($root);
        }
        return $path === $root || str_starts_with($path, $root . '/');
    }

    public function relative(string $absolute): string
    {
        $abs = rtrim(str_replace('\\', '/', $absolute), '/');
        $root = rtrim(str_replace('\\', '/', $this->root), '/');
        if (PHP_OS_FAMILY === 'Windows') {
            if (strtolower($abs) === strtolower($root)) {
                return '';
            }
            if (str_starts_with(strtolower($abs), strtolower($root) . '/')) {
                return substr($abs, strlen($root) + 1);
            }
        } elseif ($abs === $root) {
            return '';
        } elseif (str_starts_with($abs, $root . '/')) {
            return substr($abs, strlen($root) + 1);
        }
        throw new FmException('Path is outside the root.', 403);
    }

    public static function uploadBlocked(string $name, array $extraBlocked, array $allow): bool
    {
        if (FmStore::dangerousBasename($name)) {
            return true;
        }
        $lower = strtolower($name);
        $parts = explode('.', $lower);
        if (count($parts) < 2) {
            return $allow !== [];
        }
        $exts = array_slice($parts, 1);
        foreach ($exts as $ext) {
            if ($ext === '' || in_array($ext, FmStore::hardBlocked(), true) || in_array($ext, $extraBlocked, true)) {
                return true;
            }
        }
        $last = (string)end($exts);
        return $allow !== [] && !in_array($last, $allow, true);
    }

    public static function scriptLike(string $name): bool
    {
        return self::uploadBlocked($name, [], []);
    }

    public static function safeZipEntry(string $name): ?string
    {
        $name = str_replace('\\', '/', $name);
        if ($name === '' || str_contains($name, "\0") || str_contains($name, ':') || str_starts_with($name, '/')) {
            return null;
        }
        $parts = [];
        foreach (explode('/', $name) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..' || !self::validName($part)) {
                return null;
            }
            $parts[] = $part;
        }
        return $parts === [] ? null : implode('/', $parts);
    }
}

final class FmAuth
{
    public function __construct(private FmStore $store, private array $cfg)
    {
    }

    public function config(): array
    {
        return $this->cfg;
    }

    public function reload(): void
    {
        $this->cfg = $this->store->load();
    }

    public function timeout(): int
    {
        return (int)$this->cfg['settings']['session_timeout'];
    }

    public function fingerprint(): string
    {
        return hash('sha256', (string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    }

    public function checkOrigin(): void
    {
        if (empty($_SERVER['HTTP_ORIGIN'])) {
            return;
        }
        $originHost = parse_url((string)$_SERVER['HTTP_ORIGIN'], PHP_URL_HOST);
        $host = preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? ''));
        if (!is_string($originHost) || !is_string($host) || !hash_equals(strtolower($host), strtolower($originHost))) {
            throw new FmException('Request origin was rejected.', 403);
        }
    }

    public function csrfOk(?string $token): void
    {
        $known = (string)($_SESSION['csrf'] ?? '');
        if ($known === '' || !is_string($token) || !hash_equals($known, $token)) {
            throw new FmException('Security token mismatch. Reload the page.', 403);
        }
    }

    public function loggedIn(): bool
    {
        return !empty($_SESSION['auth']) && hash_equals((string)($_SESSION['user'] ?? ''), (string)$this->cfg['user']['username']);
    }

    public function requireAuth(): void
    {
        if (!$this->loggedIn()) {
            throw new FmException('Sign in required.', 401);
        }
        $last = (int)($_SESSION['last'] ?? 0);
        if ($last > 0 && (time() - $last) > $this->timeout()) {
            $this->destroy();
            throw new FmException('Session expired.', 401);
        }
        if (!hash_equals((string)($_SESSION['fp'] ?? ''), $this->fingerprint())) {
            $this->destroy();
            throw new FmException('Session expired.', 401);
        }
        if ((time() - (int)($_SESSION['reg'] ?? 0)) > 900) {
            session_regenerate_id(true);
            $_SESSION['reg'] = time();
        }
        $_SESSION['last'] = time();
    }

    public function login(string $username, string $password): array
    {
        $this->assertNotLocked();
        $knownUser = (string)$this->cfg['user']['username'];
        $userMatch = hash_equals(hash('sha256', strtolower($knownUser)), hash('sha256', strtolower($username)));
        $hash = $userMatch ? (string)$this->cfg['user']['password_hash'] : (string)$this->cfg['dummy_hash'];
        $verified = FmCrypto::passwordOk($password, $hash);
        if (!$userMatch || !$verified) {
            $this->failLogin();
            throw new FmException('Invalid username or password.', 401);
        }
        $this->clearFailures();
        session_regenerate_id(true);
        $_SESSION = [];
        $_SESSION['csrf'] = FmCrypto::randomHex(32);
        $_SESSION['fp'] = $this->fingerprint();
        $_SESSION['reg'] = time();
        $_SESSION['last'] = time();
        if (!empty($this->cfg['user']['totp_enabled'])) {
            $_SESSION['pre_auth'] = true;
            $_SESSION['pre_user'] = $knownUser;
            $_SESSION['pre_at'] = time();
            return ['totp' => true];
        }
        $this->completeLogin($knownUser);
        return ['totp' => false];
    }

    public function verifyTotp(string $code): void
    {
        if (empty($_SESSION['pre_auth']) || (time() - (int)($_SESSION['pre_at'] ?? 0)) > 300) {
            $this->destroy();
            throw new FmException('Sign in required.', 401);
        }
        $this->assertNotLocked();
        $secret = FmCrypto::decrypt((string)$this->cfg['user']['totp_secret'], (string)$this->cfg['app_key']);
        $valid = FmCrypto::totpValid($secret, $code);
        $usedRecovery = false;
        if (!$valid) {
            $usedRecovery = $this->consumeRecovery($code);
        }
        if (!$valid && !$usedRecovery) {
            $this->failLogin();
            throw new FmException('Invalid authentication code.', 401);
        }
        $user = (string)$_SESSION['pre_user'];
        $this->clearFailures();
        session_regenerate_id(true);
        $_SESSION = [];
        $_SESSION['csrf'] = FmCrypto::randomHex(32);
        $_SESSION['fp'] = $this->fingerprint();
        $_SESSION['reg'] = time();
        $_SESSION['last'] = time();
        $this->completeLogin($user);
        if ($usedRecovery) {
            $_SESSION['recovery_used'] = true;
        }
    }

    public function destroy(): void
    {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool)$params['secure'], true);
            session_destroy();
        }
    }

    private function completeLogin(string $user): void
    {
        $_SESSION['auth'] = true;
        $_SESSION['user'] = $user;
        $_SESSION['recent'] = [];
    }

    private function key(): string
    {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $ip = '0.0.0.0';
        }
        return hash_hmac('sha256', $ip, (string)$this->cfg['app_key']);
    }

    private function readRates(): array
    {
        $file = $this->store->ratePath();
        if (!is_file($file)) {
            return [];
        }
        $data = json_decode((string)file_get_contents($file), true);
        return is_array($data) ? $data : [];
    }

    private function writeRates(array $data): void
    {
        file_put_contents($this->store->ratePath(), json_encode($data), LOCK_EX);
        @chmod($this->store->ratePath(), 0600);
    }

    private function assertNotLocked(): void
    {
        $rates = $this->readRates();
        $row = $rates[$this->key()] ?? null;
        if (is_array($row) && (int)($row['until'] ?? 0) > time()) {
            throw new FmException('Too many attempts. Try again later.', 429);
        }
    }

    private function failLogin(): void
    {
        $rates = $this->readRates();
        $key = $this->key();
        $window = max(60, (int)$this->cfg['settings']['login_lock_minutes'] * 60);
        $now = time();
        $row = is_array($rates[$key] ?? null) ? $rates[$key] : ['count' => 0, 'start' => $now, 'until' => 0];
        if (($now - (int)($row['start'] ?? 0)) > $window) {
            $row = ['count' => 0, 'start' => $now, 'until' => 0];
        }
        $row['count'] = (int)($row['count'] ?? 0) + 1;
        $max = (int)$this->cfg['settings']['login_max_attempts'];
        if ($row['count'] >= $max) {
            $row['until'] = $now + $window;
            $row['count'] = 0;
            $row['start'] = $now;
        }
        $rates[$key] = $row;
        if (count($rates) > 500) {
            $rates = array_slice($rates, -200, null, true);
        }
        $this->writeRates($rates);
    }

    private function clearFailures(): void
    {
        $rates = $this->readRates();
        unset($rates[$this->key()]);
        $this->writeRates($rates);
    }

    private function consumeRecovery(string $code): bool
    {
        $norm = FmCrypto::normalizeRecovery($code);
        if (strlen($norm) !== 20) {
            return false;
        }
        $hashes = $this->cfg['user']['recovery_hashes'] ?? [];
        if (!is_array($hashes)) {
            return false;
        }
        foreach ($hashes as $i => $hash) {
            if (is_string($hash) && password_verify($norm, $hash)) {
                unset($hashes[$i]);
                $this->store->lock(function () use ($hashes) {
                    $cfg = $this->store->load();
                    $cfg['user']['recovery_hashes'] = array_values($hashes);
                    $this->store->save($cfg);
                });
                $this->reload();
                return true;
            }
        }
        return false;
    }
}

final class FmFiles
{
    public function __construct(private FmPath $paths, private string $dataDir, private string $scriptFile, private array $settings)
    {
    }

    public function list(string $relative): array
    {
        $dir = $this->paths->resolve($relative, true, true);
        if (!is_dir($dir)) {
            throw new FmException('Directory not found.', 404);
        }
        $items = [];
        $count = 0;
        $dh = opendir($dir);
        if ($dh === false) {
            throw new FmException('Directory cannot be read.', 403);
        }
        while (($name = readdir($dh)) !== false) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $full = $dir . DIRECTORY_SEPARATOR . $name;
            if ($this->isData($full)) {
                continue;
            }
            $count++;
            if ($count > 5000) {
                break;
            }
            $items[] = $this->describe($full, $name, $this->paths->relative($dir));
        }
        closedir($dh);
        return [
            'path' => $this->paths->relative($dir),
            'items' => $items,
            'truncated' => $count > 5000,
        ];
    }

    public function mkdir(string $relative, string $name): string
    {
        if (!FmPath::validName($name)) {
            throw new FmException('Invalid folder name.');
        }
        $parent = $this->paths->resolve($relative, true, true);
        if (!is_dir($parent)) {
            throw new FmException('Directory not found.', 404);
        }
        $dest = $parent . DIRECTORY_SEPARATOR . $name;
        $this->guardNew($dest);
        if (file_exists($dest)) {
            throw new FmException('Already exists.');
        }
        if (!mkdir($dest, 0755)) {
            throw new FmException('Folder could not be created.');
        }
        return $this->paths->relative($dest);
    }

    public function create(string $relative, string $name): string
    {
        if (!FmPath::validName($name) || FmStore::dangerousBasename($name)) {
            throw new FmException('Invalid file name.');
        }
        $parent = $this->paths->resolve($relative, true, true);
        $dest = $parent . DIRECTORY_SEPARATOR . $name;
        $this->guardNew($dest);
        if (file_exists($dest)) {
            throw new FmException('Already exists.');
        }
        if (file_put_contents($dest, '') === false) {
            throw new FmException('File could not be created.');
        }
        @chmod($dest, 0644);
        return $this->paths->relative($dest);
    }

    public function rename(string $relative, string $name): string
    {
        if (!FmPath::validName($name) || FmStore::dangerousBasename($name)) {
            throw new FmException('Invalid file name.');
        }
        $src = $this->paths->resolve($relative, true, false);
        $this->assertMutable($src);
        if ($this->containsProtected($src)) {
            throw new FmException('That location is protected.', 403);
        }
        $dest = dirname($src) . DIRECTORY_SEPARATOR . $name;
        $this->guardNew($dest);
        if (file_exists($dest) || is_link($dest)) {
            throw new FmException('Already exists.');
        }
        if (!rename($src, $dest)) {
            throw new FmException('Rename failed.');
        }
        return $this->paths->relative($dest);
    }

    public function move(array $rels, string $destDir): int
    {
        $dest = $this->paths->resolve($destDir, true, true);
        if (!is_dir($dest)) {
            throw new FmException('Destination is not a directory.');
        }
        $n = 0;
        foreach ($rels as $rel) {
            $src = $this->paths->resolve((string)$rel, true, false);
            $this->assertMutable($src);
            if ($this->paths->isInside($dest) && self::samePath(dirname($src), $dest)) {
                continue;
            }
            $target = $dest . DIRECTORY_SEPARATOR . basename($src);
            $this->guardNew($target);
            if ($this->contains($src, $target)) {
                throw new FmException('Cannot move a directory into itself.');
            }
            if ($this->containsProtected($src) || $this->containsProtected($target)) {
                throw new FmException('That location is protected.', 403);
            }
            if (file_exists($target) || is_link($target)) {
                throw new FmException('Already exists.');
            }
            if (!rename($src, $target)) {
                throw new FmException('Move failed.');
            }
            $n++;
        }
        return $n;
    }

    public function copy(array $rels, string $destDir): int
    {
        $dest = $this->paths->resolve($destDir, true, true);
        if (!is_dir($dest)) {
            throw new FmException('Destination is not a directory.');
        }
        $n = 0;
        $count = 0;
        foreach ($rels as $rel) {
            $src = $this->paths->resolve((string)$rel, true, true);
            if ($this->containsProtected($src)) {
                throw new FmException('That location is protected.', 403);
            }
            if (is_dir($src) && (self::samePath($dest, $src) || FmPath::within($dest, $src))) {
                throw new FmException('Cannot copy a directory into itself.');
            }
            $target = $dest . DIRECTORY_SEPARATOR . basename($src);
            $this->guardNew($target);
            if (file_exists($target)) {
                throw new FmException('Already exists.');
            }
            $this->copyRecursive($src, $target, $count);
            $n++;
        }
        return $n;
    }

    public function duplicate(array $rels): array
    {
        $made = [];
        $count = 0;
        foreach ($rels as $rel) {
            $src = $this->paths->resolve((string)$rel, true, true);
            if ($this->containsProtected($src)) {
                throw new FmException('That location is protected.', 403);
            }
            $dest = $this->duplicateName($src);
            $this->guardNew($dest);
            $this->copyRecursive($src, $dest, $count);
            $made[] = $this->paths->relative($dest);
        }
        return $made;
    }

    public function delete(array $rels): int
    {
        $paths = [];
        foreach ($rels as $rel) {
            $src = $this->paths->resolve((string)$rel, true, false);
            if (self::samePath($src, $this->paths->root())) {
                throw new FmException('The root directory cannot be deleted.', 403);
            }
            if ($this->containsProtected($src)) {
                throw new FmException('That location is protected.', 403);
            }
            $paths[] = $src;
        }
        $count = 0;
        foreach ($paths as $src) {
            $this->deleteRecursive($src, $count);
        }
        return $count;
    }

    public function chmod(string $relative, string $mode): void
    {
        if (!preg_match('/^0?[0-7]{3}$/', $mode)) {
            throw new FmException('Permissions must be a three-digit octal mode.');
        }
        $path = $this->paths->resolve($relative, true, false);
        $this->assertMutable($path);
        $bits = octdec($mode);
        if (($bits & 06000) !== 0) {
            throw new FmException('Setuid and setgid are not allowed.', 403);
        }
        if (!chmod($path, $bits)) {
            throw new FmException('Permissions could not be changed.');
        }
    }

    public function read(string $relative, int $maxBytes): array
    {
        $path = $this->paths->resolve($relative, true, true);
        if (!is_file($path)) {
            throw new FmException('File not found.', 404);
        }
        $size = filesize($path);
        if ($size === false || $size > $maxBytes) {
            throw new FmException('File is too large to edit.');
        }
        $fh = fopen($path, 'rb');
        $sample = $fh ? (string)fread($fh, 8192) : '';
        if ($fh) {
            fclose($fh);
        }
        if (str_contains($sample, "\0")) {
            throw new FmException('Binary files cannot be edited here.');
        }
        $content = file_get_contents($path);
        if ($content === false) {
            throw new FmException('File could not be read.');
        }
        return [
            'path' => $this->paths->relative($path),
            'name' => basename($path),
            'size' => $size,
            'content' => $content,
            'script' => FmPath::scriptLike(basename($path)),
        ];
    }

    public function write(string $relative, string $content, int $maxBytes): void
    {
        if (strlen($content) > $maxBytes) {
            throw new FmException('Content exceeds the editor limit.');
        }
        $path = $this->paths->resolve($relative, true, true);
        if (!is_file($path)) {
            throw new FmException('File not found.', 404);
        }
        $this->assertMutable($path);
        if (FmStore::dangerousBasename(basename($path))) {
            throw new FmException('That file is protected.', 403);
        }
        $tmp = $path . '.fmwrite';
        if (file_put_contents($tmp, $content, LOCK_EX) === false) {
            throw new FmException('File could not be saved.');
        }
        $this->replaceFile($tmp, $path);
    }

    public function upload(string $relative, array $files): array
    {
        $dir = $this->paths->resolve($relative, true, true);
        if (!is_dir($dir) || !is_writable($dir)) {
            throw new FmException('Upload directory is not writable.', 403);
        }
        $saved = [];
        $list = $this->normalizeFiles($files);
        if (count($list) > 20) {
            throw new FmException('Upload at most 20 files at a time.');
        }
        $limit = $this->uploadLimit();
        foreach ($list as $file) {
            if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new FmException($this->uploadError((int)$file['error']));
            }
            if ((int)$file['size'] > $limit) {
                throw new FmException('A file exceeds the upload limit.');
            }
            $name = basename(str_replace(["\0", '\\', '/'], '', (string)$file['name']));
            if (!FmPath::validName($name) || FmPath::uploadBlocked($name, $this->extList('blocked_extensions'), $this->extList('allowed_extensions'))) {
                throw new FmException('File type is not allowed: ' . $name);
            }
            $tmp = (string)$file['tmp_name'];
            if (!is_uploaded_file($tmp)) {
                throw new FmException('Upload was rejected.', 403);
            }
            $mime = $this->mime($tmp);
            if (in_array($mime, ['application/x-httpd-php', 'text/x-php', 'application/x-php'], true)) {
                throw new FmException('File type is not allowed: ' . $name);
            }
            $dest = $this->unique($dir . DIRECTORY_SEPARATOR . $name);
            $this->guardNew($dest);
            if (!move_uploaded_file($tmp, $dest)) {
                throw new FmException('Upload could not be stored.');
            }
            @chmod($dest, 0644);
            $saved[] = $this->paths->relative($dest);
        }
        return $saved;
    }

    public function search(string $relative, string $query, bool $contents): array
    {
        $query = trim($query);
        if (strlen($query) < 2 || strlen($query) > 80 || str_contains($query, "\0")) {
            throw new FmException('Enter between 2 and 80 characters.');
        }
        $dir = $this->paths->resolve($relative, true, true);
        $hits = [];
        $count = 0;
        $this->walkSearch($dir, $query, $contents, $hits, $count, microtime(true) + 8);
        return ['hits' => $hits, 'truncated' => $count >= 8000 || count($hits) >= 200];
    }

    public function describePath(string $relative): array
    {
        $path = $this->paths->resolve($relative, true, false);
        return $this->describe($path, basename($path), $this->paths->relative(dirname($path)));
    }

    public function absolute(string $relative, bool $follow = true): string
    {
        return $this->paths->resolve($relative, true, $follow);
    }

    public function paths(): FmPath
    {
        return $this->paths;
    }

    public function isData(string $path): bool
    {
        $data = realpath($this->dataDir);
        return $data !== false && FmPath::within($path, $data);
    }

    public function assertMutable(string $path): void
    {
        if ($this->isData($path) || self::samePath($path, $this->scriptFile)) {
            throw new FmException('That location is protected.', 403);
        }
    }

    private function containsProtected(string $path): bool
    {
        $self = realpath($this->scriptFile);
        $data = realpath($this->dataDir);
        $dir = is_dir($path) && !is_link($path);
        if ($self && (self::samePath($path, $self) || ($dir && FmPath::within($self, $path)))) {
            return true;
        }
        return $data !== false && (self::samePath($path, $data) || ($dir && FmPath::within($data, $path)));
    }

    private function replaceFile(string $from, string $to): void
    {
        if (PHP_OS_FAMILY === 'Windows' && is_file($to)) {
            $bak = $to . '.fmbak';
            @unlink($bak);
            if (!rename($to, $bak)) {
                @unlink($from);
                throw new FmException('File could not be saved.');
            }
            if (!rename($from, $to)) {
                @rename($bak, $to);
                @unlink($from);
                throw new FmException('File could not be saved.');
            }
            @unlink($bak);
            return;
        }
        if (!rename($from, $to)) {
            @unlink($from);
            throw new FmException('File could not be saved.');
        }
    }

    private function guardNew(string $path): void
    {
        $this->paths->assertInside($path);
        if ($this->isData($path) || self::samePath($path, $this->scriptFile)) {
            throw new FmException('That location is protected.', 403);
        }
    }

    private function describe(string $full, string $name, string $parent): array
    {
        $link = is_link($full);
        $dir = !$link && is_dir($full);
        $perms = @fileperms($full);
        $mode = is_int($perms) ? substr(sprintf('%o', $perms), -4) : '';
        $uid = @fileowner($full);
        $gid = @filegroup($full);
        $rel = $parent === '' || $parent === '.' ? $name : $parent . '/' . $name;
        if ($parent === '' && dirname($full) !== $full) {
            $rel = ltrim(str_replace('\\', '/', $this->paths->relative(dirname($full)) . '/' . $name), '/');
        }
        return [
            'name' => $name,
            'path' => $rel,
            'type' => $link ? 'link' : ($dir ? 'dir' : 'file'),
            'size' => (!$link && is_file($full)) ? (int)@filesize($full) : 0,
            'mtime' => (int)@filemtime($full),
            'perms' => $mode,
            'symbolic' => is_int($perms) ? self::symbolic($perms) : '',
            'owner' => self::ownerName(is_int($uid) ? $uid : -1),
            'group' => self::groupName(is_int($gid) ? $gid : -1),
            'hidden' => str_starts_with($name, '.'),
            'ext' => strtolower(pathinfo($name, PATHINFO_EXTENSION)),
            'writable' => is_writable($full),
            'protected' => self::samePath($full, $this->scriptFile),
        ];
    }

    private function copyRecursive(string $src, string $dest, int &$count): void
    {
        if (++$count > 10000) {
            throw new FmException('Copy limit reached.');
        }
        if ($this->isData($src)) {
            throw new FmException('That location is protected.', 403);
        }
        if (is_link($src)) {
            $real = realpath($src);
            if ($real === false || !$this->paths->isInside($real)) {
                throw new FmException('Refusing to copy a link that leaves the root.', 403);
            }
            $src = $real;
        }
        $this->paths->assertInside($src);
        $this->guardNew($dest);
        if (is_dir($src)) {
            if (!mkdir($dest, 0755) && !is_dir($dest)) {
                throw new FmException('Copy failed.');
            }
            $dh = opendir($src);
            if ($dh === false) {
                throw new FmException('Copy failed.');
            }
            while (($name = readdir($dh)) !== false) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $this->copyRecursive($src . DIRECTORY_SEPARATOR . $name, $dest . DIRECTORY_SEPARATOR . $name, $count);
            }
            closedir($dh);
            return;
        }
        if (!copy($src, $dest)) {
            throw new FmException('Copy failed.');
        }
        @chmod($dest, 0644);
    }

    private function deleteRecursive(string $path, int &$count): void
    {
        if (++$count > 10000) {
            throw new FmException('Delete limit reached.');
        }
        $this->paths->assertInside($path);
        $this->assertMutable($path);
        if (is_link($path)) {
            if (!unlink($path)) {
                throw new FmException('Delete failed.');
            }
            return;
        }
        if (is_dir($path)) {
            $dh = opendir($path);
            if ($dh === false) {
                throw new FmException('Delete failed.');
            }
            while (($name = readdir($dh)) !== false) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $this->deleteRecursive($path . DIRECTORY_SEPARATOR . $name, $count);
            }
            closedir($dh);
            if (!rmdir($path)) {
                throw new FmException('Delete failed.');
            }
            return;
        }
        if (!unlink($path)) {
            throw new FmException('Delete failed.');
        }
    }

    private function contains(string $dir, string $target): bool
    {
        if (!is_dir($dir) || is_link($dir)) {
            return false;
        }
        return FmPath::within($target, $dir);
    }

    private function duplicateName(string $src): string
    {
        $dir = dirname($src);
        $base = pathinfo($src, PATHINFO_FILENAME);
        $ext = pathinfo($src, PATHINFO_EXTENSION);
        for ($i = 0; $i < 50; $i++) {
            $suffix = $i === 0 ? ' copy' : ' copy ' . ($i + 1);
            $name = $base . $suffix . ($ext !== '' ? '.' . $ext : '');
            if (!FmPath::validName($name)) {
                continue;
            }
            $candidate = $dir . DIRECTORY_SEPARATOR . $name;
            if (!file_exists($candidate)) {
                return $candidate;
            }
        }
        throw new FmException('Could not find a free name.');
    }

    private function unique(string $dest): string
    {
        if (!file_exists($dest)) {
            return $dest;
        }
        $dir = dirname($dest);
        $base = pathinfo($dest, PATHINFO_FILENAME);
        $ext = pathinfo($dest, PATHINFO_EXTENSION);
        for ($i = 2; $i < 100; $i++) {
            $name = $base . '-' . $i . ($ext !== '' ? '.' . $ext : '');
            $candidate = $dir . DIRECTORY_SEPARATOR . $name;
            if (!file_exists($candidate)) {
                return $candidate;
            }
        }
        throw new FmException('Could not find a free name.');
    }

    private function walkSearch(string $dir, string $query, bool $contents, array &$hits, int &$count, float $deadline): void
    {
        if ($count >= 8000 || count($hits) >= 200 || microtime(true) > $deadline) {
            return;
        }
        $dh = @opendir($dir);
        if ($dh === false) {
            return;
        }
        $q = function_exists('mb_strtolower') ? mb_strtolower($query) : strtolower($query);
        while (($name = readdir($dh)) !== false) {
            if ($name === '.' || $name === '..' || $count >= 8000 || count($hits) >= 200) {
                continue;
            }
            $full = $dir . DIRECTORY_SEPARATOR . $name;
            if ($this->isData($full)) {
                continue;
            }
            $count++;
            $hay = function_exists('mb_strtolower') ? mb_strtolower($name) : strtolower($name);
            $nameHit = str_contains($hay, $q);
            if ($nameHit) {
                $hits[] = $this->describe($full, $name, $this->paths->relative($dir));
            }
            if (!$nameHit && $contents && !is_link($full) && is_file($full)) {
                $size = @filesize($full);
                if (is_int($size) && $size > 0 && $size <= 1048576 && $this->looksText($full) && $this->fileContains($full, $query)) {
                    $hits[] = $this->describe($full, $name, $this->paths->relative($dir));
                }
            }
            if (!is_link($full) && is_dir($full)) {
                $this->walkSearch($full, $query, $contents, $hits, $count, $deadline);
            }
        }
        closedir($dh);
    }

    private function looksText(string $path): bool
    {
        $fh = fopen($path, 'rb');
        if ($fh === false) {
            return false;
        }
        $sample = (string)fread($fh, 4096);
        fclose($fh);
        return !str_contains($sample, "\0");
    }

    private function fileContains(string $path, string $query): bool
    {
        $fh = fopen($path, 'rb');
        if ($fh === false) {
            return false;
        }
        $data = (string)fread($fh, 1048576);
        fclose($fh);
        return stripos($data, $query) !== false;
    }

    private function normalizeFiles(array $files): array
    {
        if (!isset($files['name'])) {
            return [];
        }
        if (!is_array($files['name'])) {
            return [$files];
        }
        $out = [];
        foreach ($files['name'] as $i => $name) {
            $out[] = [
                'name' => $name,
                'type' => $files['type'][$i] ?? '',
                'tmp_name' => $files['tmp_name'][$i] ?? '',
                'error' => $files['error'][$i] ?? UPLOAD_ERR_NO_FILE,
                'size' => $files['size'][$i] ?? 0,
            ];
        }
        return $out;
    }

    private function uploadError(int $code): string
    {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'A file exceeds the server upload limit.',
            UPLOAD_ERR_PARTIAL => 'A file was only partially uploaded.',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
            default => 'Upload failed.',
        };
    }

    private function mime(string $tmp): string
    {
        if (!class_exists('finfo')) {
            return 'application/octet-stream';
        }
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($tmp);
        return is_string($mime) ? $mime : 'application/octet-stream';
    }

    private function uploadLimit(): int
    {
        $setting = max(1, (int)$this->settings['max_upload_mb']) * 1048576;
        return (int)min($setting, FmHttp::iniBytes((string)ini_get('upload_max_filesize')), FmHttp::iniBytes((string)ini_get('post_max_size')));
    }

    private function extList(string $key): array
    {
        $list = $this->settings[$key] ?? [];
        return is_array($list) ? array_values(array_map('strval', $list)) : [];
    }

    public static function symbolic(int $perms): string
    {
        $type = match ($perms & 0xF000) {
            0x4000 => 'd',
            0xA000 => 'l',
            default => '-',
        };
        $flags = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
        return $type
            . $flags[($perms >> 6) & 7]
            . $flags[($perms >> 3) & 7]
            . $flags[$perms & 7];
    }

    private static function ownerName(int $uid): string
    {
        if ($uid < 0) {
            return '';
        }
        if (function_exists('posix_getpwuid')) {
            $info = posix_getpwuid($uid);
            if (is_array($info) && isset($info['name'])) {
                return (string)$info['name'];
            }
        }
        return (string)$uid;
    }

    private static function groupName(int $gid): string
    {
        if ($gid < 0) {
            return '';
        }
        if (function_exists('posix_getgrgid')) {
            $info = posix_getgrgid($gid);
            if (is_array($info) && isset($info['name'])) {
                return (string)$info['name'];
            }
        }
        return (string)$gid;
    }

    private static function samePath(string $a, string $b): bool
    {
        $a = rtrim(str_replace('\\', '/', $a), '/');
        $b = rtrim(str_replace('\\', '/', $b), '/');
        if (PHP_OS_FAMILY === 'Windows') {
            return strtolower($a) === strtolower($b);
        }
        return $a === $b;
    }
}

final class FmArchive
{
    public function __construct(private FmFiles $files, private string $tmpDir)
    {
    }

    public function available(): bool
    {
        return class_exists('ZipArchive');
    }

    public function create(array $rels, string $dirRel, string $zipName): string
    {
        if (!$this->available()) {
            throw new FmException('ZIP support is not available.', 500);
        }
        if (!FmPath::validName($zipName) || !str_ends_with(strtolower($zipName), '.zip')) {
            throw new FmException('Archive name must end in .zip.');
        }
        $dir = $this->files->absolute($dirRel, true);
        if (!is_dir($dir)) {
            throw new FmException('Directory not found.', 404);
        }
        $dest = $dir . DIRECTORY_SEPARATOR . $zipName;
        $this->files->assertMutable($dest);
        if (file_exists($dest)) {
            throw new FmException('Already exists.');
        }
        $zip = new ZipArchive();
        if ($zip->open($dest, ZipArchive::CREATE) !== true) {
            throw new FmException('Archive could not be created.');
        }
        $count = 0;
        try {
            foreach ($rels as $rel) {
                $path = $this->files->absolute((string)$rel, true);
                $this->add($zip, $path, basename($path), $count);
            }
        } catch (Throwable $e) {
            $zip->close();
            @unlink($dest);
            throw $e;
        }
        $zip->close();
        @chmod($dest, 0644);
        return $this->files->paths()->relative($dest);
    }

    public function extract(string $relative): array
    {
        if (!$this->available()) {
            throw new FmException('ZIP support is not available.', 500);
        }
        $zipPath = $this->files->absolute($relative, true);
        if (!is_file($zipPath) || strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) !== 'zip') {
            throw new FmException('Choose a ZIP file.');
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) {
            throw new FmException('Archive could not be opened.');
        }
        $total = 0;
        $entries = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            if ($i > 2000) {
                $zip->close();
                throw new FmException('Archive has too many files.');
            }
            $stat = $zip->statIndex($i);
            if (!is_array($stat)) {
                continue;
            }
            $total += (int)$stat['size'];
            if ($total > 500 * 1048576) {
                $zip->close();
                throw new FmException('Archive expands beyond the size limit.');
            }
            $safe = FmPath::safeZipEntry((string)$stat['name']);
            if ($safe === null) {
                $zip->close();
                throw new FmException('Archive contains an unsafe path.', 403);
            }
            $entries[] = [$i, $safe, str_ends_with((string)$stat['name'], '/')];
        }
        $folder = $this->extractDir($zipPath);
        $skipped = [];
        $written = 0;
        foreach ($entries as [$index, $safe, $isDir]) {
            if (FmPath::uploadBlocked($safe, [], []) || FmStore::dangerousBasename($safe)) {
                $skipped[] = $safe;
                continue;
            }
            $target = $folder . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $safe);
            $this->files->paths()->assertInside($isDir ? $target : dirname($target));
            $this->files->assertMutable($target);
            if (is_link($target)) {
                $zip->close();
                throw new FmException('Refusing to write through a link.', 403);
            }
            if ($isDir) {
                if (!is_dir($target) && !mkdir($target, 0755, true) && !is_dir($target)) {
                    $zip->close();
                    throw new FmException('Extract failed.');
                }
                continue;
            }
            $parent = dirname($target);
            if (is_link($parent)) {
                $zip->close();
                throw new FmException('Refusing to write through a link.', 403);
            }
            $realParent = realpath($parent);
            if ($realParent === false || !$this->files->paths()->isInside($realParent)) {
                if (!is_dir($parent) && !mkdir($parent, 0755, true)) {
                    $zip->close();
                    throw new FmException('Extract failed.');
                }
                $realParent = realpath($parent);
            }
            if ($realParent === false || !$this->files->paths()->isInside($realParent)) {
                $zip->close();
                throw new FmException('Path is outside the root.', 403);
            }
            $stream = $zip->getStream((string)$zip->getNameIndex($index));
            if ($stream === false) {
                continue;
            }
            $out = fopen($target, 'wb');
            if ($out === false) {
                fclose($stream);
                $zip->close();
                throw new FmException('Extract failed.');
            }
            $bytes = 0;
            while (!feof($stream)) {
                $chunk = fread($stream, 8192);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $bytes += strlen($chunk);
                if ($bytes > 500 * 1048576) {
                    fclose($stream);
                    fclose($out);
                    @unlink($target);
                    $zip->close();
                    throw new FmException('Archive expands beyond the size limit.');
                }
                fwrite($out, $chunk);
            }
            fclose($stream);
            fclose($out);
            @chmod($target, 0644);
            $written++;
        }
        $zip->close();
        return [
            'path' => $this->files->paths()->relative($folder),
            'written' => $written,
            'skipped' => $skipped,
        ];
    }

    public function tempZip(array $rels): string
    {
        if (!$this->available()) {
            throw new FmException('ZIP support is not available.', 500);
        }
        if (!is_dir($this->tmpDir)) {
            throw new FmException('Temporary storage is unavailable.', 500);
        }
        $dest = $this->tmpDir . DIRECTORY_SEPARATOR . 'dl-' . bin2hex(random_bytes(8)) . '.zip';
        $zip = new ZipArchive();
        if ($zip->open($dest, ZipArchive::CREATE) !== true) {
            throw new FmException('Archive could not be created.');
        }
        $count = 0;
        foreach ($rels as $rel) {
            $path = $this->files->absolute((string)$rel, true);
            $this->add($zip, $path, basename($path), $count);
        }
        $zip->close();
        return $dest;
    }

    private function add(ZipArchive $zip, string $path, string $local, int &$count): void
    {
        if (++$count > 5000) {
            throw new FmException('Too many files to archive.');
        }
        if (is_link($path) || $this->files->isData($path)) {
            return;
        }
        $this->files->paths()->assertInside($path);
        if (is_dir($path)) {
            $zip->addEmptyDir(str_replace('\\', '/', $local));
            $dh = opendir($path);
            if ($dh === false) {
                return;
            }
            while (($name = readdir($dh)) !== false) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $this->add($zip, $path . DIRECTORY_SEPARATOR . $name, $local . '/' . $name, $count);
            }
            closedir($dh);
            return;
        }
        if (is_file($path)) {
            $zip->addFile($path, str_replace('\\', '/', $local));
        }
    }

    private function extractDir(string $zipPath): string
    {
        $base = pathinfo($zipPath, PATHINFO_FILENAME);
        $dir = dirname($zipPath);
        $name = $base;
        for ($i = 0; $i < 50; $i++) {
            if (!FmPath::validName($name)) {
                $name = 'archive' . ($i + 1);
            }
            $candidate = $dir . DIRECTORY_SEPARATOR . $name;
            if (!file_exists($candidate)) {
                if (!mkdir($candidate, 0755)) {
                    throw new FmException('Extract folder could not be created.');
                }
                return $candidate;
            }
            $name = $base . '-' . ($i + 2);
        }
        throw new FmException('Extract folder could not be created.');
    }
}

final class FmSystem
{
    public function __construct(private string $root, private FmStore $store, private array $settings)
    {
    }

    public function snapshot(): array
    {
        $total = @disk_total_space($this->root);
        $free = @disk_free_space($this->root);
        $mem = $this->memory();
        return [
            'os' => php_uname('s') . ' ' . php_uname('r') . ' ' . php_uname('m'),
            'php' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'server' => (string)($_SERVER['SERVER_SOFTWARE'] ?? ''),
            'hostname' => php_uname('n'),
            'root' => $this->root,
            'disk_total' => is_float($total) ? (int)$total : 0,
            'disk_free' => is_float($free) ? (int)$free : 0,
            'memory' => $mem,
            'load' => function_exists('sys_getloadavg') ? sys_getloadavg() : null,
            'uptime' => $this->uptime(),
            'cpu' => $this->cpuPercent(),
            'https' => FmHttp::https(),
        ];
    }

    public function phpInfo(): array
    {
        $keys = [
            'memory_limit', 'upload_max_filesize', 'post_max_size', 'max_execution_time',
            'max_input_time', 'file_uploads', 'upload_tmp_dir', 'display_errors',
            'expose_php', 'open_basedir', 'disable_functions', 'date.timezone',
            'session.cookie_httponly', 'allow_url_fopen', 'allow_url_include',
        ];
        $ini = [];
        foreach ($keys as $key) {
            $ini[$key] = (string)ini_get($key);
        }
        $env = [];
        foreach (array_merge($_SERVER, $_ENV) as $key => $value) {
            if (!is_string($key) || !preg_match('/^[A-Za-z0-9_]+$/', $key)) {
                continue;
            }
            if (str_starts_with($key, 'HTTP_') && $key !== 'HTTP_HOST') {
                continue;
            }
            if (!is_scalar($value)) {
                continue;
            }
            if (preg_match('/PASS|SECRET|KEY|TOKEN|PWD|AUTH|CREDENTIAL|COOKIE|SESSION/i', $key)) {
                $env[$key] = '••••';
            } else {
                $env[$key] = substr((string)$value, 0, 180);
            }
            if (count($env) >= 80) {
                break;
            }
        }
        $ext = get_loaded_extensions();
        sort($ext);
        return ['ini' => $ini, 'env' => $env, 'extensions' => $ext];
    }

    public function processes(): array
    {
        $rows = [];
        foreach (glob('/proc/[0-9]*', GLOB_ONLYDIR) ?: [] as $dir) {
            if (count($rows) >= 300) {
                break;
            }
            $pid = basename($dir);
            $comm = is_readable($dir . '/comm') ? trim((string)file_get_contents($dir . '/comm')) : '';
            $state = '';
            $user = '';
            $status = is_readable($dir . '/status') ? (string)file_get_contents($dir . '/status') : '';
            if (preg_match('/^State:\s+(\S+)/m', $status, $m)) {
                $state = $m[1];
            }
            if (preg_match('/^Uid:\s+(\d+)/m', $status, $m)) {
                $uid = (int)$m[1];
                $user = (string)$uid;
                if (function_exists('posix_getpwuid')) {
                    $info = posix_getpwuid($uid);
                    if (is_array($info) && isset($info['name'])) {
                        $user = (string)$info['name'];
                    }
                }
            }
            $rows[] = ['pid' => (int)$pid, 'user' => $user, 'state' => $state, 'name' => $comm];
        }
        if ($rows === [] && PHP_OS_FAMILY === 'Windows') {
            return ['available' => false, 'rows' => [], 'note' => 'Process listing from /proc is available on Linux.'];
        }
        return ['available' => $rows !== [] || is_dir('/proc'), 'rows' => $rows, 'note' => ''];
    }

    public function cron(): array
    {
        $files = [];
        $candidates = ['/etc/crontab'];
        foreach (glob('/etc/cron.d/*') ?: [] as $file) {
            $candidates[] = $file;
        }
        foreach ($candidates as $file) {
            if (!is_file($file) || !is_readable($file)) {
                continue;
            }
            $size = filesize($file);
            if ($size === false || $size > 32768) {
                $files[] = ['name' => basename($file), 'body' => 'Skipped: file is larger than 32 KB.'];
                continue;
            }
            $files[] = ['name' => basename($file), 'body' => (string)file_get_contents($file)];
            if (count($files) >= 30) {
                break;
            }
        }
        return [
            'available' => $files !== [],
            'files' => $files,
            'note' => $files === [] ? 'Cron files are not readable by the PHP user.' : '',
        ];
    }

    public function mounts(): array
    {
        if (!is_readable('/proc/mounts')) {
            $total = @disk_total_space($this->root);
            $free = @disk_free_space($this->root);
            return [[
                'device' => 'root',
                'mount' => $this->root,
                'type' => PHP_OS_FAMILY,
                'total' => is_float($total) ? (int)$total : 0,
                'free' => is_float($free) ? (int)$free : 0,
            ]];
        }
        $skip = ['proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'pstore', 'bpf', 'tracefs', 'debugfs', 'securityfs', 'configfs', 'mqueue', 'hugetlbfs', 'rpc_pipefs', 'nsfs', 'autofs', 'binfmt_misc'];
        $rows = [];
        foreach (file('/proc/mounts', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $parts = preg_split('/\s+/', $line) ?: [];
            if (count($parts) < 3 || in_array($parts[2], $skip, true)) {
                continue;
            }
            $mount = $parts[1];
            $total = @disk_total_space($mount);
            $free = @disk_free_space($mount);
            $rows[] = [
                'device' => $parts[0],
                'mount' => $mount,
                'type' => $parts[2],
                'total' => is_float($total) ? (int)$total : 0,
                'free' => is_float($free) ? (int)$free : 0,
            ];
            if (count($rows) >= 40) {
                break;
            }
        }
        return $rows;
    }

    public function network(): array
    {
        $ifaces = [];
        if (is_readable('/proc/net/dev')) {
            $lines = file('/proc/net/dev', FILE_IGNORE_NEW_LINES) ?: [];
            foreach (array_slice($lines, 2) as $line) {
                if (!str_contains($line, ':')) {
                    continue;
                }
                [$name, $rest] = explode(':', $line, 2);
                $cols = preg_split('/\s+/', trim($rest)) ?: [];
                $ifaces[] = [
                    'name' => trim($name),
                    'rx' => (int)($cols[0] ?? 0),
                    'tx' => (int)($cols[8] ?? 0),
                ];
            }
        }
        return [
            'hostname' => php_uname('n'),
            'addr' => (string)($_SERVER['SERVER_ADDR'] ?? ''),
            'interfaces' => $ifaces,
        ];
    }

    public function lookup(string $host): array
    {
        if (!preg_match('/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/', $host)) {
            throw new FmException('Enter a hostname, not a URL or command.');
        }
        $ips = gethostbynamel($host);
        return ['host' => $host, 'addresses' => $ips === false ? [] : array_values(array_unique($ips))];
    }

    public function analyze(string $dir): array
    {
        if (!is_dir($dir)) {
            throw new FmException('Directory not found.', 404);
        }
        $rows = [];
        $count = 0;
        $deadline = microtime(true) + 6;
        $dh = opendir($dir);
        if ($dh === false) {
            throw new FmException('Directory cannot be read.', 403);
        }
        while (($name = readdir($dh)) !== false) {
        if ($name === '.' || $name === '..' || $name === FM_DATA) {
            continue;
        }
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        if (is_link($full)) {
            continue;
        }
        $rows[] = [
                'name' => $name,
                'type' => is_dir($full) ? 'dir' : 'file',
                'size' => $this->sizeOf($full, $count, $deadline),
            ];
        }
        closedir($dh);
        usort($rows, static fn(array $a, array $b): int => $b['size'] <=> $a['size']);
        return [
            'rows' => array_slice($rows, 0, 30),
            'truncated' => $count >= 8000 || microtime(true) > $deadline,
        ];
    }

    public function logs(): array
    {
        $logs = [['id' => 'audit', 'label' => 'Application audit log']];
        $err = ini_get('error_log');
        if (is_string($err) && $err !== '' && $this->logAllowed($err)) {
            $logs[] = ['id' => 'php', 'label' => 'PHP error log'];
        }
        foreach ($this->settings['extra_logs'] as $i => $path) {
            if (is_string($path) && $this->logAllowed($path)) {
                $logs[] = ['id' => 'x' . $i, 'label' => basename($path)];
            }
        }
        return $logs;
    }

    public function logBody(string $id): string
    {
        if ($id === 'audit') {
            return $this->store->tail($this->store->dir . DIRECTORY_SEPARATOR . 'audit.log');
        }
        if ($id === 'php') {
            $err = (string)ini_get('error_log');
            if (!$this->logAllowed($err)) {
                throw new FmException('Log is not available.', 404);
            }
            return $this->store->tail((string)realpath($err));
        }
        if (preg_match('/^x(\d+)$/', $id, $m)) {
            $path = $this->settings['extra_logs'][(int)$m[1]] ?? '';
            if (!is_string($path) || !$this->logAllowed($path)) {
                throw new FmException('Log is not available.', 404);
            }
            return $this->store->tail((string)realpath($path));
        }
        throw new FmException('Log is not available.', 404);
    }

    public function logAllowed(string $path): bool
    {
        $real = realpath($path);
        if ($real === false || !is_file($real) || !is_readable($real)) {
            return false;
        }
        $data = realpath($this->store->dir);
        if ($data !== false && FmPath::within($real, $data) && !str_ends_with(strtolower($real), 'audit.log') && !str_ends_with(strtolower($real), 'audit.log.1')) {
            return false;
        }
        $norm = str_replace('\\', '/', $real);
        $base = strtolower(basename($norm));
        if (str_ends_with($base, '.log')) {
            return true;
        }
        if (str_starts_with($norm, '/var/log/')) {
            return true;
        }
        $php = ini_get('error_log');
        return is_string($php) && realpath($php) === $real;
    }

    private function sizeOf(string $path, int &$count, float $deadline): int
    {
        if ($count >= 8000 || microtime(true) > $deadline) {
            return 0;
        }
        if (is_link($path)) {
            return 0;
        }
        if (is_file($path)) {
            $count++;
            $size = @filesize($path);
            return is_int($size) ? $size : 0;
        }
        if (!is_dir($path)) {
            return 0;
        }
        $total = 0;
        $dh = @opendir($path);
        if ($dh === false) {
            return 0;
        }
        while (($name = readdir($dh)) !== false) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $total += $this->sizeOf($path . DIRECTORY_SEPARATOR . $name, $count, $deadline);
        }
        closedir($dh);
        return $total;
    }

    private function memory(): ?array
    {
        if (!is_readable('/proc/meminfo')) {
            return null;
        }
        $text = (string)file_get_contents('/proc/meminfo');
        $vals = [];
        foreach (['MemTotal', 'MemAvailable', 'MemFree', 'Buffers', 'Cached'] as $key) {
            if (preg_match('/^' . $key . ':\s+(\d+)/m', $text, $m)) {
                $vals[$key] = (int)$m[1] * 1024;
            }
        }
        if (!isset($vals['MemTotal'])) {
            return null;
        }
        $available = $vals['MemAvailable'] ?? (($vals['MemFree'] ?? 0) + ($vals['Buffers'] ?? 0) + ($vals['Cached'] ?? 0));
        return ['total' => $vals['MemTotal'], 'available' => $available, 'used' => max(0, $vals['MemTotal'] - $available)];
    }

    private function uptime(): ?int
    {
        if (!is_readable('/proc/uptime')) {
            return null;
        }
        $parts = explode(' ', trim((string)file_get_contents('/proc/uptime')));
        return isset($parts[0]) ? (int)$parts[0] : null;
    }

    private function cpuPercent(): ?float
    {
        if (!is_readable('/proc/stat')) {
            return null;
        }
        $line = strtok((string)file_get_contents('/proc/stat'), "\n");
        if (!is_string($line) || !preg_match('/^cpu\s+(.+)$/', $line, $m)) {
            return null;
        }
        $parts = array_map('intval', preg_split('/\s+/', trim($m[1])) ?: []);
        $idle = ($parts[3] ?? 0) + ($parts[4] ?? 0);
        $total = array_sum($parts);
        $prev = $_SESSION['cpu'] ?? null;
        $_SESSION['cpu'] = ['idle' => $idle, 'total' => $total];
        if (!is_array($prev)) {
            return null;
        }
        $dTotal = $total - (int)$prev['total'];
        $dIdle = $idle - (int)$prev['idle'];
        if ($dTotal <= 0) {
            return null;
        }
        return round((1 - ($dIdle / $dTotal)) * 100, 1);
    }
}

final class FmTerminal
{
    private const BLOCKED = [
        'sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'fish', 'php', 'php-cgi', 'python', 'python3',
        'perl', 'ruby', 'node', 'nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'ssh', 'scp', 'sftp',
        'ftp', 'telnet', 'awk', 'sed', 'find', 'xargs', 'env', 'sudo', 'su', 'chmod', 'chown', 'rm',
        'mv', 'cp', 'dd', 'mkfs', 'mount', 'umount', 'systemctl', 'service', 'kill', 'killall', 'pkill',
        'reboot', 'shutdown', 'poweroff', 'halt', 'passwd', 'useradd', 'userdel', 'visudo', 'crontab',
        'at', 'batch', 'screen', 'tmux', 'script', 'openssl', 'gpg', 'busybox', 'install', 'tee',
        'php8.1', 'php8.2', 'php8.3', 'php8.4', 'php8.5',
    ];

    private const PATH_CMDS = ['ls', 'du', 'stat', 'wc', 'head', 'tail', 'cat', 'file'];

    public static function enabled(array $settings): bool
    {
        return !empty($settings['terminal_enabled']);
    }

    public static function runnable(): bool
    {
        if (PHP_OS_FAMILY === 'Windows' || !function_exists('proc_open')) {
            return false;
        }
        $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
        return !in_array('proc_open', $disabled, true);
    }

    public static function filterAllow(array $commands): array
    {
        $out = [];
        foreach ($commands as $cmd) {
            $cmd = strtolower(trim((string)$cmd));
            if (preg_match('/^[a-z0-9][a-z0-9._+-]{0,40}$/', $cmd) && !in_array($cmd, self::BLOCKED, true)) {
                $out[] = $cmd;
            }
            if (count($out) >= 40) {
                break;
            }
        }
        return array_values(array_unique($out));
    }

    public static function assertLine(string $input): void
    {
        if ($input === '' || strlen($input) > 500) {
            throw new FmException('Command is empty or too long.');
        }
        if (preg_match('/[\x00-\x1F|&;<>`$\\\\(){}!\n\r]/', $input)) {
            throw new FmException('Command contains unsupported characters.', 403);
        }
    }

    public function run(string $input, array $allow, FmPath $paths): array
    {
        if (!self::runnable()) {
            throw new FmException('Terminal is not available on this server.', 403);
        }
        self::assertLine($input);
        $tokens = preg_split('/\s+/', trim($input)) ?: [];
        $name = strtolower((string)array_shift($tokens));
        if (!preg_match('/^[a-z0-9][a-z0-9._+-]{0,40}$/', $name) || in_array($name, self::BLOCKED, true)) {
            throw new FmException('Command is not allowed.', 403);
        }
        if (!in_array($name, $allow, true)) {
            throw new FmException('Command is not on the allowlist.', 403);
        }
        if (count($tokens) > 20) {
            throw new FmException('Too many arguments.');
        }
        $args = [];
        foreach ($tokens as $arg) {
            if (strlen($arg) > 180 || str_contains($arg, '..')) {
                throw new FmException('Argument is not allowed.', 403);
            }
            $args[] = $this->normalizeArg($name, $arg, $paths);
        }
        $bin = $this->resolveBin($name);
        $cmd = array_merge([$bin], $args);
        $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $env = ['PATH' => '/usr/bin:/bin', 'LANG' => 'C', 'LC_ALL' => 'C', 'HOME' => $paths->root()];
        $proc = proc_open($cmd, $desc, $pipes, $paths->root(), $env, ['bypass_shell' => true]);
        if (!is_resource($proc)) {
            throw new FmException('Command could not be started.', 500);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $start = microtime(true);
        $status = ['running' => true];
        while ((microtime(true) - $start) < 8) {
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            if (strlen($out) + strlen($err) > 200000) {
                $out = substr($out, 0, 200000);
                $err = substr($err, 0, 20000);
                proc_terminate($proc, 9);
                break;
            }
            $status = proc_get_status($proc);
            if (!$status['running']) {
                break;
            }
            usleep(40000);
        }
        if (!empty($status['running'])) {
            proc_terminate($proc, 9);
            $err .= "\nStopped: time limit reached.";
        }
        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);
        return ['stdout' => $out, 'stderr' => $err, 'code' => $code];
    }

    private function normalizeArg(string $cmd, string $arg, FmPath $paths): string
    {
        if (preg_match('/^-[A-Za-z0-9=_,.-]+$/', $arg)) {
            return $arg;
        }
        if (in_array($cmd, ['head', 'tail', 'wc', 'ps'], true) && preg_match('/^[A-Za-z0-9-]+$/', $arg)) {
            return $arg;
        }
        if (!in_array($cmd, self::PATH_CMDS, true)) {
            throw new FmException('That argument is not allowed.', 403);
        }
        return $paths->resolve($arg, true, true);
    }

    private function resolveBin(string $name): string
    {
        foreach (['/usr/bin', '/bin'] as $dir) {
            $candidate = $dir . '/' . $name;
            if (!is_file($candidate) || !is_executable($candidate)) {
                continue;
            }
            $real = realpath($candidate);
            if (is_string($real) && (str_starts_with($real, '/usr/bin/') || str_starts_with($real, '/bin/'))) {
                return $real;
            }
        }
        throw new FmException('Command is not available.', 404);
    }
}

final class FmHttp
{
    public static function assertOrigin(): void
    {
        if (empty($_SERVER['HTTP_ORIGIN'])) {
            return;
        }
        $originHost = parse_url((string)$_SERVER['HTTP_ORIGIN'], PHP_URL_HOST);
        $host = preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? ''));
        if (!is_string($originHost) || !is_string($host) || !hash_equals(strtolower($host), strtolower($originHost))) {
            throw new FmException('Request origin was rejected.', 403);
        }
    }

    public static function https(): bool
    {
        $https = (string)($_SERVER['HTTPS'] ?? '');
        if ($https !== '' && strtolower($https) !== 'off') {
            return true;
        }
        return (int)($_SERVER['SERVER_PORT'] ?? 0) === 443
            || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    }

    public static function securityHeaders(): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header("Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow');
    }

    public static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function json(array $payload, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function iniBytes(string $val): int
    {
        $val = trim($val);
        if ($val === '' || $val === '-1') {
            return PHP_INT_MAX;
        }
        $unit = strtolower(substr($val, -1));
        $num = (float)$val;
        return (int)match ($unit) {
            'g' => $num * 1073741824,
            'm' => $num * 1048576,
            'k' => $num * 1024,
            default => $num,
        };
    }

    public static function clientIp(): string
    {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    public static function cookiePath(): string
    {
        $dir = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')));
        if ($dir === '/' || $dir === '.' || $dir === '\\') {
            return '/';
        }
        return rtrim($dir, '/') . '/';
    }

    public static function cleanList(mixed $value, int $max, string $pattern): array
    {
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $item) {
            $item = strtolower(trim((string)$item));
            if ($item !== '' && preg_match($pattern, $item)) {
                $out[] = $item;
            }
            if (count($out) >= $max) {
                break;
            }
        }
        return array_values(array_unique($out));
    }
}

final class FmUi
{
    public static function page(string $title, string $body, string $css, string $js, ?array $boot): void
    {
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }
        $bootJson = $boot === null ? 'null' : json_encode($boot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
        echo '<meta name="robots" content="noindex,nofollow"><title>' . FmHttp::e($title) . '</title>';
        echo '<style>' . $css . '</style></head><body>';
        echo $body;
        echo '<script>window.FM_BOOT=' . $bootJson . ';</script>';
        echo '<script>' . $js . '</script></body></html>';
    }

    public static function css(): string
    {
        return <<<'FMCSS'
:root{color-scheme:light;--bg:#f3efe6;--elev:#fffdf8;--ink:#1c1915;--muted:#6f675e;--line:#e3dacd;--accent:#0f6e6b;--accent-ink:#fff;--danger:#9f2d2d;--ok:#1f7a4d;--warn:#9a5b12;--shadow:0 16px 40px rgba(48,36,20,.08);--side:248px;--mono:ui-monospace,Cascadia Code,Consolas,monospace;--sans:"Segoe UI",system-ui,sans-serif}
html[data-theme="dark"]{color-scheme:dark;--bg:#121417;--elev:#1c2128;--ink:#f3efe6;--muted:#b1a89d;--line:#313842;--accent:#3cbfb4;--accent-ink:#06211f;--danger:#ff8d8d;--ok:#7dcea0;--warn:#f0c27a;--shadow:0 16px 40px rgba(0,0,0,.35)}
*{box-sizing:border-box}html,body{margin:0;height:100%}body{font-family:var(--sans);background:var(--bg);color:var(--ink);font-size:15px}
button,input,select,textarea{font:inherit;color:inherit}button{cursor:pointer}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.gate{min-height:100%;display:grid;place-items:center;padding:24px;background:radial-gradient(1200px 500px at 10% -10%,color-mix(in srgb,var(--accent) 22%,transparent),transparent),var(--bg)}
.gate-card{width:min(440px,100%);background:var(--elev);border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow);padding:28px}
.mark{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:var(--accent);color:var(--accent-ink);font-weight:700}
.gate h1{margin:14px 0 6px;font-size:28px;letter-spacing:-.04em}.muted{color:var(--muted)}label{display:block;margin:14px 0 6px;font-size:13px;font-weight:650}
input,select,textarea{width:100%;background:transparent;border:1px solid var(--line);border-radius:12px;padding:11px 12px;background:color-mix(in srgb,var(--bg) 65%,var(--elev))}
textarea{resize:vertical}.row{display:flex;gap:10px;align-items:center}.spread{display:flex;justify-content:space-between;gap:12px;align-items:center}
.btn{border:0;border-radius:12px;padding:10px 14px;background:var(--accent);color:var(--accent-ink);font-weight:700}.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}.btn.danger{background:var(--danger);color:#fff}.btn.small{padding:7px 10px;border-radius:10px;font-size:13px}
.err{color:var(--danger);min-height:1.2em;font-size:14px}.app{min-height:100%;display:grid;grid-template-columns:var(--side) 1fr}
.side{background:color-mix(in srgb,var(--elev) 88%,var(--bg));border-right:1px solid var(--line);padding:18px 14px;display:flex;flex-direction:column;gap:8px;position:sticky;top:0;height:100vh}
.brand{display:flex;gap:10px;align-items:center;padding:4px 8px 14px}.brand b{display:block;letter-spacing:-.03em}.brand span{color:var(--muted);font-size:12px}
.nav button{width:100%;text-align:left;border:0;background:transparent;border-radius:12px;padding:10px 12px;color:var(--muted);font-weight:650}.nav button.active{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--ink)}
.side .grow{flex:1}.userbox{padding:10px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:8px;align-items:center}
.main{min-width:0;display:flex;flex-direction:column;min-height:100vh}.top{display:flex;gap:10px;align-items:center;padding:14px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(10px);z-index:5}
.crumbs{display:flex;gap:4px;flex-wrap:wrap;min-width:0}.crumbs button{border:0;background:transparent;color:var(--muted);padding:4px;border-radius:8px}.crumbs button:hover{color:var(--ink)}
.search{margin-left:auto;width:min(280px,40vw)}#progress{height:3px;background:transparent}#progress.on{background:linear-gradient(90deg,transparent,var(--accent),transparent);background-size:40% 100%;animation:slide 1s linear infinite}
@keyframes slide{from{background-position:-40% 0}to{background-position:140% 0}}
.view{padding:18px;display:flex;flex-direction:column;gap:16px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{background:var(--elev);border:1px solid var(--line);border-radius:18px;padding:16px;box-shadow:var(--shadow)}
.card h3{margin:0 0 8px;font-size:13px;color:var(--muted);font-weight:650}.stat{font-size:28px;letter-spacing:-.04em;font-weight:720}
.meter{height:8px;border-radius:99px;background:var(--line);overflow:hidden;margin-top:10px}.meter span{display:block;height:100%;background:var(--accent)}
.files{display:grid;grid-template-columns:230px 1fr;gap:12px;min-height:60vh}.tree,.listing{background:var(--elev);border:1px solid var(--line);border-radius:18px;min-height:420px}
.tree{padding:10px;overflow:auto}.tree button{width:100%;text-align:left;border:0;background:transparent;border-radius:8px;padding:6px 8px;color:var(--ink)}
.toolbar,.bulk{display:flex;gap:8px;flex-wrap:wrap;align-items:center;padding:10px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:9px 10px;border-top:1px solid var(--line);text-align:left;white-space:nowrap}
th{font-size:12px;color:var(--muted);font-weight:650;cursor:pointer}tr:hover td{background:color-mix(in srgb,var(--accent) 7%,transparent)}tr.selected td{background:color-mix(in srgb,var(--accent) 14%,transparent)}
.name{display:flex;gap:8px;align-items:center;font-weight:650}.mono{font-family:var(--mono);font-size:12px}.status{padding:8px 18px 16px;color:var(--muted);font-size:13px}
.foot{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:8px 18px 16px;color:var(--muted);font-size:13px}.foot .status{padding:0}
.byline{margin:18px 0 0;color:var(--muted);font-size:13px}a.by{color:var(--accent);font-weight:700;text-decoration:none}a.by:hover{text-decoration:underline}
.menu{position:fixed;z-index:30;background:var(--elev);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:6px;min-width:190px}
.menu button{display:block;width:100%;text-align:left;border:0;background:transparent;border-radius:8px;padding:8px 10px}.menu button:hover{background:color-mix(in srgb,var(--accent) 12%,transparent)}
dialog{border:0;border-radius:20px;padding:0;background:var(--elev);color:var(--ink);box-shadow:var(--shadow);width:min(560px,calc(100% - 24px))}dialog::backdrop{background:rgba(0,0,0,.45)}
.modal{padding:18px}.modal h2{margin:0 0 8px;letter-spacing:-.03em}.modal .actions{display:flex;justify-content:flex-end;gap:8px;margin-top:16px}
#editor-dialog{width:min(1080px,calc(100% - 20px))}
.editor{display:grid;grid-template-columns:48px 1fr;border:1px solid var(--line);border-radius:14px;overflow:hidden;height:min(62vh,680px);background:#171a1f}
.gutter{margin:0;padding:12px 6px;text-align:right;color:#8b93a0;font-family:var(--mono);font-size:13px;line-height:1.45;overflow:hidden;background:#12151a}
.editor-layer{position:relative}.editor-layer pre,.editor-layer textarea{margin:0;padding:12px;font-family:var(--mono);font-size:13px;line-height:1.45;tab-size:2;white-space:pre;overflow:auto;position:absolute;inset:0}
.editor-layer textarea{background:transparent;color:transparent;caret-color:#f3efe6;border:0;resize:none}
.editor-layer pre{color:#e7e1d6;pointer-events:none}.tok-k{color:#7fd1cb}.tok-s{color:#e7b008}.tok-c{color:#8b93a0}.tok-n{color:#f0a080}
.term{background:#12151a;color:#d7efe8;border-radius:16px;min-height:320px;padding:14px;font-family:var(--mono);white-space:pre-wrap;overflow:auto}
.toasts{position:fixed;right:14px;bottom:14px;display:flex;flex-direction:column;gap:8px;z-index:40}.toast{background:var(--elev);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:12px;padding:10px 12px;box-shadow:var(--shadow);max-width:320px}.toast.bad{border-left-color:var(--danger)}
.drop{outline:2px dashed var(--accent);outline-offset:-8px}.chips{display:flex;gap:6px;flex-wrap:wrap}.chips button{border:1px solid var(--line);background:transparent;border-radius:999px;padding:5px 10px}.chips button.on{background:var(--accent);color:var(--accent-ink);border-color:transparent}
.notice{padding:10px 12px;border-radius:12px;background:color-mix(in srgb,var(--warn) 16%,var(--elev));border:1px solid color-mix(in srgb,var(--warn) 40%,var(--line))}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 10px;font-size:14px}.kv b{color:var(--muted);font-weight:600}
.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.check{display:flex;gap:8px;align-items:center;margin:6px 0}.check input{width:auto}
.iconbtn{border:1px solid var(--line);background:var(--elev);border-radius:10px;padding:8px 10px}
@media(min-width:901px){#menu-btn{display:none}}
@media(max-width:900px){.app{grid-template-columns:1fr}.side{position:fixed;z-index:20;transform:translateX(-105%);width:min(var(--side),86vw);transition:transform .2s}.side.open{transform:none}.grid,.files,.split{grid-template-columns:1fr}.search{width:auto;flex:1}.hide-sm{display:none}}
@media(prefers-reduced-motion:reduce){#progress.on{animation:none}}
FMCSS;
    }

    public static function script(): string
    {
        return <<<'FMJS'
(() => {
  const boot = window.FM_BOOT || {mode:'setup', csrf:''};
  const endpoint = location.pathname;
  const $ = (s, r=document) => r.querySelector(s);
  const el = (tag, attrs={}, kids=[]) => {
    const n = document.createElement(tag);
    Object.entries(attrs).forEach(([k,v]) => {
      if (k === 'class') n.className = v;
      else if (v !== null && v !== undefined) n.setAttribute(k, String(v));
    });
    [].concat(kids).forEach(c => { if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c))); });
    return n;
  };
  const esc = s => s.replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  const fmt = n => {
    n = Number(n) || 0;
    const u = ['B','KB','MB','GB','TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(n >= 10 ? 0 : 1) : n) + ' ' + u[i];
  };
  const when = ts => ts ? new Date(ts * 1000).toLocaleString() : '';
  const pct = (used, total) => total > 0 ? Math.max(0, Math.min(100, Math.round(used / total * 100))) : 0;
  let inflight = 0;
  function busy(on){ inflight += on ? 1 : -1; const p = $('#progress'); if (p) p.classList.toggle('on', inflight > 0); }
  function toast(msg, bad=false){
    const box = $('#toasts'); if (!box) return;
    const t = el('div', {class:'toast' + (bad ? ' bad' : ''), role:'status'}, [msg]);
    box.append(t); setTimeout(() => t.remove(), 4200);
  }
  function applyTheme(theme){
    const dark = theme === 'dark' || (theme !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  }
  applyTheme(localStorage.getItem('fm-theme') || boot.theme || 'system');
  async function api(action, body={}){
    busy(true);
    try {
      const res = await fetch(endpoint, {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json','Accept':'application/json','X-CSRF-Token':boot.csrf},
        body: JSON.stringify({action, csrf: boot.csrf, ...body})
      });
      const data = await res.json().catch(() => ({ok:false, error:'Unexpected response'}));
      if (res.status === 401 && boot.mode === 'app') { location.reload(); throw new Error(data.error || 'Sign in required'); }
      if (!data.ok) throw new Error(data.error || 'Request failed');
      return data;
    } finally { busy(false); }
  }
  async function apiBlob(action, body={}){
    busy(true);
    try {
      const res = await fetch(endpoint, {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-CSRF-Token':boot.csrf},
        body: JSON.stringify({action, csrf: boot.csrf, ...body})
      });
      const ct = res.headers.get('content-type') || '';
      if (ct.includes('json')) {
        const data = await res.json();
        if (res.status === 401 && boot.mode === 'app') location.reload();
        throw new Error(data.error || 'Request failed');
      }
      if (!res.ok) throw new Error('Download failed');
      const cd = res.headers.get('content-disposition') || '';
      const star = cd.match(/filename\*=UTF-8''([^;]+)/i);
      const plain = cd.match(/filename="([^"]+)"/i);
      const name = star ? decodeURIComponent(star[1]) : (plain ? plain[1] : 'download');
      return {blob: await res.blob(), name};
    } finally { busy(false); }
  }
  function saveBlob(blob, name){
    const a = el('a', {href: URL.createObjectURL(blob), download: name});
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  let askAbort;
  function ask(opts){
    askAbort?.abort();
    askAbort = new AbortController();
    const {signal} = askAbort;
    const dlg = $('#ask'), slot = $('#ask-body'), yes = $('#ask-ok');
    $('#ask-title').textContent = opts.title || 'Confirm';
    slot.replaceChildren();
    if (typeof opts.body === 'string') slot.append(el('p', {}, [opts.body]));
    else if (opts.body) slot.append(opts.body);
    yes.textContent = opts.ok || 'Confirm';
    yes.className = 'btn' + (opts.danger ? ' danger' : '');
    $('#ask-cancel').textContent = opts.cancel || 'Cancel';
    return new Promise(resolve => {
      const finish = (ok) => {
        const values = {};
        slot.querySelectorAll('input,select,textarea').forEach(i => { values[i.name || 'value'] = i.type === 'checkbox' ? i.checked : i.value; });
        if (dlg.open) dlg.close();
        resolve(ok ? values : null);
      };
      $('#ask-form').addEventListener('submit', e => { e.preventDefault(); finish(true); }, {signal});
      $('#ask-cancel').addEventListener('click', () => finish(false), {signal});
      dlg.addEventListener('cancel', e => { e.preventDefault(); finish(false); }, {signal});
      dlg.showModal();
      const focus = slot.querySelector('input,textarea,select');
      if (focus) focus.focus();
    });
  }
  if (boot.mode !== 'app') {
    const titles = {setup:['Create the administrator','Choose a username and a password of at least 12 characters. It is stored only as a hash.'], login:['Sign in','This panel is private.'], totp:['Authentication code','Enter the 6-digit code or a recovery code.']};
    const [title, sub] = titles[boot.mode] || titles.login;
    $('#gate-title').textContent = boot.brand || title;
    $('#gate-sub').textContent = boot.mode === 'login' ? title + '. ' + sub : sub;
    if (boot.mode !== 'login') $('#gate-title').textContent = title;
    const fields = $('#gate-fields');
    if (boot.mode === 'totp') fields.append(el('label', {}, ['Code', el('input', {name:'code', inputmode:'numeric', autocomplete:'one-time-code', required:'required'})]));
    else {
      fields.append(el('label', {}, ['Username', el('input', {name:'username', autocomplete:'username', required:'required'})]));
      fields.append(el('label', {}, ['Password', el('input', {name:'password', type:'password', autocomplete: boot.mode === 'setup' ? 'new-password' : 'current-password', required:'required'})]));
      if (boot.mode === 'setup') fields.append(el('label', {}, ['Confirm password', el('input', {name:'confirm', type:'password', autocomplete:'new-password', required:'required'})]));
    }
    $('#gate-submit').textContent = boot.mode === 'setup' ? 'Create account' : (boot.mode === 'totp' ? 'Verify' : 'Sign in');
    if (boot.https === false) {
      $('#gate').prepend(el('p', {class:'notice'}, ['This connection is not using HTTPS. Use HTTPS on a real server.']));
    }
    $('#gate').addEventListener('submit', async e => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const body = Object.fromEntries(fd.entries());
      $('#gate-error').textContent = '';
      try {
        await api(boot.mode === 'setup' ? 'setup' : (boot.mode === 'totp' ? 'totp' : 'login'), body);
        location.reload();
      } catch (err) { $('#gate-error').textContent = err.message; }
    });
    return;
  }

  const state = {view:'dashboard', path:'', items:[], selected:new Set(), sort:'name', dir:1, filter:'all', query:'', showHidden:!!boot.showHidden, editorPath:'', dirty:false, anchor:-1};
  const icons = {dir:'▣', link:'⤷', file:'▤'};
  const codeExt = new Set(['php','js','ts','tsx','jsx','json','css','html','htm','xml','sql','py','sh','md','ini','yml','yaml','env','txt','log','conf']);
  const imageExt = new Set(['png','jpg','jpeg','gif','webp']);
  const zipExt = new Set(['zip']);
  function join(dir, name){ return dir ? dir.replace(/\/+$/,'') + '/' + name : name; }
  function parent(p){ const i = p.lastIndexOf('/'); return i < 0 ? '' : p.slice(0,i); }
  function base(p){ const i = p.lastIndexOf('/'); return i < 0 ? p : p.slice(i+1); }
  async function go(view){
    state.view = view;
    document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    $('#side').classList.remove('open');
    const search = $('#search');
    search.hidden = view !== 'files';
    try {
      if (view === 'dashboard') await dashboard();
      else if (view === 'files') await openDir(state.path || boot.defaultPath || '');
      else if (view === 'server') await server();
      else if (view === 'logs') await logs();
      else if (view === 'terminal') await terminal();
      else if (view === 'settings') await settings();
    } catch (e) { toast(e.message, true); }
  }
  function meter(label, value, text){
    return el('article', {class:'card'}, [el('h3', {}, [label]), el('div', {class:'stat'}, [text]), el('div', {class:'meter'}, [el('span', {style:'width:'+value+'%'})])]);
  }
  async function dashboard(){
    const res = await api('dashboard');
    const d = res.data, s = d.stats, diskUsed = Math.max(0, s.disk_total - s.disk_free);
    const view = $('#view');
    view.replaceChildren(el('h2', {}, ['Dashboard']));
    if (d.notices?.length) d.notices.forEach(n => view.append(el('div', {class:'notice'}, [n])));
    if (d.recovery) view.append(el('div', {class:'notice'}, ['A recovery code was used. Generate new codes in Settings.']));
    const cpu = s.cpu == null ? 'n/a' : s.cpu + '%';
    const ram = s.memory ? fmt(s.memory.used) + ' / ' + fmt(s.memory.total) : 'n/a';
    const ramPct = s.memory ? pct(s.memory.used, s.memory.total) : 0;
    view.append(el('section', {class:'grid'}, [
      meter('CPU', s.cpu || 0, cpu),
      meter('Memory', ramPct, ram),
      meter('Disk', pct(diskUsed, s.disk_total), fmt(diskUsed) + ' / ' + fmt(s.disk_total)),
      meter('Load', s.load ? Math.min(100, s.load[0] * 20) : 0, s.load ? s.load.map(n => Number(n).toFixed(2)).join('  ') : 'n/a')
    ]));
    const info = el('div', {class:'kv'});
    [['OS', s.os], ['PHP', s.php + ' · ' + s.sapi], ['Software', s.server || 'n/a'], ['Host', s.hostname], ['Uptime', s.uptime ? fmtDuration(s.uptime) : 'n/a'], ['Root', s.root], ['HTTPS', s.https ? 'yes' : 'no']].forEach(([k,v]) => { info.append(el('b', {}, [k]), el('span', {}, [v || ''])); });
    const recent = el('div');
    (d.recent || []).forEach(r => recent.append(el('div', {}, [el('button', {class:'btn ghost small', type:'button'}, [r.path])])));
    recent.querySelectorAll('button').forEach(b => b.addEventListener('click', () => { state.view = 'files'; openDir(parent(b.textContent)); }));
    const activity = el('div', {class:'mono'});
    (d.audit || []).forEach(row => activity.append(el('div', {}, [(row.ok ? '' : 'failed ') + row.action + ' · ' + (row.detail || '')])));
    view.append(el('section', {class:'split'}, [el('article', {class:'card'}, [el('h3', {}, ['System']), info]), el('article', {class:'card'}, [el('h3', {}, ['Recent files']), recent.childNodes.length ? recent : el('p', {class:'muted'}, ['Files you open will show up here.'])])]));
    view.append(el('article', {class:'card'}, [el('h3', {}, ['Recent activity']), activity.childNodes.length ? activity : el('p', {class:'muted'}, ['No audit events yet.'])]));
    $('#crumbs').replaceChildren(el('span', {}, ['Dashboard']));
    $('#status').textContent = 'PHP ' + s.php;
  }
  function fmtDuration(sec){
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    return [d ? d + 'd' : '', h ? h + 'h' : '', m + 'm'].filter(Boolean).join(' ');
  }
  function visibleItems(){
    const q = state.query.trim().toLowerCase();
    return state.items.filter(item => {
      if (!state.showHidden && item.hidden) return false;
      if (q && !item.name.toLowerCase().includes(q)) return false;
      if (state.filter === 'folders') return item.type === 'dir';
      if (state.filter === 'files') return item.type === 'file';
      if (state.filter === 'images') return imageExt.has(item.ext);
      if (state.filter === 'code') return codeExt.has(item.ext);
      if (state.filter === 'archives') return zipExt.has(item.ext);
      return true;
    }).sort((a,b) => {
      if (a.type === 'dir' && b.type !== 'dir') return -1;
      if (b.type === 'dir' && a.type !== 'dir') return 1;
      const av = state.sort === 'size' ? a.size : state.sort === 'mtime' ? a.mtime : a.name.toLowerCase();
      const bv = state.sort === 'size' ? b.size : state.sort === 'mtime' ? b.mtime : b.name.toLowerCase();
      if (av < bv) return -1 * state.dir;
      if (av > bv) return 1 * state.dir;
      return 0;
    });
  }
  function crumbs(){
    const box = $('#crumbs');
    box.replaceChildren();
    const root = el('button', {type:'button'}, ['Root']);
    root.addEventListener('click', () => openDir(''));
    box.append(root);
    let acc = '';
    if (!state.path) return;
    state.path.split('/').filter(Boolean).forEach(part => {
      acc = join(acc, part);
      const path = acc;
      const b = el('button', {type:'button'}, [' / ' + part]);
      b.addEventListener('click', () => openDir(path));
      box.append(b);
    });
  }
  async function openDir(path){
    state.path = path || '';
    state.selected.clear();
    const res = await api('list', {path: state.path});
    state.path = res.data.path || '';
    state.items = res.data.items || [];
    renderFiles(res.data.truncated);
    crumbs();
  }
  function renderFiles(truncated){
    const items = visibleItems();
    const view = $('#view');
    const filters = ['all','folders','files','images','code','archives'].map(name => {
      const b = el('button', {type:'button', class: state.filter === name ? 'on' : ''}, [name]);
      b.addEventListener('click', () => { state.filter = name; renderFiles(truncated); });
      return b;
    });
    const hidden = el('button', {type:'button', class:'btn ghost small'}, [state.showHidden ? 'Hide dotted' : 'Show dotted']);
    hidden.addEventListener('click', async () => {
      state.showHidden = !state.showHidden;
      try { await api('pref', {key:'show_hidden', value: state.showHidden}); } catch (e) { toast(e.message, true); }
      renderFiles(truncated);
    });
    const toolbar = el('div', {class:'toolbar'}, [
      el('div', {class:'chips'}, filters),
      hidden,
      button('Upload', () => $('#file-input').click()),
      button('New file', newFile),
      button('New folder', newFolder),
      button('Refresh', () => openDir(state.path))
    ]);
    const head = el('thead');
    const hr = el('tr');
    const all = el('input', {type:'checkbox'});
    all.checked = items.length > 0 && items.every(i => state.selected.has(i.path));
    all.addEventListener('change', () => { items.forEach(i => all.checked ? state.selected.add(i.path) : state.selected.delete(i.path)); renderFiles(truncated); });
    [['', all], ['name','Name'], ['size','Size'], ['mtime','Modified'], ['perms','Permissions'], ['owner','Owner']].forEach(([key, label]) => {
      const th = el('th', {}, [label]);
      if (key) th.addEventListener('click', () => { if (state.sort === key) state.dir *= -1; else { state.sort = key; state.dir = 1; } renderFiles(truncated); });
      if (!key) th.append(all) ;
      hr.append(th);
    });
    head.append(hr);
    const body = el('tbody');
    items.forEach((item, index) => {
      const cb = el('input', {type:'checkbox'});
      cb.checked = state.selected.has(item.path);
      cb.addEventListener('click', e => { e.stopPropagation(); toggleSelect(item, index, e.shiftKey); renderFiles(truncated); });
      const name = el('button', {type:'button', class:'btn ghost'}, [icons[item.type] || icons.file, ' ', item.name + (item.protected ? ' · protected' : '')]);
      name.addEventListener('click', () => activate(item));
      const more = el('button', {type:'button', class:'iconbtn', 'aria-label':'Actions'}, ['⋯']);
      more.addEventListener('click', e => { e.stopPropagation(); menuFor(item, e.clientX, e.clientY); });
      const tr = el('tr', {draggable:'true'});
      if (state.selected.has(item.path)) tr.classList.add('selected');
      tr.addEventListener('contextmenu', e => { e.preventDefault(); menuFor(item, e.clientX, e.clientY); });
      tr.addEventListener('dragstart', e => {
        const paths = state.selected.has(item.path) ? [...state.selected] : [item.path];
        e.dataTransfer.setData('application/x-fm-paths', JSON.stringify(paths));
        e.dataTransfer.effectAllowed = 'move';
      });
      if (item.type === 'dir') {
        tr.addEventListener('dragover', e => { if ([...e.dataTransfer.types].includes('application/x-fm-paths')) { e.preventDefault(); tr.classList.add('drop'); } });
        tr.addEventListener('dragleave', () => tr.classList.remove('drop'));
        tr.addEventListener('drop', async e => {
          tr.classList.remove('drop');
          const raw = e.dataTransfer.getData('application/x-fm-paths');
          if (!raw) return;
          e.preventDefault();
          try { await api('move', {paths: JSON.parse(raw), dest: item.path}); await openDir(state.path); toast('Moved'); }
          catch (err) { toast(err.message, true); }
        });
      }
      tr.append(el('td', {}, [cb]), el('td', {}, [el('div', {class:'name'}, [name, more])]), el('td', {}, [item.type === 'file' ? fmt(item.size) : '—']), el('td', {}, [when(item.mtime)]), el('td', {class:'mono'}, [(item.symbolic || '') + ' ' + (item.perms || '')]), el('td', {class:'hide-sm'}, [item.owner || '']));
      body.append(tr);
    });
    const table = el('table', {}, [head, body]);
    const listing = el('div', {class:'listing', id:'listing'}, [toolbar]);
    if (state.selected.size) {
      listing.append(el('div', {class:'bulk'}, [
        el('strong', {}, [state.selected.size + ' selected']),
        button('Download', downloadSelected),
        button('Move', () => transfer('move')),
        button('Copy', () => transfer('copy')),
        button('Zip', zipSelected),
        button('Delete', deleteSelected, true)
      ]));
    }
    listing.append(el('div', {class:'table-wrap'}, [items.length ? table : el('p', {class:'muted', style:'padding:18px'}, ['This folder is empty.'])]));
    const tree = el('div', {class:'tree', id:'tree'});
    view.replaceChildren(el('div', {class:'files'}, [tree, listing]));
    $('#status').textContent = items.length + ' shown' + (truncated ? ' · directory truncated at 5000 entries' : '') + (state.selected.size ? ' · ' + state.selected.size + ' selected' : '');
    buildTree();
    const listingEl = $('#listing');
    listingEl.addEventListener('dragover', e => { if ([...e.dataTransfer.types].includes('Files')) { e.preventDefault(); listingEl.classList.add('drop'); } });
    listingEl.addEventListener('dragleave', () => listingEl.classList.remove('drop'));
    listingEl.addEventListener('drop', e => {
      if (!e.dataTransfer.files?.length) return;
      e.preventDefault(); listingEl.classList.remove('drop'); uploadFiles(e.dataTransfer.files);
    });
  }
  function button(label, fn, danger=false){
    const b = el('button', {type:'button', class:'btn small' + (danger ? ' danger' : ' ghost')}, [label]);
    b.addEventListener('click', fn); return b;
  }
  function toggleSelect(item, index, shift){
    if (shift && state.anchor >= 0) {
      const items = visibleItems();
      const [a,b] = [state.anchor, index].sort((x,y) => x-y);
      for (let i = a; i <= b; i++) state.selected.add(items[i].path);
    } else if (state.selected.has(item.path)) state.selected.delete(item.path);
    else state.selected.add(item.path);
    state.anchor = index;
  }
  async function buildTree(){
    const tree = $('#tree'); if (!tree) return;
    tree.replaceChildren(el('strong', {}, ['Folders']));
    try {
      const res = await api('list', {path:''});
      res.data.items.filter(i => i.type === 'dir' && (state.showHidden || !i.hidden)).forEach(i => tree.append(treeButton(i)));
    } catch (e) { tree.append(el('p', {class:'muted'}, [e.message])); }
  }
  function treeButton(item){
    const b = el('button', {type:'button'}, [item.name]);
    b.addEventListener('click', () => openDir(item.path));
    return b;
  }
  function activate(item){
    if (item.type === 'dir') return openDir(item.path);
    if (imageExt.has(item.ext)) return preview(item);
    if (codeExt.has(item.ext) || item.size < 262144) return edit(item);
    return downloadPaths([item.path]);
  }
  function menuFor(item, x, y){
    const menu = $('#menu');
    const add = (label, fn, danger=false) => {
      const b = el('button', {type:'button'}, [label]);
      if (danger) b.style.color = 'var(--danger)';
      b.addEventListener('click', () => { menu.hidden = true; fn(); });
      menu.append(b);
    };
    menu.replaceChildren();
    if (item.type === 'dir') add('Open', () => openDir(item.path));
    else {
      if (imageExt.has(item.ext)) add('Preview', () => preview(item));
      if (codeExt.has(item.ext) || item.type === 'file') add('Edit', () => edit(item));
      add('Download', () => downloadPaths([item.path]));
    }
    if (zipExt.has(item.ext)) add('Extract', () => unzip(item));
    add('Rename', () => rename(item));
    add('Duplicate', () => duplicate([item.path]));
    add('Copy to…', () => transfer('copy', [item.path]));
    add('Move to…', () => transfer('move', [item.path]));
    add('Zip', () => zipPaths([item.path]));
    add('Permissions', () => chmod(item));
    if (!item.protected) add('Delete', () => deletePaths([item.path]), true);
    menu.hidden = false;
    menu.style.left = Math.min(x, innerWidth - 210) + 'px';
    menu.style.top = Math.min(y, innerHeight - 280) + 'px';
  }
  async function newFile(){
    const body = el('label', {}, ['File name', el('input', {name:'name', required:'required'})]);
    const v = await ask({title:'New file', body, ok:'Create'});
    if (!v || !v.name) return;
    try { await api('create', {path: state.path, name: v.name}); await openDir(state.path); toast('File created'); }
    catch (e) { toast(e.message, true); }
  }
  async function newFolder(){
    const body = el('label', {}, ['Folder name', el('input', {name:'name', required:'required'})]);
    const v = await ask({title:'New folder', body, ok:'Create'});
    if (!v || !v.name) return;
    try { await api('mkdir', {path: state.path, name: v.name}); await openDir(state.path); toast('Folder created'); }
    catch (e) { toast(e.message, true); }
  }
  async function rename(item){
    const input = el('input', {name:'name', value:item.name});
    const v = await ask({title:'Rename', body: el('label', {}, ['New name', input]), ok:'Rename'});
    if (!v || !v.name || v.name === item.name) return;
    try { await api('rename', {path: item.path, name: v.name}); await openDir(state.path); }
    catch (e) { toast(e.message, true); }
  }
  async function deletePaths(paths){
    const v = await ask({title:'Delete ' + paths.length + ' item' + (paths.length>1?'s':''), body:'This cannot be undone. Folders are removed with everything inside them.', ok:'Delete', danger:true});
    if (!v) return;
    try { const res = await api('delete', {paths}); toast('Removed ' + res.data.count + ' item' + (res.data.count===1?'':'s')); await openDir(state.path); }
    catch (e) { toast(e.message, true); }
  }
  function deleteSelected(){ deletePaths([...state.selected]); }
  async function duplicate(paths){
    try { await api('duplicate', {paths}); await openDir(state.path); toast('Duplicated'); }
    catch (e) { toast(e.message, true); }
  }
  async function transfer(op, paths){
    paths = paths || [...state.selected];
    let dest = state.path;
    const body = el('div');
    const label = el('p', {}, ['Destination: /' + dest]);
    const list = el('div');
    body.append(label, list, el('p', {class:'muted'}, ['Open a folder, then confirm.']));
    async function browse(path){
      dest = path;
      label.textContent = 'Destination: /' + (path || '');
      const res = await api('list', {path});
      list.replaceChildren(button('Up', () => browse(parent(path))));
      res.data.items.filter(i => i.type === 'dir').forEach(i => list.append(button(i.name, () => browse(i.path))));
    }
    await browse(state.path);
    const v = await ask({title: op === 'move' ? 'Move' : 'Copy', body, ok: op === 'move' ? 'Move here' : 'Copy here'});
    if (!v) return;
    try { await api(op, {paths, dest}); await openDir(state.path); toast(op === 'move' ? 'Moved' : 'Copied'); }
    catch (e) { toast(e.message, true); }
  }
  async function chmod(item){
    const bits = String(item.perms || '644').slice(-3);
    const labels = ['User read','User write','User execute','Group read','Group write','Group execute','Other read','Other write','Other execute'];
    const box = el('div');
    const checks = [];
    labels.forEach((label, i) => {
      const digit = parseInt(bits[Math.floor(i / 3)] || '0', 8);
      const input = el('input', {type:'checkbox'});
      input.checked = !!(digit & (1 << (2 - (i % 3))));
      checks.push(input);
      box.append(el('label', {class:'check'}, [input, label]));
    });
    const v = await ask({title:'Permissions for ' + item.name, body: box, ok:'Save'});
    if (!v) return;
    let mode = 0;
    checks.forEach((input, i) => { if (input.checked) mode |= 1 << (8 - i); });
    try { await api('chmod', {path: item.path, mode: mode.toString(8).padStart(3,'0')}); await openDir(state.path); }
    catch (e) { toast(e.message, true); }
  }
  async function downloadPaths(paths){
    try {
      const res = paths.length === 1 ? await apiBlob('download', {path: paths[0]}) : await apiBlob('download_zip', {paths});
      saveBlob(res.blob, res.name);
    } catch (e) { toast(e.message, true); }
  }
  function downloadSelected(){ downloadPaths([...state.selected]); }
  async function zipPaths(paths){
    const v = await ask({title:'Create zip', body: el('label', {}, ['File name', el('input', {name:'name', value:'archive.zip'})]), ok:'Create'});
    if (!v) return;
    try { await api('zip', {paths, path: state.path, name: v.name}); await openDir(state.path); toast('Archive created'); }
    catch (e) { toast(e.message, true); }
  }
  function zipSelected(){ zipPaths([...state.selected]); }
  async function unzip(item){
    const v = await ask({title:'Extract archive', body:'Files are extracted into a new folder. Executable types such as PHP are skipped.', ok:'Extract'});
    if (!v) return;
    try {
      const res = await api('unzip', {path: item.path});
      const skipped = res.data.skipped?.length ? ' Skipped ' + res.data.skipped.length + '.' : '';
      toast('Extracted ' + res.data.written + ' file' + (res.data.written===1?'':'s') + '.' + skipped);
      await openDir(state.path);
    } catch (e) { toast(e.message, true); }
  }
  async function preview(item){
    try {
      const res = await apiBlob('preview', {path: item.path});
      const img = el('img', {alt:item.name, style:'max-width:100%;height:auto'});
      img.src = URL.createObjectURL(res.blob);
      await ask({title:item.name, body: img, ok:'Close', cancel:'Download'});
    } catch (e) { toast(e.message, true); }
  }
  const KEYWORDS = {php:'function class return if else elseif foreach while public private protected namespace use new echo require include true false null', js:'function return const let var if else for while class new true false null undefined async await export import', ts:'function return const let var if else for while class new true false null undefined async await export import type interface', py:'def class return if elif else for while import from True False None', sql:'select from where insert update delete create table join left inner and or not null', sh:'if then else fi for while do done echo exit function local'};
  function highlight(src, ext){
    if (src.length > 100000) return esc(src);
    const keys = new Set((KEYWORDS[ext] || '').split(' ').filter(Boolean));
    let out = '', i = 0;
    const push = (text, cls) => { out += cls ? '<span class="'+cls+'">'+esc(text)+'</span>' : esc(text); };
    while (i < src.length) {
      if (src.startsWith('/*', i)) {
        const end = src.indexOf('*/', i + 2);
        const j = end < 0 ? src.length : end + 2;
        push(src.slice(i, j), 'tok-c'); i = j; continue;
      }
      if (src.startsWith('//', i) || ((ext === 'py' || ext === 'sh') && src[i] === '#')) {
        const end = src.indexOf('\n', i);
        const j = end < 0 ? src.length : end;
        push(src.slice(i, j), 'tok-c'); i = j; continue;
      }
      const q = src[i];
      if (q === '"' || q === "'" || q === '`') {
        let j = i + 1;
        while (j < src.length && src[j] !== q) { if (src[j] === '\\') j++; j++; }
        if (j < src.length) j++;
        push(src.slice(i, j), 'tok-s'); i = j; continue;
      }
      if (/[A-Za-z_]/.test(src[i])) {
        let j = i + 1;
        while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
        const word = src.slice(i, j);
        push(word, keys.has(word) ? 'tok-k' : ''); i = j; continue;
      }
      if (/[0-9]/.test(src[i])) {
        let j = i + 1;
        while (j < src.length && /[0-9.]/.test(src[j])) j++;
        push(src.slice(i, j), 'tok-n'); i = j; continue;
      }
      push(src[i], ''); i++;
    }
    return out;
  }
  async function edit(itemOrPath){
    const path = typeof itemOrPath === 'string' ? itemOrPath : itemOrPath.path;
    try {
      const res = await api('read', {path});
      const file = res.data;
      if (file.script) {
        const ok = await ask({title:'Executable file', body:'The web server may run this file if it is requested directly. The panel itself will not execute it.', ok:'Edit', danger:true});
        if (!ok) return;
      }
      const ext = (file.name.split('.').pop() || '').toLowerCase();
      const ta = $('#editor'), pre = $('#editor-pre'), gutter = $('#gutter');
      $('#editor-title').textContent = file.path;
      state.editorPath = file.path;
      state.dirty = false;
      ta.value = file.content;
      const paint = () => { pre.innerHTML = highlight(ta.value, ext) + '\n'; gutter.textContent = ta.value.split('\n').map((_,i)=>String(i+1)).join('\n'); };
      ta.oninput = () => { state.dirty = true; paint(); };
      ta.onscroll = () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; gutter.scrollTop = ta.scrollTop; };
      ta.onkeydown = e => {
        if (e.key === 'Tab') { e.preventDefault(); const s = ta.selectionStart; ta.setRangeText('  ', s, ta.selectionEnd, 'end'); paint(); }
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveEditor(); }
      };
      paint();
      $('#editor-dialog').showModal();
    } catch (e) { toast(e.message, true); }
  }
  async function saveEditor(){
    try {
      await api('write', {path: state.editorPath, content: $('#editor').value});
      state.dirty = false; toast('Saved');
    } catch (e) { toast(e.message, true); }
  }
  async function uploadFiles(list){
    const fd = new FormData();
    fd.append('action','upload'); fd.append('csrf', boot.csrf); fd.append('path', state.path);
    [...list].forEach(f => fd.append('files[]', f, f.name));
    busy(true);
    try {
      const data = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', endpoint);
        xhr.setRequestHeader('X-CSRF-Token', boot.csrf);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.upload.onprogress = e => { if (e.lengthComputable) $('#status').textContent = 'Uploading ' + Math.round(e.loaded / e.total * 100) + '%'; };
        xhr.onload = () => { let d = {}; try { d = JSON.parse(xhr.responseText); } catch { reject(new Error('Upload failed')); return; } d.ok ? resolve(d) : reject(new Error(d.error || 'Upload failed')); };
        xhr.onerror = () => reject(new Error('Upload failed'));
        xhr.send(fd);
      });
      toast('Uploaded ' + (data.data.saved?.length || 0) + ' file' + ((data.data.saved?.length||0)===1?'':'s'));
      await openDir(state.path);
    } catch (e) { toast(e.message, true); }
    finally { busy(false); }
  }
  async function server(){
    const res = await api('server');
    const d = res.data, view = $('#view');
    view.replaceChildren(el('h2', {}, ['Server']));
    const kv = rows => { const box = el('div', {class:'kv'}); rows.forEach(([k,v]) => { box.append(el('b', {}, [k]), el('span', {class:'mono'}, [v ?? ''])); }); return box; };
    const s = d.stats;
    view.append(el('article', {class:'card'}, [el('h3', {}, ['Machine']), kv([['OS', s.os], ['PHP', s.php], ['SAPI', s.sapi], ['Hostname', s.hostname], ['Disk free', fmt(s.disk_free)], ['Uptime', s.uptime ? fmtDuration(s.uptime) : 'n/a']])]));
    view.append(el('article', {class:'card'}, [el('h3', {}, ['PHP configuration']), kv(Object.entries(d.php.ini))]));
    const mounts = el('div');
    (d.mounts || []).forEach(m => mounts.append(el('div', {}, [m.mount + ' · ' + m.type + ' · ' + fmt(m.free) + ' free'])));
    view.append(el('article', {class:'card'}, [el('h3', {}, ['Storage']), mounts]));
    const net = el('div');
    (d.network.interfaces || []).forEach(i => net.append(el('div', {class:'mono'}, [i.name + '  rx ' + fmt(i.rx) + '  tx ' + fmt(i.tx)])));
    const host = el('input', {name:'host', placeholder:'example.com'});
    const lookup = button('Resolve', async () => {
      try { const r = await api('dns', {host: host.value}); toast(r.data.addresses.join(', ') || 'No addresses'); } catch (e) { toast(e.message, true); }
    });
    view.append(el('article', {class:'card'}, [el('h3', {}, ['Network']), el('p', {}, [d.network.hostname + (d.network.addr ? ' · ' + d.network.addr : '')]), net, el('div', {class:'row'}, [host, lookup])]));
    const procs = el('div', {class:'mono'});
    view.append(el('article', {class:'card'}, [el('div', {class:'spread'}, [el('h3', {}, ['Processes']), button('Load', async () => {
      try {
        const r = await api('processes');
        procs.replaceChildren();
        if (!r.data.available) procs.append(el('p', {}, [r.data.note || 'Unavailable']));
        else r.data.rows.slice(0, 80).forEach(p => procs.append(el('div', {}, [p.pid + '  ' + p.user + '  ' + p.state + '  ' + p.name])));
      } catch (e) { toast(e.message, true); }
    })]), procs]));
    const cron = el('pre', {class:'mono'});
    view.append(el('article', {class:'card'}, [el('div', {class:'spread'}, [el('h3', {}, ['Cron']), button('Load', async () => {
      try {
        const r = await api('cron');
        cron.textContent = r.data.available ? r.data.files.map(f => '# ' + f.name + '\n' + f.body).join('\n\n') : (r.data.note || 'Unavailable');
      } catch (e) { toast(e.message, true); }
    })]), cron]));
    const usage = el('div');
    view.append(el('article', {class:'card'}, [el('div', {class:'spread'}, [el('h3', {}, ['Disk usage in current folder']), button('Analyze', async () => {
      try {
        const r = await api('analyze', {path: state.path});
        usage.replaceChildren();
        const max = Math.max(1, ...r.data.rows.map(x => x.size));
        r.data.rows.forEach(row => usage.append(el('div', {}, [row.name + ' · ' + fmt(row.size)]), el('div', {class:'meter'}, [el('span', {style:'width:' + Math.round(row.size / max * 100) + '%'})])));
        if (r.data.truncated) usage.append(el('p', {class:'muted'}, ['Scan stopped early to keep the request short.']));
      } catch (e) { toast(e.message, true); }
    })]), usage]));
    const env = el('div', {class:'kv'});
    Object.entries(d.php.env || {}).forEach(([k,v]) => { env.append(el('b', {}, [k]), el('span', {class:'mono'}, [v])); });
    view.append(el('article', {class:'card'}, [el('h3', {}, ['Environment']), env]));
    $('#crumbs').replaceChildren(el('span', {}, ['Server']));
  }
  async function logs(){
    const res = await api('logs');
    const view = $('#view');
    const pre = el('pre', {class:'term'});
    const select = el('select');
    (res.data.logs || []).forEach(l => select.append(el('option', {value:l.id}, [l.label])));
    async function load(){
      try { const r = await api('log', {id: select.value}); pre.textContent = r.data.body || 'Empty log.'; }
      catch (e) { toast(e.message, true); }
    }
    select.addEventListener('change', load);
    view.replaceChildren(el('div', {class:'spread'}, [el('h2', {}, ['Logs']), el('div', {class:'row'}, [select, button('Refresh', load)])]), pre);
    if (select.value) await load();
    $('#crumbs').replaceChildren(el('span', {}, ['Logs']));
  }
  async function terminal(){
    const view = $('#view');
    if (!boot.terminal) {
      view.replaceChildren(el('h2', {}, ['Terminal']), el('article', {class:'card'}, [el('p', {}, [boot.terminalReady ? 'The terminal is off. Turn it on in Settings. It stays limited to an allowlist and never opens a shell.' : 'This server cannot run the controlled terminal. File tools still work.'])]));
      $('#crumbs').replaceChildren(el('span', {}, ['Terminal']));
      return;
    }
    const out = el('div', {class:'term'}, ['Allowlisted commands only. Working directory is the file root.\n']);
    const input = el('input', {name:'cmd', placeholder:'ls', autocomplete:'off'});
    const form = el('form', {class:'row'}, [input, el('button', {class:'btn', type:'submit'}, ['Run'])]);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const command = input.value;
      input.value = '';
      out.append(document.createTextNode('\n$ ' + command + '\n'));
      try {
        const res = await api('terminal', {command});
        out.append(document.createTextNode((res.data.stdout || '') + (res.data.stderr || '') + '\n'));
      } catch (err) { out.append(document.createTextNode(err.message + '\n')); }
      out.scrollTop = out.scrollHeight;
    });
    view.replaceChildren(el('h2', {}, ['Terminal']), out, form);
    $('#crumbs').replaceChildren(el('span', {}, ['Terminal']));
  }
  function field(label, node){ return el('label', {}, [label, node]); }
  async function settings(){
    const res = await api('settings');
    const s = res.data.settings, account = res.data.account, view = $('#view');
    const brand = el('input', {name:'brand_name', value:s.brand_name});
    const timeout = el('input', {name:'session_timeout', type:'number', value:s.session_timeout});
    const upload = el('input', {name:'max_upload_mb', type:'number', value:s.max_upload_mb});
    const editor = el('input', {name:'editor_max_kb', type:'number', value:s.editor_max_kb});
    const allow = el('input', {name:'allowed_extensions', value:(s.allowed_extensions || []).join(', ')});
    const block = el('input', {name:'blocked_extensions', value:(s.blocked_extensions || []).join(', ')});
    const theme = el('select', {name:'theme'});
    ['system','light','dark'].forEach(v => theme.append(el('option', {value:v}, [v])));
    theme.value = s.theme;
    const tz = el('input', {name:'timezone', value:s.timezone});
    const def = el('input', {name:'default_directory', value:s.default_directory});
    const hidden = el('input', {type:'checkbox', name:'show_hidden'}); hidden.checked = !!s.show_hidden;
    const audit = el('input', {type:'checkbox', name:'audit_enabled'}); audit.checked = !!s.audit_enabled;
    const attempts = el('input', {name:'login_max_attempts', type:'number', value:s.login_max_attempts});
    const lock = el('input', {name:'login_lock_minutes', type:'number', value:s.login_lock_minutes});
    const root = el('input', {name:'root_path', value:s.root_path});
    const term = el('input', {type:'checkbox', name:'terminal_enabled'}); term.checked = !!s.terminal_enabled;
    const enable = el('input', {name:'confirm_terminal', placeholder:'ENABLE'});
    const pass = el('input', {name:'current_password', type:'password', autocomplete:'current-password'});
    const known = ['ls','pwd','df','du','free','uptime','whoami','date','uname','id','ps','hostname','nproc','stat','wc','head','tail','cat','file'];
    const allowBox = el('div');
    const chosen = new Set(s.terminal_allowlist || []);
    known.forEach(cmd => {
      const c = el('input', {type:'checkbox'}); c.checked = chosen.has(cmd); c.dataset.cmd = cmd;
      allowBox.append(el('label', {class:'check'}, [c, cmd]));
    });
    const extra = el('input', {name:'extra_cmds', placeholder:'extra command names, separated by spaces', value:(s.terminal_allowlist || []).filter(c => !known.includes(c)).join(' ')});
    const logs = el('textarea', {name:'extra_logs', rows:'3'}); logs.value = (s.extra_logs || []).join('\n');
    const form = el('form', {class:'card'}, [
      el('h3', {}, ['Branding and appearance']),
      field('Application name', brand), field('Theme', theme), field('Timezone', tz),
      el('label', {class:'check'}, [hidden, 'Show hidden files by default']),
      el('h3', {}, ['Session and sign-in']),
      field('Session timeout (seconds)', timeout), field('Failed attempts before lockout', attempts), field('Lockout minutes', lock),
      el('label', {class:'check'}, [audit, 'Write the audit log']),
      el('h3', {}, ['Files']),
      field('Upload limit (MB)', upload), field('Editor limit (KB)', editor),
      field('Allowed extensions (empty means all except blocked)', allow),
      field('Extra blocked extensions', block), field('Default directory inside the root', def),
      el('h3', {}, ['File root']),
      el('p', {class:'muted'}, ['Changing the root exposes that directory to this administrator. The data directory stays protected.']),
      field('Absolute root path', root),
      el('h3', {}, ['Terminal']),
      el('p', {class:'muted'}, [res.data.terminal_runnable ? 'Off by default. Shells, editors that run code, and destructive system tools cannot be allowlisted.' : 'This PHP build cannot start the terminal.']),
      el('label', {class:'check'}, [term, 'Enable terminal']),
      field('Type ENABLE to turn it on', enable), allowBox, field('Additional allowlist names', extra),
      el('h3', {}, ['Extra logs']),
      el('p', {class:'muted'}, ['One absolute path per line. Only .log files, /var/log, or the PHP error log are accepted.']),
      logs,
      field('Current password for root or terminal changes', pass),
      el('div', {class:'actions'}, [el('button', {class:'btn', type:'submit'}, ['Save settings'])])
    ]);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const cmds = [...allowBox.querySelectorAll('input')].filter(i => i.checked).map(i => i.dataset.cmd);
      extra.value.split(/\s+/).filter(Boolean).forEach(c => cmds.push(c));
      const settings = {
        brand_name: brand.value, theme: theme.value, timezone: tz.value.trim(), show_hidden: hidden.checked,
        session_timeout: Number(timeout.value), login_max_attempts: Number(attempts.value), login_lock_minutes: Number(lock.value),
        audit_enabled: audit.checked, max_upload_mb: Number(upload.value), editor_max_kb: Number(editor.value),
        allowed_extensions: allow.value.split(',').map(x => x.trim()).filter(Boolean),
        blocked_extensions: block.value.split(',').map(x => x.trim()).filter(Boolean),
        default_directory: def.value.trim(), root_path: root.value.trim(), terminal_enabled: term.checked,
        terminal_allowlist: cmds, extra_logs: logs.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)
      };
      try {
        const saved = await api('save_settings', {settings, current_password: pass.value, confirm_terminal: enable.value});
        pass.value = ''; enable.value = '';
        toast(saved.data.note || 'Settings saved');
        boot.theme = settings.theme; applyTheme(settings.theme); $('#brand-name').textContent = settings.brand_name;
      } catch (err) { toast(err.message, true); }
    });
    const user = el('input', {name:'username', value:account.username});
    const np = el('input', {name:'new_password', type:'password', autocomplete:'new-password'});
    const cp = el('input', {name:'current_password', type:'password'});
    const acct = el('form', {class:'card'}, [el('h3', {}, ['Administrator']), field('Username', user), field('New password', np), field('Current password', cp), el('div', {class:'actions'}, [el('button', {class:'btn', type:'submit'}, ['Update account'])])]);
    acct.addEventListener('submit', async e => {
      e.preventDefault();
      try { await api('save_account', {username: user.value, new_password: np.value, current_password: cp.value}); np.value=''; cp.value=''; toast('Account updated'); }
      catch (err) { toast(err.message, true); }
    });
    const tpass = el('input', {type:'password', name:'password'});
    const totpBox = el('div', {class:'card'}, [el('h3', {}, ['Two-factor authentication']), el('p', {}, [account.totp ? 'Authenticator app is on.' : 'Authenticator app is off.']), field('Current password', tpass)]);
    if (!account.totp) {
      const b = button('Start setup', async () => {
        try {
          const r = await api('totp_begin', {password: tpass.value});
          const secret = el('p', {class:'mono'}, [r.data.secret]);
          const code = el('input', {name:'code', inputmode:'numeric'});
          const body = el('div', {}, [el('p', {}, ['Add this key to your authenticator app, then enter a code.']), secret, el('p', {class:'mono'}, [r.data.uri]), code]);
          const v = await ask({title:'Confirm two-factor', body, ok:'Enable'});
          if (!v) return;
          const done = await api('totp_enable', {code: code.value});
          const codes = el('div', {class:'mono'});
          (done.data.recovery || []).forEach(c => codes.append(el('div', {}, [c])));
          await ask({title:'Recovery codes', body: el('div', {}, [el('p', {}, ['Store these codes somewhere safe. They are shown once.']), codes]), ok:'I saved them', cancel:'Close'});
          go('settings');
        } catch (err) { toast(err.message, true); }
      });
      totpBox.append(b);
    } else {
      const code = el('input', {name:'code'});
      totpBox.append(field('Current code', code), button('Turn off', async () => {
        try { await api('totp_disable', {password: tpass.value, code: code.value}); toast('Two-factor turned off'); go('settings'); }
        catch (err) { toast(err.message, true); }
      }), button('New recovery codes', async () => {
        try {
          const r = await api('recovery', {password: tpass.value, code: code.value});
          const codes = el('div', {class:'mono'});
          (r.data.recovery || []).forEach(c => codes.append(el('div', {}, [c])));
          await ask({title:'Recovery codes', body: codes, ok:'Done', cancel:'Close'});
        } catch (err) { toast(err.message, true); }
      }));
    }
    const nginx = el('pre', {class:'mono'});
    nginx.textContent = 'location ~ /\\.fmdata/ {\n    deny all;\n}';
    view.replaceChildren(el('h2', {}, ['Settings']), form, acct, totpBox, el('article', {class:'card'}, [el('h3', {}, ['Web server']), el('p', {}, ['Apache and IIS rules are written into .fmdata automatically. Nginx needs this location:']), nginx, el('p', {class:'muted'}, ['Effective upload limit: ' + fmt(res.data.upload_limit) + '. Version ' + boot.version])]));
    $('#crumbs').replaceChildren(el('span', {}, ['Settings']));
  }
  document.querySelectorAll('.nav button').forEach(b => b.addEventListener('click', () => go(b.dataset.view)));
  $('#logout').addEventListener('click', async () => { try { await api('logout'); } catch {} location.reload(); });
  $('#menu-btn').addEventListener('click', () => $('#side').classList.toggle('open'));
  $('#theme-btn').addEventListener('click', async () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('fm-theme', next); applyTheme(next);
    try { await api('pref', {key:'theme', value: next}); } catch {}
  });
  $('#search').addEventListener('input', () => { state.query = $('#search').value; if (state.view === 'files') renderFiles(false); });
  $('#search').addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const q = $('#search').value.trim();
    if (q.length < 2) return;
    try {
      const contents = e.shiftKey;
      const res = await api('search', {path: state.path, q, contents});
      state.items = res.data.hits || [];
      state.query = '';
      $('#search').value = '';
      renderFiles(res.data.truncated);
      toast(state.items.length + ' match' + (state.items.length===1?'':'es') + (contents ? ' in names and text' : ''));
    } catch (err) { toast(err.message, true); }
  });
  $('#file-input').addEventListener('change', e => { if (e.target.files?.length) uploadFiles(e.target.files); e.target.value = ''; });
  $('#editor-save').addEventListener('click', saveEditor);
  $('#editor-close').addEventListener('click', async () => {
    if (state.dirty) {
      const v = await ask({title:'Close editor', body:'Discard unsaved changes?', ok:'Discard', danger:true});
      if (!v) return;
    }
    $('#editor-dialog').close();
    openDir(state.path);
  });
  document.addEventListener('click', e => { if (!$('#menu').contains(e.target)) $('#menu').hidden = true; });
  document.addEventListener('keydown', e => {
    const typing = ['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName);
    if (e.key === 'Escape') { $('#menu').hidden = true; $('#side').classList.remove('open'); }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && $('#editor-dialog').open) { e.preventDefault(); saveEditor(); }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); $('#search').focus(); }
    if (e.key === '?' ) help();
    if (state.view !== 'files') return;
    if (e.key === 'n') newFile();
    if (e.key === 'N') newFolder();
    if (e.key === 'F2' && state.selected.size === 1) rename(state.items.find(i => i.path === [...state.selected][0]));
    if (e.key === 'Delete' && state.selected.size) deleteSelected();
  });
  async function help(){
    await ask({title:'Shortcuts', body: el('div', {}, ['/ search this folder','Enter searches names. Shift+Enter also searches text.','n new file · N new folder','Delete removes the selection · F2 renames','Ctrl+S saves the editor','Esc closes menus'].map(t => el('div', {}, [t]))), ok:'Close', cancel:'Close'});
  }
  let timer = boot.timeout || 1800, warn;
  setInterval(() => {
    if (document.visibilityState !== 'visible') return;
    timer -= 1;
    if (timer === 60) toast('Your session will expire in a minute.');
    if (timer <= 0) { timer = 86400; api('logout').finally(() => location.reload()); }
  }, 1000);
  document.addEventListener('pointerdown', () => { timer = boot.timeout || 1800; });
  const oldApi = api;
  $('#brand-name').textContent = boot.brand || 'File Manager';
  $('#who').textContent = boot.user || '';
  go('dashboard');
  if (boot.recovery) toast('A recovery code was used. Generate new ones in Settings.');
})();
FMJS;
    }
}

final class FmApp
{
    private FmStore $store;
    private ?array $cfg = null;
    private ?FmAuth $auth = null;
    private ?FmFiles $files = null;

    public function run(): void
    {
        if (PHP_VERSION_ID < 80100) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            echo 'PHP 8.1 or newer is required.';
            return;
        }
        umask(0077);
        FmHttp::securityHeaders();
        $this->store = new FmStore(__DIR__);
        try {
            $this->store->ensureLayout();
            $this->bootSession();
            $this->dispatch();
        } catch (FmException $e) {
            $this->fail($e);
        } catch (Throwable $e) {
            error_log('file_manager: ' . $e->getMessage());
            $this->fail(new FmException('Something went wrong.', 500));
        }
    }

    private function bootSession(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_name('FMSESSID');
            session_save_path($this->store->dir . DIRECTORY_SEPARATOR . 'sessions');
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => FmHttp::cookiePath(),
                'domain' => '',
                'secure' => FmHttp::https(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            @ini_set('session.use_strict_mode', '1');
            @ini_set('session.use_only_cookies', '1');
            @ini_set('session.use_trans_sid', '0');
            session_start();
        }
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new FmException('Sessions are unavailable.', 500);
        }
        if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
            $_SESSION['csrf'] = FmCrypto::randomHex(32);
        }
    }

    private function dispatch(): void
    {
        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($method === 'GET') {
            $this->render();
            return;
        }
        if ($method !== 'POST') {
            throw new FmException('Method not allowed.', 405);
        }
        FmHttp::assertOrigin();
        $input = $this->input();
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($input['csrf'] ?? null);
        $known = (string)($_SESSION['csrf'] ?? '');
        if ($known === '' || !is_string($token) || !hash_equals($known, $token)) {
            throw new FmException('Security token mismatch. Reload the page.', 403);
        }
        $action = (string)($input['action'] ?? '');
        if (!preg_match('/^[a-z_]{2,40}$/', $action)) {
            throw new FmException('Unknown action.', 404);
        }
        $installed = $this->store->installed();
        if (!$installed) {
            if ($action !== 'setup') {
                throw new FmException('Setup is required.', 401);
            }
            $this->setup($input);
            return;
        }
        $this->loadCfg();
        if (!in_array($action, ['login', 'totp'], true)) {
            $this->auth->requireAuth();
        }
        match ($action) {
            'login' => $this->login($input),
            'totp' => $this->totp($input),
            'logout' => $this->logout(),
            'dashboard' => $this->dashboard(),
            'list' => $this->listing($input),
            'mkdir' => $this->mkdir($input),
            'create' => $this->create($input),
            'rename' => $this->rename($input),
            'move' => $this->transfer('move', $input),
            'copy' => $this->transfer('copy', $input),
            'duplicate' => $this->duplicate($input),
            'delete' => $this->delete($input),
            'chmod' => $this->chmod($input),
            'read' => $this->read($input),
            'write' => $this->write($input),
            'upload' => $this->upload($input),
            'download' => $this->download($input, false),
            'preview' => $this->download($input, true),
            'download_zip' => $this->downloadZip($input),
            'zip' => $this->zip($input),
            'unzip' => $this->unzip($input),
            'search' => $this->search($input),
            'server' => $this->server(),
            'processes' => $this->processes(),
            'cron' => $this->cron(),
            'dns' => $this->dns($input),
            'analyze' => $this->analyze($input),
            'logs' => $this->logs(),
            'log' => $this->log($input),
            'terminal' => $this->terminal($input),
            'settings' => $this->settings(),
            'save_settings' => $this->saveSettings($input),
            'save_account' => $this->saveAccount($input),
            'pref' => $this->pref($input),
            'totp_begin' => $this->totpBegin($input),
            'totp_enable' => $this->totpEnable($input),
            'totp_disable' => $this->totpDisable($input),
            'recovery' => $this->recovery($input),
            default => throw new FmException('Unknown action.', 404),
        };
    }

    private function input(): array
    {
        $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
        $type = (string)($_SERVER['CONTENT_TYPE'] ?? '');
        if (str_contains($type, 'multipart/form-data')) {
            if ($length > 0 && $_POST === [] && $_FILES === []) {
                throw new FmException('Upload exceeds the server limit.', 413);
            }
            return $_POST;
        }
        $raw = file_get_contents('php://input');
        if ($length > 0 && ($raw === false || $raw === '')) {
            throw new FmException('Request exceeds the server limit.', 413);
        }
        if (!is_string($raw) || strlen($raw) > 12 * 1048576) {
            throw new FmException('Request is too large.', 413);
        }
        try {
            $data = json_decode($raw === '' ? '[]' : $raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new FmException('Request could not be read.');
        }
        if (!is_array($data)) {
            throw new FmException('Request could not be read.');
        }
        return $data;
    }

    private function loadCfg(): void
    {
        $this->cfg = $this->store->load();
        $tz = (string)$this->cfg['settings']['timezone'];
        if (in_array($tz, timezone_identifiers_list(), true)) {
            date_default_timezone_set($tz);
        }
        $this->auth = new FmAuth($this->store, $this->cfg);
    }

    private function files(): FmFiles
    {
        if ($this->files === null) {
            $root = (string)($this->cfg['settings']['root_path'] ?? '');
            if ($root === '' || !is_dir($root)) {
                $root = __DIR__;
            }
            $this->files = new FmFiles(new FmPath($root), $this->store->dir, __FILE__, $this->cfg['settings']);
        }
        return $this->files;
    }

    private function system(): FmSystem
    {
        return new FmSystem($this->files()->paths()->root(), $this->store, $this->cfg['settings']);
    }

    private function render(): void
    {
        $mode = 'setup';
        $brand = 'File Manager';
        if ($this->store->installed()) {
            $this->loadCfg();
            $brand = (string)$this->cfg['settings']['brand_name'];
            if (!empty($_SESSION['pre_auth'])) {
                $mode = 'totp';
            } elseif ($this->auth->loggedIn()) {
                try {
                    $this->auth->requireAuth();
                    $mode = 'app';
                } catch (FmException) {
                    $this->bootSession();
                    $mode = 'login';
                }
            } else {
                $mode = 'login';
            }
        }
        $recovery = !empty($_SESSION['recovery_used']);
        unset($_SESSION['recovery_used']);
        $settings = $this->cfg['settings'] ?? FmStore::defaults();
        $boot = [
            'mode' => $mode,
            'csrf' => (string)$_SESSION['csrf'],
            'brand' => $brand,
            'https' => FmHttp::https(),
            'version' => FM_VERSION,
        ];
        if ($mode === 'app') {
            $boot += [
                'user' => (string)$_SESSION['user'],
                'theme' => (string)$settings['theme'],
                'timeout' => (int)$settings['session_timeout'],
                'showHidden' => (bool)$settings['show_hidden'],
                'terminal' => FmTerminal::enabled($settings) && FmTerminal::runnable(),
                'terminalReady' => FmTerminal::runnable(),
                'defaultPath' => (string)$settings['default_directory'],
                'recovery' => $recovery,
            ];
        }
        FmUi::page($brand, $this->body($mode), FmUi::css(), FmUi::script(), $boot);
    }

    private function body(string $mode): string
    {
        if ($mode !== 'app') {
            return '<main class="gate"><form class="gate-card" id="gate"><div class="mark" aria-hidden="true">FM</div><h1 id="gate-title"></h1><p class="muted" id="gate-sub"></p><div id="gate-fields"></div><button class="btn" id="gate-submit" type="submit">Continue</button><p class="err" id="gate-error"></p><p class="byline">Made by <a class="by" href="https://inside.ansnew.com/" target="_blank" rel="noopener noreferrer">ANSNEW TECH.</a></p></form></main><div class="toasts" id="toasts" aria-live="polite"></div><noscript><p>JavaScript is required.</p></noscript>';
        }
        return <<<'FMHTML'
<div class="app"><aside class="side" id="side"><div class="brand"><div class="mark" aria-hidden="true">FM</div><div><b id="brand-name">File Manager</b><span>Server panel</span></div></div><nav class="nav"><button type="button" data-view="dashboard">Dashboard</button><button type="button" data-view="files">Files</button><button type="button" data-view="server">Server</button><button type="button" data-view="logs">Logs</button><button type="button" data-view="terminal">Terminal</button><button type="button" data-view="settings">Settings</button></nav><div class="grow"></div><div class="userbox"><span id="who"></span><button type="button" class="btn ghost small" id="logout">Sign out</button></div></aside><div class="main"><div id="progress"></div><header class="top"><button type="button" class="iconbtn" id="menu-btn" aria-label="Menu">Menu</button><div class="crumbs" id="crumbs"></div><input class="search" id="search" type="search" placeholder="Search, Enter" hidden><button type="button" class="iconbtn" id="theme-btn" aria-label="Theme">Theme</button></header><div class="view" id="view"></div><footer class="foot"><span class="status" id="status"></span><a class="by" href="https://inside.ansnew.com/" target="_blank" rel="noopener noreferrer">ANSNEW TECH.</a></footer></div></div><input type="file" id="file-input" multiple hidden><div id="menu" class="menu" hidden></div><div class="toasts" id="toasts" aria-live="polite"></div><dialog id="ask"><form class="modal" id="ask-form"><h2 id="ask-title"></h2><div id="ask-body"></div><div class="actions"><button type="button" class="btn ghost" id="ask-cancel">Cancel</button><button type="submit" class="btn" id="ask-ok">Confirm</button></div></form></dialog><dialog id="editor-dialog"><div class="modal"><div class="spread"><h2 id="editor-title">Editor</h2><div class="row"><button type="button" class="btn ghost" id="editor-close">Close</button><button type="button" class="btn" id="editor-save">Save</button></div></div><div class="editor"><pre class="gutter" id="gutter"></pre><div class="editor-layer"><pre id="editor-pre"></pre><textarea id="editor" spellcheck="false" aria-label="File contents"></textarea></div></div></div></dialog>
FMHTML;
    }

    private function setup(array $in): void
    {
        $user = $this->username((string)($in['username'] ?? ''));
        $pass = (string)($in['password'] ?? '');
        $confirm = (string)($in['confirm'] ?? '');
        if ($pass !== $confirm) {
            throw new FmException('Passwords do not match.');
        }
        $this->assertPassword($pass);
        $this->store->lock(function () use ($user, $pass) {
            if ($this->store->installed()) {
                throw new FmException('Setup is already complete.', 403);
            }
            $settings = FmStore::defaults();
            $settings['root_path'] = realpath(__DIR__) ?: __DIR__;
            $cfg = [
                'version' => 1,
                'app_key' => FmCrypto::randomHex(32),
                'installed_at' => time(),
                'dummy_hash' => FmCrypto::hashPassword(FmCrypto::randomHex(24)),
                'user' => [
                    'username' => $user,
                    'password_hash' => FmCrypto::hashPassword($pass),
                    'totp_secret' => '',
                    'totp_enabled' => false,
                    'recovery_hashes' => [],
                ],
                'settings' => $settings,
            ];
            $this->store->save($cfg);
        });
        $this->loadCfg();
        session_regenerate_id(true);
        $_SESSION = ['csrf' => FmCrypto::randomHex(32), 'fp' => $this->auth->fingerprint(), 'reg' => time(), 'last' => time(), 'auth' => true, 'user' => $user, 'recent' => []];
        $this->audit('setup', 'administrator created', true, true);
        FmHttp::json(['ok' => true, 'data' => ['ready' => true]]);
    }

    private function login(array $in): void
    {
        try {
            $result = $this->auth->login($this->text($in, 'username', 64), (string)($in['password'] ?? ''));
        } catch (FmException $e) {
            $this->audit('login_failed', 'rejected', false, true);
            throw $e;
        }
        $this->audit($result['totp'] ? 'login_password' : 'login', 'accepted', true, true);
        FmHttp::json(['ok' => true, 'data' => $result]);
    }

    private function totp(array $in): void
    {
        try {
            $this->auth->verifyTotp($this->text($in, 'code', 64));
        } catch (FmException $e) {
            $this->audit('totp_failed', 'rejected', false, true);
            throw $e;
        }
        $this->audit('login', 'two-factor accepted', true, true);
        FmHttp::json(['ok' => true, 'data' => ['ready' => true]]);
    }

    private function logout(): void
    {
        $this->audit('logout', '', true, true);
        $this->auth->destroy();
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function dashboard(): void
    {
        $rows = [];
        foreach (array_reverse(array_filter(explode("\n", $this->store->tail($this->store->dir . DIRECTORY_SEPARATOR . 'audit.log', 65536, 20)))) as $line) {
            $row = json_decode($line, true);
            if (!is_array($row)) {
                continue;
            }
            $rows[] = ['time' => $row['time'] ?? '', 'action' => $row['action'] ?? '', 'detail' => $row['detail'] ?? '', 'ok' => (bool)($row['ok'] ?? true)];
            if (count($rows) >= 8) {
                break;
            }
        }
        FmHttp::json(['ok' => true, 'data' => [
            'stats' => $this->system()->snapshot(),
            'recent' => array_values(is_array($_SESSION['recent'] ?? null) ? $_SESSION['recent'] : []),
            'audit' => $rows,
            'notices' => $this->notices(),
            'recovery' => false,
        ]]);
    }

    private function listing(array $in): void
    {
        FmHttp::json(['ok' => true, 'data' => $this->files()->list($this->rel($in))]);
    }

    private function mkdir(array $in): void
    {
        $path = $this->files()->mkdir($this->rel($in), $this->text($in, 'name', 255));
        $this->audit('mkdir', $path);
        FmHttp::json(['ok' => true, 'data' => ['path' => $path]]);
    }

    private function create(array $in): void
    {
        $name = $this->text($in, 'name', 255);
        $path = $this->files()->create($this->rel($in), $name);
        $this->audit(FmPath::scriptLike($name) ? 'create_script' : 'create', $path, true, FmPath::scriptLike($name));
        FmHttp::json(['ok' => true, 'data' => ['path' => $path]]);
    }

    private function rename(array $in): void
    {
        $path = $this->files()->rename($this->rel($in), $this->text($in, 'name', 255));
        $this->audit('rename', $path);
        FmHttp::json(['ok' => true, 'data' => ['path' => $path]]);
    }

    private function transfer(string $op, array $in): void
    {
        $paths = $this->rels($in);
        $dest = $this->rel($in, 'dest');
        $count = $op === 'move' ? $this->files()->move($paths, $dest) : $this->files()->copy($paths, $dest);
        $this->audit($op, $count . ' to ' . $dest);
        FmHttp::json(['ok' => true, 'data' => ['count' => $count]]);
    }

    private function duplicate(array $in): void
    {
        $made = $this->files()->duplicate($this->rels($in));
        $this->audit('duplicate', implode(', ', $made));
        FmHttp::json(['ok' => true, 'data' => ['paths' => $made]]);
    }

    private function delete(array $in): void
    {
        $paths = $this->rels($in);
        $count = $this->files()->delete($paths);
        $this->audit('delete', implode(', ', $paths), true, true);
        FmHttp::json(['ok' => true, 'data' => ['count' => $count]]);
    }

    private function chmod(array $in): void
    {
        $path = $this->rel($in);
        $this->files()->chmod($path, $this->text($in, 'mode', 8));
        $this->audit('chmod', $path . ' ' . $this->text($in, 'mode', 8), true, true);
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function read(array $in): void
    {
        $max = max(16, (int)$this->cfg['settings']['editor_max_kb']) * 1024;
        $data = $this->files()->read($this->rel($in), $max);
        $this->remember($data['path']);
        FmHttp::json(['ok' => true, 'data' => $data]);
    }

    private function write(array $in): void
    {
        if (!isset($in['content']) || !is_string($in['content'])) {
            throw new FmException('Missing content.');
        }
        $path = $this->rel($in);
        $max = max(16, (int)$this->cfg['settings']['editor_max_kb']) * 1024;
        $this->files()->write($path, $in['content'], $max);
        $script = FmPath::scriptLike(basename(str_replace('\\', '/', $path)));
        $this->audit($script ? 'edit_script' : 'edit', $path, true, $script);
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function upload(array $in): void
    {
        $this->longer();
        $saved = $this->files()->upload($this->rel($in), $_FILES['files'] ?? []);
        $this->audit('upload', implode(', ', $saved), true, true);
        FmHttp::json(['ok' => true, 'data' => ['saved' => $saved]]);
    }

    private function download(array $in, bool $inline): never
    {
        $rel = $this->rel($in);
        $path = $this->files()->absolute($rel, true);
        $this->remember($rel);
        $this->sendFile($path, $inline);
    }

    private function downloadZip(array $in): never
    {
        $this->longer();
        $this->store->cleanTmp();
        $tmp = (new FmArchive($this->files(), $this->store->dir . DIRECTORY_SEPARATOR . 'tmp'))->tempZip($this->rels($in));
        try {
            $this->sendFile($tmp, false, 'files.zip', true);
        } finally {
            @unlink($tmp);
        }
    }

    private function zip(array $in): void
    {
        $this->longer();
        $path = (new FmArchive($this->files(), $this->store->dir . DIRECTORY_SEPARATOR . 'tmp'))->create($this->rels($in), $this->rel($in), $this->text($in, 'name', 255));
        $this->audit('zip', $path);
        FmHttp::json(['ok' => true, 'data' => ['path' => $path]]);
    }

    private function unzip(array $in): void
    {
        $this->longer();
        $result = (new FmArchive($this->files(), $this->store->dir . DIRECTORY_SEPARATOR . 'tmp'))->extract($this->rel($in));
        $this->audit('unzip', (string)$result['path']);
        FmHttp::json(['ok' => true, 'data' => $result]);
    }

    private function search(array $in): void
    {
        $this->longer();
        $data = $this->files()->search($this->rel($in), $this->text($in, 'q', 80), $this->boolish($in['contents'] ?? false));
        FmHttp::json(['ok' => true, 'data' => $data]);
    }

    private function server(): void
    {
        $system = $this->system();
        FmHttp::json(['ok' => true, 'data' => [
            'stats' => $system->snapshot(),
            'php' => $system->phpInfo(),
            'mounts' => $system->mounts(),
            'network' => $system->network(),
        ]]);
    }

    private function processes(): void
    {
        FmHttp::json(['ok' => true, 'data' => $this->system()->processes()]);
    }

    private function cron(): void
    {
        FmHttp::json(['ok' => true, 'data' => $this->system()->cron()]);
    }

    private function dns(array $in): void
    {
        $this->hit('dns', 10);
        FmHttp::json(['ok' => true, 'data' => $this->system()->lookup($this->text($in, 'host', 253))]);
    }

    private function analyze(array $in): void
    {
        $this->hit('analyze', 6);
        $this->longer();
        $dir = $this->files()->absolute($this->rel($in), true);
        FmHttp::json(['ok' => true, 'data' => $this->system()->analyze($dir)]);
    }

    private function logs(): void
    {
        FmHttp::json(['ok' => true, 'data' => ['logs' => $this->system()->logs()]]);
    }

    private function log(array $in): void
    {
        FmHttp::json(['ok' => true, 'data' => ['body' => $this->system()->logBody($this->text($in, 'id', 20))]]);
    }

    private function terminal(array $in): void
    {
        if (!FmTerminal::enabled($this->cfg['settings'])) {
            throw new FmException('Terminal is disabled.', 403);
        }
        $this->hit('term', 20);
        $command = $this->text($in, 'command', 500);
        $allow = FmTerminal::filterAllow(is_array($this->cfg['settings']['terminal_allowlist'] ?? null) ? $this->cfg['settings']['terminal_allowlist'] : []);
        try {
            $result = (new FmTerminal())->run($command, $allow, $this->files()->paths());
        } catch (FmException $e) {
            $this->audit('terminal', $command, false, true);
            throw $e;
        }
        $this->audit('terminal', $command, true, true);
        FmHttp::json(['ok' => true, 'data' => $result]);
    }

    private function settings(): void
    {
        FmHttp::json(['ok' => true, 'data' => [
            'settings' => $this->publicSettings(),
            'account' => ['username' => (string)$this->cfg['user']['username'], 'totp' => !empty($this->cfg['user']['totp_enabled'])],
            'terminal_runnable' => FmTerminal::runnable(),
            'upload_limit' => $this->uploadLimit(),
        ]]);
    }

    private function saveSettings(array $in): void
    {
        $input = is_array($in['settings'] ?? null) ? $in['settings'] : [];
        $current = $this->cfg['settings'];
        $next = $current;
        $next['session_timeout'] = $this->intBetween($input['session_timeout'] ?? $current['session_timeout'], 300, 86400);
        $next['max_upload_mb'] = $this->intBetween($input['max_upload_mb'] ?? $current['max_upload_mb'], 1, 512);
        $next['editor_max_kb'] = $this->intBetween($input['editor_max_kb'] ?? $current['editor_max_kb'], 16, 4096);
        $next['login_max_attempts'] = $this->intBetween($input['login_max_attempts'] ?? $current['login_max_attempts'], 3, 20);
        $next['login_lock_minutes'] = $this->intBetween($input['login_lock_minutes'] ?? $current['login_lock_minutes'], 1, 1440);
        $next['show_hidden'] = array_key_exists('show_hidden', $input) ? $this->boolish($input['show_hidden']) : (bool)$current['show_hidden'];
        $next['audit_enabled'] = array_key_exists('audit_enabled', $input) ? $this->boolish($input['audit_enabled']) : (bool)$current['audit_enabled'];
        $next['terminal_enabled'] = array_key_exists('terminal_enabled', $input) ? $this->boolish($input['terminal_enabled']) : (bool)$current['terminal_enabled'];
        $theme = (string)($input['theme'] ?? $current['theme']);
        if (!in_array($theme, ['system', 'light', 'dark'], true)) {
            throw new FmException('Unknown theme.');
        }
        $next['theme'] = $theme;
        $next['language'] = 'en';
        $tz = trim((string)($input['timezone'] ?? $current['timezone']));
        if (!in_array($tz, timezone_identifiers_list(), true)) {
            throw new FmException('Unknown timezone.');
        }
        $next['timezone'] = $tz;
        $next['brand_name'] = $this->brand($input['brand_name'] ?? $current['brand_name']);
        $next['allowed_extensions'] = FmHttp::cleanList($input['allowed_extensions'] ?? $current['allowed_extensions'], 40, '/^[a-z0-9]{1,10}$/');
        $next['blocked_extensions'] = FmHttp::cleanList($input['blocked_extensions'] ?? $current['blocked_extensions'], 40, '/^[a-z0-9]{1,10}$/');
        $requested = is_array($input['terminal_allowlist'] ?? null) ? $input['terminal_allowlist'] : $current['terminal_allowlist'];
        $filtered = FmTerminal::filterAllow(is_array($requested) ? $requested : []);
        $next['terminal_allowlist'] = $filtered;
        $root = trim((string)($input['root_path'] ?? $current['root_path']));
        $next['root_path'] = $this->normalizeRoot($root);
        $next['default_directory'] = trim((string)($input['default_directory'] ?? $current['default_directory']));
        if ($next['default_directory'] !== '') {
            $probe = new FmPath($next['root_path']);
            $dir = $probe->resolve($next['default_directory'], true, true);
            if (!is_dir($dir)) {
                throw new FmException('Default directory is not a folder.');
            }
            $next['default_directory'] = $probe->relative($dir);
        }
        $logs = [];
        $extra = $input['extra_logs'] ?? $current['extra_logs'];
        if (is_array($extra)) {
            $checker = new FmSystem($next['root_path'], $this->store, $next);
            foreach ($extra as $path) {
                if (!is_string($path) || trim($path) === '') {
                    continue;
                }
                if (strlen($path) > 500 || str_contains($path, "\0") || !$checker->logAllowed($path)) {
                    throw new FmException('A log path is not allowed. Use a .log file, /var/log, or the PHP error log.');
                }
                $logs[] = (string)realpath($path);
                if (count($logs) > 10) {
                    throw new FmException('Too many log paths.');
                }
            }
        }
        $next['extra_logs'] = $logs;
        $turningOn = $next['terminal_enabled'] && !$current['terminal_enabled'];
        $rootChanged = $next['root_path'] !== $current['root_path'];
        if (($turningOn || $rootChanged) && !FmCrypto::passwordOk((string)($in['current_password'] ?? ''), (string)$this->cfg['user']['password_hash'])) {
            throw new FmException('Enter your current password to change that setting.', 403);
        }
        if ($turningOn && (string)($in['confirm_terminal'] ?? '') !== 'ENABLE') {
            throw new FmException('Type ENABLE to turn the terminal on.', 403);
        }
        $this->update(function (array $cfg) use ($next) {
            $cfg['settings'] = $next;
            return $cfg;
        });
        $this->audit('settings', $turningOn ? 'terminal enabled' : 'updated', true, true);
        $dropped = array_values(array_diff(array_map(static fn($c) => strtolower(trim((string)$c)), is_array($requested) ? $requested : []), $filtered));
        FmHttp::json(['ok' => true, 'data' => ['note' => $dropped ? 'Settings saved. Some commands cannot be allowlisted and were removed.' : 'Settings saved.']]);
    }

    private function saveAccount(array $in): void
    {
        $current = (string)($in['current_password'] ?? '');
        if (!FmCrypto::passwordOk($current, (string)$this->cfg['user']['password_hash'])) {
            throw new FmException('Current password is wrong.', 403);
        }
        $user = $this->username((string)($in['username'] ?? $this->cfg['user']['username']));
        $new = (string)($in['new_password'] ?? '');
        $hash = (string)$this->cfg['user']['password_hash'];
        if ($new !== '') {
            $this->assertPassword($new);
            $hash = FmCrypto::hashPassword($new);
        }
        $this->update(function (array $cfg) use ($user, $hash) {
            $cfg['user']['username'] = $user;
            $cfg['user']['password_hash'] = $hash;
            return $cfg;
        });
        session_regenerate_id(true);
        $_SESSION['user'] = $user;
        $_SESSION['reg'] = time();
        $this->audit('account', 'updated', true, true);
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function pref(array $in): void
    {
        $key = (string)($in['key'] ?? '');
        $settings = $this->cfg['settings'];
        if ($key === 'show_hidden') {
            $settings['show_hidden'] = $this->boolish($in['value'] ?? false);
        } elseif ($key === 'theme' && in_array((string)($in['value'] ?? ''), ['system', 'light', 'dark'], true)) {
            $settings['theme'] = (string)$in['value'];
        } else {
            throw new FmException('Unknown preference.');
        }
        $this->update(function (array $cfg) use ($settings) {
            $cfg['settings'] = $settings;
            return $cfg;
        });
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function totpBegin(array $in): void
    {
        if (!FmCrypto::passwordOk((string)($in['password'] ?? ''), (string)$this->cfg['user']['password_hash'])) {
            throw new FmException('Current password is wrong.', 403);
        }
        if (!function_exists('openssl_encrypt') && !function_exists('sodium_crypto_secretbox')) {
            throw new FmException('Encryption is unavailable on this server.', 500);
        }
        $secret = FmCrypto::base32Encode(random_bytes(20));
        $_SESSION['totp_pending'] = $secret;
        $user = rawurlencode((string)$this->cfg['user']['username']);
        $brand = rawurlencode((string)$this->cfg['settings']['brand_name']);
        FmHttp::json(['ok' => true, 'data' => [
            'secret' => $secret,
            'uri' => 'otpauth://totp/' . $brand . ':' . $user . '?secret=' . $secret . '&issuer=' . $brand . '&algorithm=SHA1&digits=6&period=30',
        ]]);
    }

    private function totpEnable(array $in): void
    {
        $secret = (string)($_SESSION['totp_pending'] ?? '');
        if ($secret === '' || !FmCrypto::totpValid($secret, $this->text($in, 'code', 12))) {
            throw new FmException('Invalid authentication code.', 401);
        }
        $codes = [];
        $hashes = [];
        for ($i = 0; $i < 8; $i++) {
            $code = FmCrypto::recoveryCode();
            $codes[] = $code;
            $hashes[] = password_hash(FmCrypto::normalizeRecovery($code), PASSWORD_BCRYPT);
        }
        $stored = FmCrypto::encrypt($secret, (string)$this->cfg['app_key']);
        $this->update(function (array $cfg) use ($stored, $hashes) {
            $cfg['user']['totp_secret'] = $stored;
            $cfg['user']['totp_enabled'] = true;
            $cfg['user']['recovery_hashes'] = $hashes;
            return $cfg;
        });
        unset($_SESSION['totp_pending']);
        $this->audit('totp_on', 'enabled', true, true);
        FmHttp::json(['ok' => true, 'data' => ['recovery' => $codes]]);
    }

    private function totpDisable(array $in): void
    {
        $this->assertSecondFactor($in);
        $this->update(function (array $cfg) {
            $cfg['user']['totp_secret'] = '';
            $cfg['user']['totp_enabled'] = false;
            $cfg['user']['recovery_hashes'] = [];
            return $cfg;
        });
        unset($_SESSION['totp_pending']);
        $this->audit('totp_off', 'disabled', true, true);
        FmHttp::json(['ok' => true, 'data' => []]);
    }

    private function recovery(array $in): void
    {
        $this->assertSecondFactor($in);
        $codes = [];
        $hashes = [];
        for ($i = 0; $i < 8; $i++) {
            $code = FmCrypto::recoveryCode();
            $codes[] = $code;
            $hashes[] = password_hash(FmCrypto::normalizeRecovery($code), PASSWORD_BCRYPT);
        }
        $this->update(function (array $cfg) use ($hashes) {
            $cfg['user']['recovery_hashes'] = $hashes;
            return $cfg;
        });
        $this->audit('recovery_codes', 'regenerated', true, true);
        FmHttp::json(['ok' => true, 'data' => ['recovery' => $codes]]);
    }

    private function assertSecondFactor(array $in): void
    {
        if (empty($this->cfg['user']['totp_enabled'])) {
            throw new FmException('Two-factor authentication is off.');
        }
        if (!FmCrypto::passwordOk((string)($in['password'] ?? ''), (string)$this->cfg['user']['password_hash'])) {
            throw new FmException('Current password is wrong.', 403);
        }
        $secret = FmCrypto::decrypt((string)$this->cfg['user']['totp_secret'], (string)$this->cfg['app_key']);
        if (!FmCrypto::totpValid($secret, (string)($in['code'] ?? ''))) {
            throw new FmException('Invalid authentication code.', 401);
        }
    }

    private function update(callable $fn): void
    {
        $cfg = $this->store->lock(function () use ($fn) {
            $cfg = $fn($this->store->load());
            if (!is_array($cfg)) {
                throw new FmException('Configuration could not be saved.', 500);
            }
            $this->store->save($cfg);
            return $cfg;
        });
        $this->cfg = $cfg;
        $this->files = null;
        $this->auth = new FmAuth($this->store, $cfg);
    }

    private function sendFile(string $path, bool $inline, ?string $downloadName = null, bool $trusted = false): never
    {
        if (!$trusted && $this->files()->isData($path)) {
            throw new FmException('That location is protected.', 403);
        }
        if (is_link($path) || !is_file($path)) {
            throw new FmException('File not found.', 404);
        }
        $name = $downloadName ?? basename($path);
        $type = 'application/octet-stream';
        $disp = 'attachment';
        if ($inline) {
            if (!class_exists('finfo')) {
                throw new FmException('Preview is not available on this server.');
            }
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($path);
            if (!is_string($mime) || !in_array($mime, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'], true)) {
                throw new FmException('Preview is only available for PNG, JPEG, GIF, and WebP images.');
            }
            $size = filesize($path);
            if ($size === false || $size > 8 * 1048576) {
                throw new FmException('Image is too large to preview.');
            }
            $type = $mime;
            $disp = 'inline';
        }
        $ascii = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'download';
        @ini_set('zlib.output_compression', '0');
        header('Content-Type: ' . $type);
        header('X-Content-Type-Options: nosniff');
        header('Content-Disposition: ' . $disp . '; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($name));
        $size = filesize($path);
        if (is_int($size)) {
            header('Content-Length: ' . $size);
        }
        $fh = fopen($path, 'rb');
        if ($fh === false) {
            throw new FmException('File could not be read.');
        }
        while (!feof($fh)) {
            if (connection_aborted()) {
                break;
            }
            echo fread($fh, 8192);
            flush();
        }
        fclose($fh);
        exit;
    }

    private function notices(): array
    {
        $notes = [];
        if (!FmHttp::https()) {
            $notes[] = 'This connection is not HTTPS. Use HTTPS before managing a real server.';
        }
        $display = strtolower((string)ini_get('display_errors'));
        if (in_array($display, ['1', 'on', 'true'], true)) {
            $notes[] = 'PHP display_errors is on. Turn it off on a public server.';
        }
        if (empty($this->cfg['user']['totp_enabled'])) {
            $notes[] = 'Two-factor authentication is off.';
        }
        if (!empty($this->cfg['settings']['terminal_enabled'])) {
            $notes[] = 'The terminal is enabled.';
        }
        $root = $this->files()->paths()->root();
        if ($root === '/' || preg_match('/^[A-Za-z]:\\\\?$/', $root)) {
            $notes[] = 'The file root is the entire filesystem.';
        }
        return $notes;
    }

    private function publicSettings(): array
    {
        $settings = $this->cfg['settings'];
        unset($settings['app_key']);
        return $settings;
    }

    private function normalizeRoot(string $path): string
    {
        if ($path === '') {
            $path = __DIR__;
        }
        if (strlen($path) > 500 || str_contains($path, "\0")) {
            throw new FmException('Root path is not valid.');
        }
        $real = realpath($path);
        if ($real === false || !is_dir($real) || !is_readable($real)) {
            throw new FmException('Root directory is not available.');
        }
        $data = realpath($this->store->dir);
        if ($data !== false && FmPath::within($real, $data)) {
            throw new FmException('Root cannot be the data directory.', 403);
        }
        return $real;
    }

    private function remember(string $rel): void
    {
        $recent = is_array($_SESSION['recent'] ?? null) ? $_SESSION['recent'] : [];
        $recent = array_values(array_filter($recent, static fn($row) => is_array($row) && ($row['path'] ?? '') !== $rel));
        array_unshift($recent, ['path' => $rel, 'time' => time()]);
        $_SESSION['recent'] = array_slice($recent, 0, 8);
    }

    private function hit(string $bucket, int $limit): void
    {
        $now = time();
        $rows = array_values(array_filter($_SESSION['hits'][$bucket] ?? [], static fn($t) => (int)$t > $now - 60));
        if (count($rows) >= $limit) {
            throw new FmException('Slow down and try again shortly.', 429);
        }
        $rows[] = $now;
        $_SESSION['hits'][$bucket] = $rows;
    }

    private function audit(string $action, string $detail, bool $ok = true, bool $force = false): void
    {
        if (!$force && empty($this->cfg['settings']['audit_enabled'])) {
            return;
        }
        $detail = trim((string)preg_replace('/\s+/', ' ', $detail));
        $this->store->audit([
            'time' => gmdate('c'),
            'user' => (string)($_SESSION['user'] ?? ''),
            'ip' => FmHttp::clientIp(),
            'action' => $action,
            'detail' => substr($detail, 0, 300),
            'ok' => $ok,
        ]);
    }

    private function rel(array $in, string $key = 'path'): string
    {
        $value = $in[$key] ?? '';
        if (!is_string($value) || strlen($value) > 4000 || str_contains($value, "\0")) {
            throw new FmException('Path is not valid.');
        }
        return $value;
    }

    private function rels(array $in): array
    {
        $list = $in['paths'] ?? null;
        if (!is_array($list) || $list === [] || count($list) > 200) {
            throw new FmException('Choose one or more items.');
        }
        $out = [];
        foreach ($list as $item) {
            if (!is_string($item) || strlen($item) > 4000 || str_contains($item, "\0")) {
                throw new FmException('Path is not valid.');
            }
            $out[] = $item;
        }
        return $out;
    }

    private function text(array $in, string $key, int $max): string
    {
        $value = $in[$key] ?? '';
        if (!is_string($value) || strlen($value) > $max || str_contains($value, "\0")) {
            throw new FmException('A field is missing or too long.');
        }
        return $value;
    }

    private function username(string $user): string
    {
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$/', $user)) {
            throw new FmException('Username must be 3 to 32 letters, numbers, dots, underscores, or hyphens.');
        }
        return $user;
    }

    private function assertPassword(string $password): void
    {
        $length = strlen($password);
        if ($length < 12 || $length > 128) {
            throw new FmException('Use a password of 12 to 128 characters.');
        }
        if (!defined('PASSWORD_ARGON2ID') && $length > 72) {
            throw new FmException('This server accepts passwords up to 72 characters.');
        }
    }

    private function brand(mixed $value): string
    {
        $text = trim(strip_tags((string)$value));
        $text = preg_replace('/\s+/', ' ', $text) ?? '';
        $length = function_exists('mb_strlen') ? mb_strlen($text) : strlen($text);
        if ($text === '' || $length > 40 || preg_match('/[\x00-\x1F<>"\'\\\\]/', $text)) {
            throw new FmException('Brand name is not valid.');
        }
        return $text;
    }

    private function intBetween(mixed $value, int $min, int $max): int
    {
        if (!is_numeric($value)) {
            throw new FmException('A number setting is invalid.');
        }
        $number = (int)$value;
        if ($number < $min || $number > $max) {
            throw new FmException('A number setting is out of range.');
        }
        return $number;
    }

    private function boolish(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1' || $value === 'true' || $value === 'on';
    }

    private function uploadLimit(): int
    {
        $setting = max(1, (int)$this->cfg['settings']['max_upload_mb']) * 1048576;
        return (int)min($setting, FmHttp::iniBytes((string)ini_get('upload_max_filesize')), FmHttp::iniBytes((string)ini_get('post_max_size')));
    }

    private function longer(): void
    {
        if (function_exists('set_time_limit')) {
            @set_time_limit(120);
        }
    }

    private function fail(FmException $e): void
    {
        $status = ($e->getCode() >= 400 && $e->getCode() < 600) ? $e->getCode() : 422;
        $json = (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST')
            || str_contains((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json')
            || str_contains((string)($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json');
        if ($json) {
            FmHttp::json(['ok' => false, 'error' => $e->getMessage()], $status);
        }
        http_response_code($status);
        header('Content-Type: text/plain; charset=utf-8');
        echo $e->getMessage();
    }
}

final class FmSelfTest
{
    public static function run(): void
    {
        $fail = 0;
        $check = static function (bool $ok, string $message) use (&$fail): void {
            echo ($ok ? 'ok  ' : 'FAIL ') . $message . PHP_EOL;
            if (!$ok) {
                $fail++;
            }
        };
        $check(FmStore::dangerousBasename('.user.ini'), 'blocks .user.ini');
        $check(FmStore::dangerousBasename('dir/.htaccess'), 'blocks htaccess');
        $check(FmStore::dangerousBasename('web.config'), 'blocks web.config');
        $check(FmPath::uploadBlocked('shell.php.jpg', [], []), 'blocks double extensions');
        $check(!FmPath::uploadBlocked('notes.txt', [], []), 'allows text upload');
        $check(FmPath::safeZipEntry('../evil.txt') === null, 'rejects zip slip');
        $check(FmPath::safeZipEntry('ok/file.txt') === 'ok/file.txt', 'accepts safe zip entry');
        $check(FmCrypto::totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59) === '287082', 'totp test vector');
        $key = FmCrypto::randomHex();
        $check(FmCrypto::decrypt(FmCrypto::encrypt('hello', $key), $key) === 'hello', 'secret round trip');
        $check(FmTerminal::filterAllow(['ls', 'bash', 'rm', 'php']) === ['ls'], 'terminal blocklist');
        $threw = false;
        try {
            FmTerminal::assertLine('ls; id');
        } catch (FmException) {
            $threw = true;
        }
        $check($threw, 'rejects shell metacharacters');
        FmTerminal::assertLine('ls -la');
        $check(true, 'accepts a plain command');
        $root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fmtest_' . bin2hex(random_bytes(4));
        $outside = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fmout_' . bin2hex(random_bytes(4));
        $rm = static function (string $path) use (&$rm): void {
            if (is_link($path) || is_file($path)) {
                @unlink($path);
                return;
            }
            if (!is_dir($path)) {
                return;
            }
            foreach (scandir($path) ?: [] as $name) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $rm($path . DIRECTORY_SEPARATOR . $name);
            }
            @rmdir($path);
        };
        try {
            mkdir($root);
            mkdir($outside);
            mkdir($root . DIRECTORY_SEPARATOR . 'sub');
            file_put_contents($root . DIRECTORY_SEPARATOR . 'sub' . DIRECTORY_SEPARATOR . 'a.txt', 'hi');
            file_put_contents($root . DIRECTORY_SEPARATOR . 'app.php', '<?php ');
            mkdir($root . DIRECTORY_SEPARATOR . '.fmdata');
            $paths = new FmPath($root);
            $check($paths->relative($paths->resolve('sub/a.txt')) === 'sub/a.txt', 'resolves a file inside the root');
            $escaped = false;
            try {
                $paths->lexical('../etc/passwd');
            } catch (FmException) {
                $escaped = true;
            }
            $check($escaped, 'rejects parent traversal');
            $files = new FmFiles($paths, $root . DIRECTORY_SEPARATOR . '.fmdata', $root . DIRECTORY_SEPARATOR . 'app.php', FmStore::defaults());
            $protected = false;
            try {
                $files->delete(['app.php']);
            } catch (FmException) {
                $protected = true;
            }
            $check($protected, 'refuses to delete the application file');
            $dataProtected = false;
            try {
                $files->delete(['.fmdata']);
            } catch (FmException) {
                $dataProtected = true;
            }
            $check($dataProtected, 'refuses to delete the data directory');
            $files->delete(['sub']);
            $check(!is_dir($root . DIRECTORY_SEPARATOR . 'sub'), 'deletes a normal folder');
            if (@symlink($outside . DIRECTORY_SEPARATOR . 'secret.txt', $root . DIRECTORY_SEPARATOR . 'link.txt') || is_link($root . DIRECTORY_SEPARATOR . 'link.txt')) {
                file_put_contents($outside . DIRECTORY_SEPARATOR . 'secret.txt', 'nope');
                $blocked = false;
                try {
                    $paths->resolve('link.txt');
                } catch (FmException) {
                    $blocked = true;
                }
                $check($blocked, 'rejects a symlink that leaves the root');
            } else {
                $check(true, 'symlink test skipped');
            }
            if (class_exists('ZipArchive')) {
                $zipPath = $root . DIRECTORY_SEPARATOR . 'good.zip';
                $zip = new ZipArchive();
                $zip->open($zipPath, ZipArchive::CREATE);
                $zip->addFromString('ok.txt', 'hi');
                $zip->addFromString('shell.php', '<?php ');
                $zip->close();
                $result = (new FmArchive($files, $root))->extract('good.zip');
                $check(($result['written'] ?? 0) === 1 && in_array('shell.php', $result['skipped'] ?? [], true), 'extract skips php');
                $bad = $root . DIRECTORY_SEPARATOR . 'bad.zip';
                $zip = new ZipArchive();
                $zip->open($bad, ZipArchive::CREATE);
                $zip->addFromString('../evil.txt', 'x');
                $zip->close();
                $slip = false;
                try {
                    (new FmArchive($files, $root))->extract('bad.zip');
                } catch (FmException) {
                    $slip = true;
                }
                $check($slip, 'rejects a zip-slip archive');
            }
        } finally {
            $rm($root);
            $rm($outside);
        }
        exit($fail === 0 ? 0 : 1);
    }
}

if (PHP_SAPI === 'cli') {
    if (in_array('--self-test', $argv ?? [], true)) {
        FmSelfTest::run();
    }
    fwrite(STDOUT, "Open file_manager.php through a web server running PHP 8.1 or newer.\n");
    exit(0);
}

if (realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    (new FmApp())->run();
}

