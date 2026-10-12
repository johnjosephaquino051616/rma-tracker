<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$arguments = array_slice($argv, 1);
if (array_diff($arguments, ['--local'])) {
    fwrite(STDERR, "Usage: php scripts/setup.php [--local]\n");
    exit(1);
}

$configPath = dirname(__DIR__) . '/config.php';
$accessCode = bin2hex(random_bytes(16));
$config = [
    'access_code_hash' => password_hash($accessCode, PASSWORD_DEFAULT),
    'data_directory' => dirname(__DIR__) . '/var',
    'secure_cookies' => !in_array('--local', $arguments, true),
];

$previousUmask = umask(0077);
$handle = @fopen($configPath, 'x');
umask($previousUmask);
if ($handle === false) {
    fwrite(STDERR, "Could not create config.php. An existing configuration will not be overwritten.\n");
    exit(1);
}
$content = "<?php\ndeclare(strict_types=1);\n\nreturn " . var_export($config, true) . ";\n";
$written = fwrite($handle, $content);
fclose($handle);
if ($written !== strlen($content)) {
    fwrite(STDERR, "Could not finish writing config.php.\n");
    exit(1);
}

fwrite(STDOUT, "Created private config.php. Store this generated access code securely:\n" . $accessCode . "\n");
if (in_array('--local', $arguments, true)) {
    fwrite(STDOUT, "Local HTTP mode enabled. Set secure_cookies to true before deploying with HTTPS.\n");
}
