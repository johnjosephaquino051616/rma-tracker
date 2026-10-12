<?php
declare(strict_types=1);

// Copy to config.php, or run: php scripts/setup.php
// Keep config.php and the data directory outside the public document root.
return [
    'access_code_hash' => '', // Generate with PHP password_hash().
    'data_directory' => __DIR__ . '/var',
    'secure_cookies' => true, // Use false only for local HTTP development.
];
