<?php
declare(strict_types=1);

// Consistent online SQLite backup; does not modify the source database.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
$configPath = dirname(__DIR__) . '/config.php';
$config = is_file($configPath) ? require $configPath : [];
if (!is_array($config)) {
    fwrite(STDERR, "Invalid configuration.\n");
    exit(1);
}
$dataDir = (string)(getenv('RMA_DATA_DIR') ?: ($config['data_directory'] ?? dirname(__DIR__) . '/var'));
$sourcePath = $dataDir . '/rma-tracker.sqlite';
if (!is_file($sourcePath)) {
    fwrite(STDERR, "The RMA database does not exist; no backup was created.\n");
    exit(1);
}
if (!class_exists(SQLite3::class)) {
    fwrite(STDERR, "The PHP sqlite3 extension is required.\n");
    exit(1);
}
$backupDir = $dataDir . '/backups';
$oldUmask = umask(0077);
try {
    if (!is_dir($backupDir) && !mkdir($backupDir, 0700, true) && !is_dir($backupDir)) {
        throw new RuntimeException('Cannot create private backups directory.');
    }
    $name = 'rma-' . gmdate('Ymd\THis\Z') . '-' . bin2hex(random_bytes(4)) . '.sqlite';
    $target = $backupDir . '/' . $name;
    $source = new SQLite3($sourcePath, SQLITE3_OPEN_READONLY);
    $destination = new SQLite3($target, SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
    try {
        if (!$source->backup($destination)) throw new RuntimeException('SQLite online backup failed.');
    } finally {
        $destination->close();
        $source->close();
    }
    chmod($target, 0600);
    fwrite(STDOUT, "Backup created: " . $target . "\n");
    fwrite(STDOUT, "Copy the backup to separate secure storage after verification.\n");
} catch (Throwable $error) {
    if (isset($target) && is_file($target)) unlink($target);
    fwrite(STDERR, "Backup failed: " . $error->getMessage() . "\n");
    exit(1);
} finally {
    umask($oldUmask);
}
