<?php
declare(strict_types=1);

$configPath = dirname(__DIR__) . '/config.php';
$config = is_file($configPath) ? require $configPath : [];
if (!is_array($config)) json_response(['error' => 'Invalid server configuration.'], 503);
$accessCodeHash = (string)(getenv('RMA_ACCESS_CODE_HASH') ?: ($config['access_code_hash'] ?? ''));
$dataDirectory = (string)(getenv('RMA_DATA_DIR') ?: ($config['data_directory'] ?? dirname(__DIR__) . '/var'));

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex, nofollow');
$cspNonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-" . $cspNonce . "'; style-src 'nonce-" . $cspNonce . "'; connect-src 'self'; form-action 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'");
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('rma_tracker_session');
session_set_cookie_params([
    'lifetime' => 604800,
    'path' => '/',
    'secure' => (bool)($config['secure_cookies'] ?? true),
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();
if (!isset($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));


function db(): PDO {
    static $db = null;
    if ($db instanceof PDO) return $db;
    global $dataDirectory;
    $dataDir = $dataDirectory;
    if (!is_dir($dataDir)) mkdir($dataDir, 0700, true);
    $db = new PDO('sqlite:' . $dataDir . '/rma-tracker.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;');
    $db->exec('CREATE TABLE IF NOT EXISTS rmas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reference TEXT NOT NULL,
        date_entered TEXT NOT NULL,
        date_requested TEXT,
        supplier TEXT NOT NULL,
        date_accepted TEXT,
        date_returned TEXT,
        processed_by TEXT NOT NULL,
        resolution TEXT NOT NULL DEFAULT "Pending",
        erp_status TEXT NOT NULL DEFAULT "Not updated",
        status TEXT NOT NULL DEFAULT "Requested",
        notes TEXT NOT NULL DEFAULT "",
        extra_details TEXT NOT NULL DEFAULT "{}",
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS rma_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rma_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (rma_id) REFERENCES rmas(id) ON DELETE CASCADE
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS login_attempts (
        attempt_key TEXT PRIMARY KEY, failures INTEGER NOT NULL, last_failure INTEGER NOT NULL
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_rmas_updated ON rmas(updated_at DESC, id DESC)');
    return $db;
}

function json_response(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function require_auth(): void {
    if (empty($_SESSION['authorized'])) json_response(['error' => 'Unauthorized'], 401);
}

function input_field(array $input, string $key, int $max, string $fallback = ''): string {
    $value = $input[$key] ?? $fallback;
    if (!is_string($value) && !is_numeric($value)) json_response(['error' => 'Invalid ' . $key . '.'], 422);
    $text = trim((string)$value);
    if (strlen($text) > $max) json_response(['error' => $key . ' is too long.'], 422);
    return $text;
}
function input_date(array $input, string $key, string $fallback = ''): ?string {
    $value = input_field($input, $key, 10, $fallback);
    if ($value === '') return null;
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value) ||
        !checkdate((int)substr($value, 5, 2), (int)substr($value, 8, 2), (int)substr($value, 0, 4))) {
        json_response(['error' => 'Invalid date for ' . $key . '.'], 422);
    }
    return $value;
}
if (isset($_GET['api'])) {
    $action = (string)$_GET['api'];
    $method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $input = [];
    if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        if (!hash_equals((string)$_SESSION['csrf_token'], (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) {
            json_response(['error' => 'Security token expired. Refresh the page and retry.'], 403);
        }
        if (!str_starts_with(strtolower((string)($_SERVER['CONTENT_TYPE'] ?? '')), 'application/json')) {
            json_response(['error' => 'Content type must be application/json.'], 415);
        }
        $raw = file_get_contents('php://input') ?: '{}';
        if (strlen($raw) > 65536) json_response(['error' => 'Request is too large.'], 413);
        $input = json_decode($raw, true);
        if (!is_array($input) || json_last_error() !== JSON_ERROR_NONE) json_response(['error' => 'Invalid JSON request.'], 400);
    }
    if ($action === 'auth' && $method === 'POST') {
        if ($accessCodeHash === '') json_response(['error' => 'The tracker access code has not been configured.'], 503);
        try {
            $database = db();
            $key = hash_hmac('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'), $accessCodeHash);
            $database->prepare('DELETE FROM login_attempts WHERE last_failure < ?')->execute([time() - 900]);
            $stmt = $database->prepare('SELECT failures, last_failure FROM login_attempts WHERE attempt_key = ?');
            $stmt->execute([$key]);
            $attempts = $stmt->fetch();
            if ($attempts && (int)$attempts['failures'] >= 10) {
                header('Retry-After: ' . max(1, 900 - (time() - (int)$attempts['last_failure'])));
                json_response(['error' => 'Too many attempts. Try again in about 15 minutes.'], 429);
            }
            if (!password_verify(input_field($input, 'code', 256), $accessCodeHash)) {
                $stmt = $database->prepare('INSERT INTO login_attempts (attempt_key,failures,last_failure) VALUES (?,1,?)
                    ON CONFLICT(attempt_key) DO UPDATE SET failures=failures+1,last_failure=excluded.last_failure');
                $stmt->execute([$key, time()]);
                json_response(['error' => 'The access code is incorrect.'], 401);
            }
            $database->prepare('DELETE FROM login_attempts WHERE attempt_key = ?')->execute([$key]);
            session_regenerate_id(true);
            $_SESSION['authorized'] = true;
            json_response(['ok' => true]);
        } catch (Throwable $error) {
            error_log('RMA login error: ' . $error->getMessage());
            json_response(['error' => 'Login temporarily unavailable.'], 503);
        }
    }
    if ($action === 'logout' && $method === 'POST') {
        $_SESSION = [];
        session_destroy();
        json_response(['ok' => true]);
    }
    require_auth();
    if ($action === 'rmas' && $method === 'GET') {
        try {
            $rows = db()->query('SELECT id, reference, date_entered AS dateEntered, date_requested AS dateRequested, supplier, date_accepted AS dateAccepted, date_returned AS dateReturned, processed_by AS processedBy, resolution, erp_status AS erpStatus, status, notes, extra_details AS extraDetails, updated_at AS updatedAt FROM rmas ORDER BY updated_at DESC, id DESC')->fetchAll();
            json_response(['records' => $rows]);
        } catch (Throwable $error) {
            error_log('RMA read error: ' . $error->getMessage());
            json_response(['error' => 'Unable to load RMAs.'], 503);
        }
    }
    if ($action === 'rmas' && in_array($method, ['POST','PUT'], true)) {
        $supplier = input_field($input, 'supplier', 200);
        $processedBy = input_field($input, 'processedBy', 150);
        if ($supplier === '' || $processedBy === '') json_response(['error' => 'Supplier and Processed by are required.'], 422);
        $allowedStatuses = ['Requested','Awaiting supplier','Accepted','Return in transit','Resolution pending','Completed','Rejected'];
        $status = input_field($input, 'status', 60, 'Requested');
        if (!in_array($status, $allowedStatuses, true)) json_response(['error' => 'Invalid RMA status.'], 422);
        $entered = input_date($input, 'dateEntered', gmdate('Y-m-d'));
        if ($entered === null) json_response(['error' => 'Date entered is required.'], 422);
        $requested = input_date($input, 'dateRequested');
        $accepted = input_date($input, 'dateAccepted');
        $returned = input_date($input, 'dateReturned');
        $reference = input_field($input, 'reference', 100);
        if ($reference === '') $reference = 'RMA-' . strtoupper(bin2hex(random_bytes(5)));
        $resolution = input_field($input, 'resolution', 300, 'Pending');
        $erpStatus = input_field($input, 'erpStatus', 300, 'Not updated');
        $notes = input_field($input, 'notes', 12000);
        $now = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.uP');
        $values = [$reference, $entered, $requested, $supplier, $accepted, $returned,
            $processedBy, $resolution, $erpStatus, $status, $notes];
        try {
            $database = db();
            $database->beginTransaction();
            if ($method === 'POST') {
                $extra = input_field($input, 'extraDetails', 12000, '{}');
                if (!is_array(json_decode($extra, true)) || json_last_error() !== JSON_ERROR_NONE) {
                    $database->rollBack();
                    json_response(['error' => 'extraDetails must be valid JSON.'], 422);
                }
                $stmt = $database->prepare('INSERT INTO rmas (reference,date_entered,date_requested,supplier,date_accepted,date_returned,processed_by,resolution,erp_status,status,notes,extra_details,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
                $stmt->execute([...$values, $extra, $now, $now]);
                $id = (int)$database->lastInsertId();
                $actionText = 'RMA created';
            } else {
                $id = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                $expected = input_field($input, 'updatedAt', 50);
                if ($id === false || $expected === '') {
                    $database->rollBack();
                    json_response(['error' => 'Open the latest version before saving.'], 422);
                }
                $stmt = $database->prepare('SELECT updated_at, extra_details FROM rmas WHERE id = ?');
                $stmt->execute([$id]);
                $existing = $stmt->fetch();
                if (!$existing) {
                    $database->rollBack();
                    json_response(['error' => 'RMA not found.'], 404);
                }
                if (!hash_equals((string)$existing['updated_at'], $expected)) {
                    $database->rollBack();
                    json_response(['error' => 'This RMA changed in another session. Copy your edits, refresh, and reopen the RMA.'], 409);
                }
                $extra = array_key_exists('extraDetails', $input)
                    ? input_field($input, 'extraDetails', 12000) : (string)$existing['extra_details'];
                if (array_key_exists('extraDetails', $input) &&
                    (!is_array(json_decode($extra, true)) || json_last_error() !== JSON_ERROR_NONE)) {
                    $database->rollBack();
                    json_response(['error' => 'extraDetails must be valid JSON.'], 422);
                }
                $stmt = $database->prepare('UPDATE rmas SET reference=?,date_entered=?,date_requested=?,supplier=?,date_accepted=?,date_returned=?,processed_by=?,resolution=?,erp_status=?,status=?,notes=?,extra_details=?,updated_at=? WHERE id=? AND updated_at=?');
                $stmt->execute([...$values, $extra, $now, $id, $expected]);
                if ($stmt->rowCount() !== 1) {
                    $database->rollBack();
                    json_response(['error' => 'RMA was changed by someone else. Refresh and reopen it.'], 409);
                }
                $actionText = 'Updated — ' . $status;
            }
            $stmt = $database->prepare('INSERT INTO rma_history (rma_id, action, changed_by, created_at) VALUES (?,?,?,?)');
            $stmt->execute([$id, $actionText, $processedBy, $now]);
            $database->commit();
            json_response(['ok' => true, 'id' => $id], $method === 'POST' ? 201 : 200);
        } catch (Throwable $error) {
            if (isset($database) && $database->inTransaction()) $database->rollBack();
            error_log('RMA save error: ' . $error->getMessage());
            json_response(['error' => 'Unable to save RMA. Please retry.'], 503);
        }
    }
    json_response(['error' => 'Not found'], 404);
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="<?php echo htmlspecialchars((string)$_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>"><title>RMA Tracker</title>
<style nonce="<?php echo htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8'); ?>">
:root{--navy:#07111f;--cyan:#22d3ee;--teal:#0a6b78;--line:#dbe2ea;--muted:#64748b}*{box-sizing:border-box}body{margin:0;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:#172033;background:#f2f5f8}button,input,select,textarea{font:inherit}.hidden{display:none!important}.login{min-height:100vh;display:grid;place-items:center;background:var(--navy);padding:20px}.login-card{width:min(390px,100%);border:1px solid #334155;background:#0d1b2d;border-radius:18px;padding:28px;box-shadow:0 25px 60px #0007;color:#fff}.shield{display:grid;place-items:center;width:46px;height:46px;border-radius:12px;background:var(--cyan);color:var(--navy);font-size:22px}.login h1{margin:20px 0 4px;font-size:26px}.login p{color:#94a3b8}.label{display:grid;gap:6px;font-weight:600}.input{width:100%;border:1px solid #cbd5e1;border-radius:8px;padding:10px 12px;background:#fff}.login .input{background:#07111f80;color:#fff;border-color:#475569}.btn{border:0;border-radius:8px;padding:10px 16px;font-weight:650;cursor:pointer}.btn-primary{background:var(--teal);color:#fff}.login .btn-primary{background:var(--cyan);color:var(--navy);width:100%;margin-top:18px}.error{color:#e11d48;margin:10px 0}.login .error{color:#fb7185}.top{background:var(--navy);color:#fff;border-bottom:1px solid #1e293b}.top-inner,.wrap{width:min(1500px,100%);margin:auto;padding-left:24px;padding-right:24px}.top-inner{height:70px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px}.brand-icon{display:grid;place-items:center;width:38px;height:38px;border-radius:9px;background:var(--cyan);color:var(--navy);font-size:20px}.brand small{display:block;color:#94a3b8}.lock{background:transparent;color:#cbd5e1}.wrap{padding-top:28px;padding-bottom:40px}.heading{display:flex;gap:18px;justify-content:space-between;align-items:end}.eyebrow{color:#0e7490;text-transform:uppercase;letter-spacing:.16em;font-weight:750}.heading h2{font-size:30px;margin:3px 0 0}.heading p{margin:2px 0;color:var(--muted)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:26px 0 18px}.metric,.panel{background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 3px #0f172a0c}.metric{padding:20px}.metric span{color:var(--muted)}.metric strong{display:block;font-size:30px;margin-top:3px}.toolbar{display:flex;gap:12px;justify-content:space-between;padding:16px;border-bottom:1px solid var(--line)}.toolbar .input:first-child{max-width:430px}.toolbar select{max-width:220px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{padding:13px 16px;border-bottom:1px solid #e8edf2;text-align:left;white-space:nowrap}th{background:#f8fafc;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em}.ref{color:var(--teal);font-weight:750}.badge{display:inline-flex;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-size:12px;font-weight:700}.badge.Completed{background:#d1fae5;color:#047857}.badge.Rejected{background:#ffe4e6;color:#be123c}.outline{background:#fff;border:1px solid #cbd5e1}.empty{text-align:center;color:var(--muted);padding:60px!important}.modal-back{position:fixed;inset:0;background:#020617aa;display:grid;place-items:center;padding:20px}.modal{width:min(760px,100%);max-height:92vh;overflow:auto;background:#fff;border-radius:14px;padding:24px;box-shadow:0 25px 60px #0008}.modal h3{font-size:22px;margin:0}.modal>p{color:var(--muted);margin-top:4px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:20px 0}.span2{grid-column:span 2}.actions{display:flex;justify-content:flex-end;gap:10px}.footer-note{text-align:center;font-size:12px;color:#64748b;margin-top:18px}.app-error{padding:0 16px}.tool-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.result-info{padding:8px 16px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;color:var(--muted);font-size:12px}.btn:disabled{opacity:.6;cursor:wait}.btn:focus-visible,.input:focus-visible{outline:3px solid #0891b2;outline-offset:2px}.modal-back{z-index:10}.toast{position:fixed;right:20px;bottom:20px;background:#ecfdf5;color:#065f46;border:1px solid #a7f3d0;border-radius:10px;padding:12px 18px;box-shadow:0 8px 25px #0002;z-index:20}@media(max-width:850px){.metrics{grid-template-columns:1fr 1fr}.heading{align-items:flex-start;flex-direction:column}.toolbar{flex-direction:column}.toolbar .input,.toolbar select{max-width:none!important}.grid{grid-template-columns:1fr}.span2{grid-column:span 1}}@media(max-width:650px){table{min-width:0}thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}tbody,tr,td{display:block;width:100%}tbody tr{border-bottom:9px solid #f2f5f8;padding:8px 0}tbody td{border:0;padding:7px 15px;white-space:normal;overflow-wrap:anywhere}tbody td::before{content:attr(data-label);display:block;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;margin-bottom:2px}.empty{padding:28px!important}.tool-actions{width:100%}.tool-actions select{flex:1}}@media(max-width:480px){.metrics{grid-template-columns:1fr}.top-inner,.wrap{padding-left:15px;padding-right:15px}.heading h2{font-size:25px}}
</style></head><body>
<section id="login" class="login"><form id="loginForm" class="login-card"><div class="shield">◆</div><h1>RMA Tracker</h1><p>Enter the company access code to continue.</p><label class="label">Access code<input id="code" class="input" type="password" autocomplete="current-password" required autofocus></label><div id="loginError" class="error"></div><button class="btn btn-primary">Open tracker</button><div class="footer-note">Shared company access</div></form></section>
<main id="app" class="hidden"><header class="top"><div class="top-inner"><div class="brand"><div class="brand-icon">▣</div><div><b>RMA Tracker</b><small>Supplier returns workspace</small></div></div><button id="logout" class="btn lock">↪ Lock</button></div></header><div class="wrap"><div class="heading"><div><div class="eyebrow">Operations overview</div><h2>Return merchandise requests</h2><p>A single view of every supplier return and its current outcome.</p></div><button id="newBtn" class="btn btn-primary">＋ New RMA</button></div><section class="metrics"><div class="metric"><span>Active RMAs</span><strong id="active">0</strong></div><div class="metric"><span>Waiting</span><strong id="waiting">0</strong></div><div class="metric"><span>Returned</span><strong id="returned">0</strong></div><div class="metric"><span>Completed</span><strong id="completed">0</strong></div></section><section class="panel"><div class="toolbar"><input id="search" class="input" type="search" aria-label="Search RMAs" placeholder="Search reference, supplier, employee or notes"><div class="tool-actions"><select id="filter" class="input" aria-label="Filter RMA status"><option>All statuses</option><option>Requested</option><option>Awaiting supplier</option><option>Accepted</option><option>Return in transit</option><option>Resolution pending</option><option>Completed</option><option>Rejected</option></select><button id="refresh" class="btn outline" type="button">↻ Refresh</button></div></div><div class="result-info"><span id="resultCount" aria-live="polite"></span><span id="lastUpdated" aria-live="polite"></span></div><div id="appError" class="error" class="app-error"></div><div class="table-wrap"><table><thead><tr><th>Reference</th><th>Date entered</th><th>Supplier / Disty</th><th>Status</th><th>Processed by</th><th>Resolution</th><th>ERP status</th><th>Action</th></tr></thead><tbody id="rows"></tbody></table></div></section></div></main>
<div id="modalBack" class="modal-back hidden"><div class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle"><h3 id="modalTitle">Create a new RMA</h3><p>Capture the supplier return details. Blank dates can be completed later.</p><form id="rmaForm"><input type="hidden" name="id"><input type="hidden" name="updatedAt"><div class="grid"><label class="label">Reference<input class="input" name="reference" placeholder="Auto-generated if blank"></label><label class="label">Supplier / Disty *<input class="input" name="supplier" required></label><label class="label">Date entered<input class="input" type="date" name="dateEntered"></label><label class="label">Date requested<input class="input" type="date" name="dateRequested"></label><label class="label">Date accepted<input class="input" type="date" name="dateAccepted"></label><label class="label">Date returned<input class="input" type="date" name="dateReturned"></label><label class="label">Processed by *<input class="input" name="processedBy" required></label><label class="label">RMA status<select class="input" name="status"><option>Requested</option><option>Awaiting supplier</option><option>Accepted</option><option>Return in transit</option><option>Resolution pending</option><option>Completed</option><option>Rejected</option></select></label><label class="label">Resolution<input class="input" name="resolution"></label><label class="label">Status in ERP<input class="input" name="erpStatus"></label><label class="label span2">Notes<textarea class="input" name="notes" rows="5"></textarea></label></div><div id="formError" class="error"></div><div class="actions"><button type="button" id="cancel" class="btn outline">Cancel</button><button id="saveBtn" class="btn btn-primary">Save RMA</button></div></form></div></div><div id="toast" class="toast hidden" role="status"></div>
<script nonce="<?php echo htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8'); ?>">
'use strict';
let records = [], previousFocus = null, searchTimer = null, toastTimer = null;
const $ = selector => document.querySelector(selector);
const csrfToken = $('meta[name="csrf-token"]').content;
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const localToday = () => {
    const d = new Date();
    return [d.getFullYear(),String(d.getMonth()+1).padStart(2,'0'),String(d.getDate()).padStart(2,'0')].join('-');
};
async function api(action, options={}) {
    const response = await fetch('?api='+encodeURIComponent(action),{
        credentials:'same-origin',cache:'no-store',...options,
        headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken,...(options.headers||{})}
    });
    let body;
    try {body=await response.json()} catch {throw new Error('Unexpected server response. Please retry.')}
    if(!response.ok) throw Object.assign(new Error(body.error||'Request failed'),{status:response.status});
    return body;
}
async function load() {
    try {
        const response=await api('rmas');
        records=response.records;
        $('#login').classList.add('hidden');
        $('#app').classList.remove('hidden');
        $('#appError').textContent='';
        $('#lastUpdated').textContent='Refreshed '+new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
        render();
    } catch(error) {
        if(error.status===401) {$('#login').classList.remove('hidden');$('#app').classList.add('hidden')}
        else {$('#appError').textContent=error.message;if($('#app').classList.contains('hidden'))$('#loginError').textContent=error.message}
    }
}
function render() {
    const q=$('#search').value.trim().toLowerCase(),filter=$('#filter').value;
    const shown=records.filter(r=>(filter==='All statuses'||r.status===filter) &&
        [r.reference,r.supplier,r.processedBy,r.resolution,r.erpStatus,r.notes].join(' ').toLowerCase().includes(q));
    $('#active').textContent=records.filter(r=>!['Completed','Rejected'].includes(r.status)).length;
    $('#waiting').textContent=records.filter(r=>['Awaiting supplier','Resolution pending'].includes(r.status)).length;
    $('#returned').textContent=records.filter(r=>Boolean(r.dateReturned)).length;
    $('#completed').textContent=records.filter(r=>r.status==='Completed').length;
    $('#resultCount').textContent='Showing '+shown.length+' of '+records.length+' RMAs';
    $('#rows').innerHTML=shown.length?shown.map(r=>
        '<tr><td class="ref" data-label="Reference">'+esc(r.reference)+'</td>'+
        '<td data-label="Date entered">'+esc(r.dateEntered)+'</td>'+
        '<td data-label="Supplier / Disty">'+esc(r.supplier)+'</td>'+
        '<td data-label="Status"><span class="badge '+esc(r.status)+'">'+esc(r.status)+'</span></td>'+
        '<td data-label="Processed by">'+esc(r.processedBy)+'</td>'+
        '<td data-label="Resolution">'+esc(r.resolution)+'</td>'+
        '<td data-label="ERP status">'+esc(r.erpStatus)+'</td>'+
        '<td data-label="Action"><button class="btn outline" type="button" data-id="'+Number(r.id)+'">View / edit</button></td></tr>'
    ).join(''):'<tr><td colspan="8" class="empty">No RMAs match this view.</td></tr>';
}
function openForm(r=null) {
    previousFocus=document.activeElement;
    const form=$('#rmaForm');form.reset();
    for(const element of form.elements)if(element.name)element.value=r?.[element.name]??'';
    if(!r) {
        form.elements.namedItem('dateEntered').value=localToday();
        form.elements.namedItem('status').value='Requested';
        form.elements.namedItem('resolution').value='Pending';
        form.elements.namedItem('erpStatus').value='Not updated';
    }
    $('#modalTitle').textContent=r?'Edit '+r.reference:'Create a new RMA';
    $('#formError').textContent='';
    $('#modalBack').classList.remove('hidden');
    form.elements.namedItem('supplier').focus();
}
function closeForm() {
    $('#modalBack').classList.add('hidden');
    if(previousFocus && typeof previousFocus.focus==='function')previousFocus.focus();
}
function toast(text) {
    $('#toast').textContent=text;$('#toast').classList.remove('hidden');clearTimeout(toastTimer);
    toastTimer=setTimeout(()=>$('#toast').classList.add('hidden'),3500);
}
$('#rows').addEventListener('click',event=>{
    const button=event.target.closest('[data-id]');
    if(!button)return;
    const r=records.find(item=>Number(item.id)===Number(button.dataset.id));
    if(r)openForm(r);
});
$('#loginForm').addEventListener('submit',async event=>{
    event.preventDefault();$('#loginError').textContent='';
    const button=event.currentTarget.querySelector('button');button.disabled=true;
    try{await api('auth',{method:'POST',body:JSON.stringify({code:$('#code').value})});$('#code').value='';await load()}
    catch(error){$('#loginError').textContent=error.message}
    finally{button.disabled=false}
});
$('#logout').addEventListener('click',async()=>{
    try{await api('logout',{method:'POST',body:'{}'});location.reload()}
    catch(error){$('#appError').textContent=error.message}
});
$('#newBtn').addEventListener('click',()=>openForm());
$('#cancel').addEventListener('click',closeForm);
$('#modalBack').addEventListener('click',event=>{if(event.target===$('#modalBack'))closeForm()});
document.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&!$('#modalBack').classList.contains('hidden'))closeForm()
});
$('#refresh').addEventListener('click',load);
$('#search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(render,100)});
$('#filter').addEventListener('change',render);
$('#rmaForm').addEventListener('submit',async event=>{
    event.preventDefault();
    const data=Object.fromEntries(new FormData(event.currentTarget));
    if(data.id)data.id=Number(data.id);else{delete data.id;delete data.updatedAt}
    const save=$('#saveBtn');save.disabled=true;save.textContent='Saving…';$('#formError').textContent='';
    try{
        await api('rmas',{method:data.id?'PUT':'POST',body:JSON.stringify(data)});
        closeForm();await load();toast('RMA saved successfully.');
    }catch(error){$('#formError').textContent=error.message}
    finally{save.disabled=false;save.textContent='Save RMA'}
});
load();
</script></body></html>
