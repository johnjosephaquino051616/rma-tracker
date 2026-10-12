<?php
declare(strict_types=1);

$configPath = dirname(__DIR__) . '/config.php';
$config = is_file($configPath) ? require $configPath : [];
if (!is_array($config)) json_response(['error' => 'Invalid server configuration.'], 503);
$accessCodeHash = (string)(getenv('RMA_ACCESS_CODE_HASH') ?: ($config['access_code_hash'] ?? ''));
$dataDirectory = (string)(getenv('RMA_DATA_DIR') ?: ($config['data_directory'] ?? dirname(__DIR__) . '/var'));

session_name('rma_tracker_session');
session_set_cookie_params([
    'lifetime' => 604800,
    'path' => '/',
    'secure' => (bool)($config['secure_cookies'] ?? true),
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();


function db(): PDO {
    static $db = null;
    if ($db instanceof PDO) return $db;
    global $dataDirectory;
    $dataDir = $dataDirectory;
    if (!is_dir($dataDir)) mkdir($dataDir, 0700, true);
    $db = new PDO('sqlite:' . $dataDir . '/rma-tracker.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $db->exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
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

if (isset($_GET['api'])) {
    $action = (string)$_GET['api'];
    $input = json_decode(file_get_contents('php://input') ?: '{}', true) ?: [];
    if ($action === 'auth' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($accessCodeHash === '') json_response(['error' => 'The tracker access code has not been configured.'], 503);
        if (!password_verify((string)($input['code'] ?? ''), $accessCodeHash)) json_response(['error' => 'The access code is incorrect.'], 401);
        session_regenerate_id(true); $_SESSION['authorized'] = true; json_response(['ok' => true]);
    }
    if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $_SESSION = []; session_destroy(); json_response(['ok' => true]);
    }
    require_auth();
    if ($action === 'rmas' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $rows = db()->query('SELECT id, reference, date_entered AS dateEntered, date_requested AS dateRequested, supplier, date_accepted AS dateAccepted, date_returned AS dateReturned, processed_by AS processedBy, resolution, erp_status AS erpStatus, status, notes, extra_details AS extraDetails, updated_at AS updatedAt FROM rmas ORDER BY updated_at DESC, id DESC')->fetchAll();
        json_response(['records' => $rows]);
    }
    if ($action === 'rmas' && in_array($_SERVER['REQUEST_METHOD'], ['POST','PUT'], true)) {
        $supplier = trim((string)($input['supplier'] ?? ''));
        $processedBy = trim((string)($input['processedBy'] ?? ''));
        if ($supplier === '' || $processedBy === '') json_response(['error' => 'Supplier and Processed by are required.'], 400);
        $now = gmdate('c');
        $values = [
            trim((string)($input['reference'] ?? '')) ?: 'RMA-' . substr((string)round(microtime(true)*1000), -7),
            (string)($input['dateEntered'] ?? gmdate('Y-m-d')),
            ($input['dateRequested'] ?? '') ?: null, $supplier,
            ($input['dateAccepted'] ?? '') ?: null, ($input['dateReturned'] ?? '') ?: null,
            $processedBy, (string)($input['resolution'] ?? 'Pending'),
            (string)($input['erpStatus'] ?? 'Not updated'), (string)($input['status'] ?? 'Requested'),
            (string)($input['notes'] ?? ''), (string)($input['extraDetails'] ?? '{}'), $now
        ];
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $stmt = db()->prepare('INSERT INTO rmas (reference,date_entered,date_requested,supplier,date_accepted,date_returned,processed_by,resolution,erp_status,status,notes,extra_details,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
            $stmt->execute([...$values, $now]);
            $id = (int)db()->lastInsertId(); $actionText = 'RMA created';
        } else {
            $id = (int)($input['id'] ?? 0);
            if (!$id) json_response(['error' => 'Invalid RMA update.'], 400);
            $stmt = db()->prepare('UPDATE rmas SET reference=?,date_entered=?,date_requested=?,supplier=?,date_accepted=?,date_returned=?,processed_by=?,resolution=?,erp_status=?,status=?,notes=?,extra_details=?,updated_at=? WHERE id=?');
            $stmt->execute([...$values, $id]);
            if ($stmt->rowCount() === 0) json_response(['error' => 'RMA not found.'], 404);
            $actionText = 'Updated — ' . $values[9];
        }
        $history = db()->prepare('INSERT INTO rma_history (rma_id, action, changed_by, created_at) VALUES (?,?,?,?)');
        $history->execute([$id, $actionText, $processedBy, $now]);
        json_response(['ok' => true, 'id' => $id], $_SERVER['REQUEST_METHOD'] === 'POST' ? 201 : 200);
    }
    json_response(['error' => 'Not found'], 404);
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RMA Tracker</title>
<style>
:root{--navy:#07111f;--cyan:#22d3ee;--teal:#0a6b78;--line:#dbe2ea;--muted:#64748b}*{box-sizing:border-box}body{margin:0;font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:#172033;background:#f2f5f8}button,input,select,textarea{font:inherit}.hidden{display:none!important}.login{min-height:100vh;display:grid;place-items:center;background:var(--navy);padding:20px}.login-card{width:min(390px,100%);border:1px solid #334155;background:#0d1b2d;border-radius:18px;padding:28px;box-shadow:0 25px 60px #0007;color:#fff}.shield{display:grid;place-items:center;width:46px;height:46px;border-radius:12px;background:var(--cyan);color:var(--navy);font-size:22px}.login h1{margin:20px 0 4px;font-size:26px}.login p{color:#94a3b8}.label{display:grid;gap:6px;font-weight:600}.input{width:100%;border:1px solid #cbd5e1;border-radius:8px;padding:10px 12px;background:#fff}.login .input{background:#07111f80;color:#fff;border-color:#475569}.btn{border:0;border-radius:8px;padding:10px 16px;font-weight:650;cursor:pointer}.btn-primary{background:var(--teal);color:#fff}.login .btn-primary{background:var(--cyan);color:var(--navy);width:100%;margin-top:18px}.error{color:#e11d48;margin:10px 0}.login .error{color:#fb7185}.top{background:var(--navy);color:#fff;border-bottom:1px solid #1e293b}.top-inner,.wrap{width:min(1500px,100%);margin:auto;padding-left:24px;padding-right:24px}.top-inner{height:70px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:12px}.brand-icon{display:grid;place-items:center;width:38px;height:38px;border-radius:9px;background:var(--cyan);color:var(--navy);font-size:20px}.brand small{display:block;color:#94a3b8}.lock{background:transparent;color:#cbd5e1}.wrap{padding-top:28px;padding-bottom:40px}.heading{display:flex;gap:18px;justify-content:space-between;align-items:end}.eyebrow{color:#0e7490;text-transform:uppercase;letter-spacing:.16em;font-weight:750}.heading h2{font-size:30px;margin:3px 0 0}.heading p{margin:2px 0;color:var(--muted)}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:26px 0 18px}.metric,.panel{background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 3px #0f172a0c}.metric{padding:20px}.metric span{color:var(--muted)}.metric strong{display:block;font-size:30px;margin-top:3px}.toolbar{display:flex;gap:12px;justify-content:space-between;padding:16px;border-bottom:1px solid var(--line)}.toolbar .input:first-child{max-width:430px}.toolbar select{max-width:220px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{padding:13px 16px;border-bottom:1px solid #e8edf2;text-align:left;white-space:nowrap}th{background:#f8fafc;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em}.ref{color:var(--teal);font-weight:750}.badge{display:inline-flex;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-size:12px;font-weight:700}.badge.Completed{background:#d1fae5;color:#047857}.badge.Rejected{background:#ffe4e6;color:#be123c}.outline{background:#fff;border:1px solid #cbd5e1}.empty{text-align:center;color:var(--muted);padding:60px!important}.modal-back{position:fixed;inset:0;background:#020617aa;display:grid;place-items:center;padding:20px}.modal{width:min(760px,100%);max-height:92vh;overflow:auto;background:#fff;border-radius:14px;padding:24px;box-shadow:0 25px 60px #0008}.modal h3{font-size:22px;margin:0}.modal>p{color:var(--muted);margin-top:4px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:20px 0}.span2{grid-column:span 2}.actions{display:flex;justify-content:flex-end;gap:10px}.footer-note{text-align:center;font-size:12px;color:#64748b;margin-top:18px}@media(max-width:850px){.metrics{grid-template-columns:1fr 1fr}.heading{align-items:flex-start;flex-direction:column}.toolbar{flex-direction:column}.toolbar .input,.toolbar select{max-width:none!important}.grid{grid-template-columns:1fr}.span2{grid-column:span 1}}@media(max-width:480px){.metrics{grid-template-columns:1fr}.top-inner,.wrap{padding-left:15px;padding-right:15px}.heading h2{font-size:25px}}
</style></head><body>
<section id="login" class="login"><form id="loginForm" class="login-card"><div class="shield">◆</div><h1>RMA Tracker</h1><p>Enter the company access code to continue.</p><label class="label">Access code<input id="code" class="input" type="password" required autofocus></label><div id="loginError" class="error"></div><button class="btn btn-primary">Open tracker</button><div class="footer-note">Shared company access</div></form></section>
<main id="app" class="hidden"><header class="top"><div class="top-inner"><div class="brand"><div class="brand-icon">▣</div><div><b>RMA Tracker</b><small>Supplier returns workspace</small></div></div><button id="logout" class="btn lock">↪ Lock</button></div></header><div class="wrap"><div class="heading"><div><div class="eyebrow">Operations overview</div><h2>Return merchandise requests</h2><p>A single view of every supplier return and its current outcome.</p></div><button id="newBtn" class="btn btn-primary">＋ New RMA</button></div><section class="metrics"><div class="metric"><span>Active RMAs</span><strong id="active">0</strong></div><div class="metric"><span>Waiting</span><strong id="waiting">0</strong></div><div class="metric"><span>Returned</span><strong id="returned">0</strong></div><div class="metric"><span>Completed</span><strong id="completed">0</strong></div></section><section class="panel"><div class="toolbar"><input id="search" class="input" placeholder="Search reference, supplier, employee or notes"><select id="filter" class="input"><option>All statuses</option><option>Requested</option><option>Awaiting supplier</option><option>Accepted</option><option>Return in transit</option><option>Resolution pending</option><option>Completed</option><option>Rejected</option></select></div><div id="appError" class="error" style="padding:0 16px"></div><div class="table-wrap"><table><thead><tr><th>Reference</th><th>Date entered</th><th>Supplier / Disty</th><th>Status</th><th>Processed by</th><th>Resolution</th><th>ERP status</th><th>Action</th></tr></thead><tbody id="rows"></tbody></table></div></section></div></main>
<div id="modalBack" class="modal-back hidden"><div class="modal"><h3 id="modalTitle">Create a new RMA</h3><p>Capture the supplier return details. Blank dates can be completed later.</p><form id="rmaForm"><input type="hidden" name="id"><div class="grid"><label class="label">Reference<input class="input" name="reference" placeholder="Auto-generated if blank"></label><label class="label">Supplier / Disty *<input class="input" name="supplier" required></label><label class="label">Date entered<input class="input" type="date" name="dateEntered"></label><label class="label">Date requested<input class="input" type="date" name="dateRequested"></label><label class="label">Date accepted<input class="input" type="date" name="dateAccepted"></label><label class="label">Date returned<input class="input" type="date" name="dateReturned"></label><label class="label">Processed by *<input class="input" name="processedBy" required></label><label class="label">RMA status<select class="input" name="status"><option>Requested</option><option>Awaiting supplier</option><option>Accepted</option><option>Return in transit</option><option>Resolution pending</option><option>Completed</option><option>Rejected</option></select></label><label class="label">Resolution<input class="input" name="resolution"></label><label class="label">Status in ERP<input class="input" name="erpStatus"></label><label class="label span2">Notes<textarea class="input" name="notes" rows="5"></textarea></label></div><div id="formError" class="error"></div><div class="actions"><button type="button" id="cancel" class="btn outline">Cancel</button><button class="btn btn-primary">Save RMA</button></div></form></div></div>
<script>
let records=[];const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(action,options={}){const r=await fetch('?api='+action,{headers:{'Content-Type':'application/json'},...options});const j=await r.json();if(!r.ok)throw Object.assign(new Error(j.error||'Request failed'),{status:r.status});return j}
async function load(){try{const j=await api('rmas');records=j.records;$('#login').classList.add('hidden');$('#app').classList.remove('hidden');render()}catch(e){if(e.status===401){$('#login').classList.remove('hidden');$('#app').classList.add('hidden')}else $('#appError').textContent=e.message}}
function render(){const q=$('#search').value.toLowerCase(),f=$('#filter').value;const shown=records.filter(r=>(f==='All statuses'||r.status===f)&&`${r.reference} ${r.supplier} ${r.processedBy} ${r.resolution} ${r.notes}`.toLowerCase().includes(q));$('#active').textContent=records.filter(r=>!['Completed','Rejected'].includes(r.status)).length;$('#waiting').textContent=records.filter(r=>['Awaiting supplier','Resolution pending'].includes(r.status)).length;$('#returned').textContent=records.filter(r=>r.dateReturned).length;$('#completed').textContent=records.filter(r=>r.status==='Completed').length;$('#rows').innerHTML=shown.length?shown.map(r=>`<tr><td class="ref">${esc(r.reference)}</td><td>${esc(r.dateEntered)}</td><td>${esc(r.supplier)}</td><td><span class="badge ${esc(r.status)}">${esc(r.status)}</span></td><td>${esc(r.processedBy)}</td><td>${esc(r.resolution)}</td><td>${esc(r.erpStatus)}</td><td><button class="btn outline" data-id="${r.id}">View / edit</button></td></tr>`).join(''):'<tr><td colspan="8" class="empty">No RMAs match this view.</td></tr>';document.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>openForm(records.find(r=>r.id==b.dataset.id)))}
function openForm(r=null){const f=$('#rmaForm');f.reset();for(const el of f.elements)if(el.name)el.value=r?.[el.name]??'';if(!r){f.dateEntered.value=new Date().toISOString().slice(0,10);f.status.value='Requested';f.resolution.value='Pending';f.erpStatus.value='Not updated'}$('#modalTitle').textContent=r?'Edit '+r.reference:'Create a new RMA';$('#formError').textContent='';$('#modalBack').classList.remove('hidden')}
$('#loginForm').onsubmit=async e=>{e.preventDefault();$('#loginError').textContent='';try{await api('auth',{method:'POST',body:JSON.stringify({code:$('#code').value})});$('#code').value='';await load()}catch(x){$('#loginError').textContent=x.message}};
$('#logout').onclick=async()=>{await api('logout',{method:'POST',body:'{}'});location.reload()};$('#newBtn').onclick=()=>openForm();$('#cancel').onclick=()=>$('#modalBack').classList.add('hidden');$('#search').oninput=render;$('#filter').onchange=render;
$('#rmaForm').onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));if(data.id)data.id=Number(data.id);else delete data.id;try{await api('rmas',{method:data.id?'PUT':'POST',body:JSON.stringify(data)});$('#modalBack').classList.add('hidden');await load()}catch(x){$('#formError').textContent=x.message}};load();
</script></body></html>
