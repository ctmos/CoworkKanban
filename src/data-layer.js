

// ============================================================

// FROZEN SECTION — NIEMALS AENDERN OHNE CHRISTIAN'S FREIGABE

const PIN_HASH = 'MjYxMWNvd29yaw==';

const PIN_SALT = 'cowork';

function verifyPin(input) {

  return btoa(unescape(encodeURIComponent(input + PIN_SALT))) === PIN_HASH;

}

// END FROZEN SECTION

// ============================================================



// ─── UTF-8 BASE64 HELPERS ───────────────────────────────────────────────────
// IMMER diese Funktionen fuer GitHub API base64 content nutzen.
// Nie direkt atob()/btoa() auf Strings mit Nicht-ASCII-Zeichen anwenden.

function decodeBase64Utf8(b64) {
  var binary = atob(b64.replace(/\n/g, ''));
  var bytes = new Uint8Array(binary.length);
  for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

function encodeUtf8Base64(str) {
  var bytes = new TextEncoder().encode(str);
  var binary = '';
  bytes.forEach(function(b) { binary += String.fromCharCode(b); });
  return btoa(binary);
}

// ─── GITHUB HELPERS ──────────────────────────────────────────────────────────

const GH_TOKEN = '';

const GH_DATA_BASE = 'https://api.github.com/repos/ctmos/cowork-data/contents/data';

const GH_DATA_REPO = 'ctmos/cowork-data';

const GH_API_BASE  = 'https://api.github.com';

// ─── WRITE QUEUE (Single-Flight per file) ───────────────────────────────────

var _writeQueue = {};

var _writeRunning = {};

async function queuedWrite(path, writeFn) {

  if (_writeRunning[path]) {

    _writeQueue[path] = writeFn;

    return;

  }

  _writeRunning[path] = true;

  try {

    await writeFn();

  } finally {

    _writeRunning[path] = false;

    if (_writeQueue[path]) {

      var next = _writeQueue[path];

      _writeQueue[path] = null;

      await queuedWrite(path, next);

    }

  }

}

const GH_TOKEN_DEFAULT = '';



// ─── LAYER 4: AUTHORIZED WRITE TARGETS ──────────────────────────────────────

// CRITICAL: All write operations MUST target exactly these repo/path.

// Any deviation throws immediately and NEVER proceeds silently.

// These constants are the single source of truth for write authorization.

const AUTHORIZED_DATA_REPO = 'ctmos/cowork-data';

const AUTHORIZED_DATA_FILE = 'data/tasks.json';

// Runtime assertion — fails fast on misconfiguration before any write

if (GH_DATA_REPO !== AUTHORIZED_DATA_REPO) {

  console.error('[REPO LOCK] CRITICAL: GH_DATA_REPO (' + GH_DATA_REPO +

    ') !== AUTHORIZED_DATA_REPO (' + AUTHORIZED_DATA_REPO + '). Code misconfigured!');

}



// ─── DATA GUARD (v2.0: Schreibschutz Floor + forceSetFloor) ──────────────────

const DataGuard = {

  minTasksFloor: 5,

  get floor() {

    var stored = parseInt(localStorage.getItem('cowork_dg_floor') || '0');

    return Math.max(stored, this.minTasksFloor);

  },



  // setFloor: Upward-only (Math.max). Use ONLY when pushing data upward (count increases).

  // Preserves high-water mark across the session.

  setFloor(count) {

    var newFloor = Math.max(this.floor, count, this.minTasksFloor);

    try { localStorage.setItem('cowork_dg_floor', String(newFloor)); } catch(e) {}

  },



  // forceSetFloor: Resets floor to exact loaded/pushed count.

  // ALWAYS call this after a successful GitHub load — GitHub is the authoritative source.

  // Overrides stale floor values from previous sessions.

  // Also call after a successful push (to track current state including deletions).

  forceSetFloor(count) {

    var newFloor = Math.max(count, this.minTasksFloor);

    var prev = this.floor;

    try { localStorage.setItem('cowork_dg_floor', String(newFloor)); } catch(e) {}

    console.log('[DataGuard] forceSetFloor: ' + prev + ' → ' + newFloor);

  },



  // canPush: Only blocks catastrophic data wipe (< minTasksFloor).

  // HIGH_RISK detection (>20% reduction) is handled by WriteGuard.assessRisk().

  // The floor NEVER blocks a load from GitHub — it only applies to push operations.

  canPush(newCount) {

    if (newCount < this.minTasksFloor) {

      console.error('[DataGuard] BLOCKED: ' + newCount + ' < minTasksFloor ' + this.minTasksFloor);

      return false;

    }

    return true;

  },

  canPushSilent(newCount) {

    return newCount >= this.minTasksFloor;

  }

};



// ─── WRITE GUARD (v1.9: Maximaler Schreibschutz) ─────────────────────────────

const WriteGuard = {

  _pushInProgress: false,

  _pushTimeout: null,

  writeLog: [],



  log(entry) {

    this.writeLog.unshift(Object.assign({ ts: new Date().toISOString() }, entry));

    if (this.writeLog.length > 20) this.writeLog.pop();

    this._updateBadge();

  },



  async canPush(cards) {

    var tasks = Object.values(cards || {});

    var results = {

      dataLoaded: _dataLoaded === true,

      noActivePush: true, // _pushInProgress check moved to syncToGitHub entry

      tokenPresent: !!((_appState.gh_token || GH_TOKEN_DEFAULT || '').trim()),

      noEmptyCards: tasks.every(function(t) { return t.id && t.lane && t.title; }),

      dataGuardOk: DataGuard.canPushSilent(tasks.length),

      schemaOk: validateAllTasks(cards).length === 0

    };

    var failed = Object.keys(results).filter(function(k) { return !results[k]; });

    return { ok: failed.length === 0, results: results, failed: failed };

  },



  _updateBadge() {

    var badge = document.getElementById('wg-badge');

    if (!badge) return;

    var last = this.writeLog[0];

    if (!last) { badge.textContent = '\uD83D\uDEE1\uFE0F'; badge.className = 'wg-badge'; return; }

    if (last.status === 'ok') {

      badge.className = 'wg-badge wg-green'; badge.textContent = '\u2713 OK';

    } else if (last.status === 'pending') {

      badge.className = 'wg-badge wg-yellow'; badge.textContent = '\u2191 Push';

    } else if (last.status === 'blocked') {

      badge.className = 'wg-badge wg-red'; badge.textContent = '\u26A0 Push blockiert';

        } else if (last.status === 'timeout') {

      badge.className = 'wg-badge wg-yellow'; badge.textContent = '\u23F3 Timeout \u2014 retry';

    } else if (last.status === 'high_risk') {

      badge.className = 'wg-badge wg-orange'; badge.textContent = '\u26A0\uFE0F HIGH_RISK';

    } else {

      badge.className = 'wg-badge wg-red'; badge.textContent = '\u2717 Fehler';

    }

    var tip = 'WriteGuard: ' + last.status;

    if (last.reason) tip += ' — ' + last.reason;

    if (last.failed && last.failed.length) tip += '\nBlockiert: ' + last.failed.join(', ');

    tip += '\n' + last.ts;

    badge.title = tip;

  },



  ensureBadge() {

    if (document.getElementById('wg-badge')) return;

    var badge = document.createElement('span');

    badge.id = 'wg-badge';

    badge.className = 'wg-badge';

    badge.textContent = '\uD83D\uDEE1\uFE0F';

    badge.title = 'WriteGuard v2.0 — Schreibschutz aktiv';

    badge.style.cssText = 'position:fixed;bottom:10px;right:10px;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;cursor:default;z-index:9000;background:rgba(80,80,80,0.75);color:#fff;transition:background 0.3s;';

    document.body.appendChild(badge);

    var s = document.createElement('style');

    s.textContent = '.wg-badge.wg-green{background:#22c55e!important}.wg-badge.wg-yellow{background:#eab308!important}.wg-badge.wg-red{background:#ef4444!important}.wg-badge.wg-orange{background:#f97316!important}';

    document.head.appendChild(s);

  },



  // ── LAYER 2: HIGH_RISK Write Assessment ──────────────────────────────────

  // Detects writes that could indicate accidental bulk data manipulation.

  // Does NOT block human UI edits — only logs, warns, and flags for agents.

  // OpenClaw and other automated agents MUST check isHighRisk and abort if true.

  assessRisk(newCards, previousCards) {

    var prevCount = Object.keys(previousCards || {}).length;

    var newCount = Object.keys(newCards || {}).length;

    var risks = [];



    // Risk 1: Task count reduction > 20%

    if (prevCount > 0 && newCount < prevCount * 0.8) {

      var pct = Math.round((1 - newCount / prevCount) * 100);

      risks.push('COUNT_REDUCTION: ' + prevCount + ' → ' + newCount + ' (-' + pct + '%)');

    }



    // Risk 2: More than 5 tasks change lane in a single write

    var laneChanges = 0;

    Object.keys(newCards || {}).forEach(function(id) {

      var prev = (previousCards || {})[id];

      var curr = newCards[id];

      if (prev && curr && prev.lane !== curr.lane) laneChanges++;

    });

    if (laneChanges > 5) {

      risks.push('BULK_LANE_CHANGE: ' + laneChanges + ' tasks changed lane');

    }



    return { risks: risks, isHighRisk: risks.length > 0 };

  }

};



// ─── SCHEMA VALIDATION (Fix 3) ─────────────────────────────────────────────

const VALID_LANES = ['JZ','HE','HD','HB','BA','WB','IK','PA','FI','FA','FR','EV','EX','MA','LO','TB','EK'];

const ID_PATTERN = /^[A-Z]{2}\d{3}$/;

const FORBIDDEN_ID_PATTERNS = [/^[Bb][Bb]\d+$/];



function validateTask(task) {

  const errors = [];

  if (!task.id) errors.push('Missing: id');

  if (!task.title) errors.push('Missing: title');

  if (!task.lane) errors.push('Missing: lane');

  if (task.id && !ID_PATTERN.test(task.id)) errors.push('Invalid ID format: ' + task.id);

  if (task.lane && !VALID_LANES.includes(task.lane)) errors.push('Invalid lane: ' + task.lane);

  for (const pat of FORBIDDEN_ID_PATTERNS) {

    if (task.id && pat.test(task.id)) errors.push('Forbidden ID pattern: ' + task.id);

  }

  return errors;

}



function validateAllTasks(cards) {

  const errors = [];

  const ids = new Set();

  const tasksArr = Object.values(cards || {});

  for (const task of tasksArr) {

    const taskErrors = validateTask(task);

    errors.push(...taskErrors.map(function(e) { return '[' + (task.id || 'NO_ID') + '] ' + e; }));

    if (task.id) {

      if (ids.has(task.id)) errors.push('Duplicate ID: ' + task.id);

      ids.add(task.id);

    }

  }

  return errors;

}



// ─── ERROR DISPLAY (Fix 4) ─────────────────────────────────────────────────

let _validationErrors = [];



function showErrorBanner(message) {

  let banner = document.getElementById('error-banner');

  if (!banner) {

    banner = document.createElement('div');

    banner.id = 'error-banner';

    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#ef4444;color:#fff;padding:10px 16px;font-size:13px;z-index:10000;text-align:center;cursor:pointer;';

    banner.addEventListener('click', function() { banner.style.display = 'none'; });

    document.body.appendChild(banner);

  }

  banner.textContent = message;

  banner.style.display = 'block';

}



function hideErrorBanner() {

  var banner = document.getElementById('error-banner');

  if (banner) banner.style.display = 'none';

}



// ─── DATA LOADED FLAG (Fix 5) ─────────────────────────────────────────────

let _dataLoaded = false;



// ─── SHA CACHE ─────────────────────────────────────────────────────────────

const ghSHA = {

  'data/tasks.json': null,

  'data/patients.json': null,

  'data/projects.json': null,

  'data/autonomy-log.json': null,

  'data/collect.json': null,

  'data/settings.json': null

};



function getGHToken() {

  return _appState.gh_token || localStorage.getItem('cowork_gh_token') || '';

}



// ─── SAFE READ FROM GITHUB (with ETag support) ─────────────────────────────

var _etagCache = {};

async function fetchFromGitHub(path, options) {

  var token = getGHToken();

  if (!token) return null;

  var useEtag = options && options.conditional;

  try {

    var headers = { Authorization: 'token ' + token, Accept: 'application/vnd.github.v3+json' };

    if (useEtag && _etagCache[path]) {

      headers['If-None-Match'] = _etagCache[path];

    }

    var r = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/contents/' + path, {

      headers: headers

    });

    if (r.status === 304) return { notModified: true };

    if (!r.ok) {

      if (r.status === 404) return null;

      console.warn('[fetchFromGitHub] ' + path + ' HTTP ' + r.status);

      return null;

    }

    var etag = r.headers.get('ETag');

    if (etag) _etagCache[path] = etag;

    var d = await r.json();

    if (ghSHA.hasOwnProperty(path)) ghSHA[path] = d.sha;

    // Fallback für Dateien >1MB: GitHub Contents-API gibt encoding:"none" ohne content.
    // download_url hat token-signed URL die oft CORS-preflight triggert (Failed to fetch).
    // Stattdessen git/blobs API nutzen — gleicher Auth-Header wie contents, liefert base64.
    if (!d.content && d.sha) {
      try {
        var blobResp = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/git/blobs/' + d.sha, {
          headers: headers
        });
        if (blobResp.ok) {
          var blobJson = await blobResp.json();
          if (blobJson.content && blobJson.encoding === 'base64') {
            return { content: decodeBase64Utf8(blobJson.content.replace(/\n/g, '')), sha: d.sha };
          }
        } else {
          console.warn('[fetchFromGitHub] blob fallback HTTP ' + blobResp.status + ' for ' + path);
        }
      } catch(blobErr) {
        console.warn('[fetchFromGitHub] blob fallback threw for ' + path, blobErr);
      }
      // Second fallback: download_url (falls blob endpoint aus Auth-Gründen blockiert)
      if (d.download_url) {
        try {
          var rawResp = await fetch(d.download_url);
          if (rawResp.ok) {
            var rawText = await rawResp.text();
            return { content: rawText, sha: d.sha };
          }
        } catch(rawErr) {
          console.warn('[fetchFromGitHub] download_url fallback threw for ' + path, rawErr);
        }
      }
      return null;
    }

    return { content: decodeBase64Utf8(d.content), sha: d.sha };

  } catch(e) {

    console.error('[fetchFromGitHub] ' + path, e);

    return null;

  }

}



// ─── LAYER 1: PRE-WRITE BACKUP ──────────────────────────────────────────────

// Before every cards write, saves current cards as a timestamped backup.

// Backups live in data/backups/ in ctmos/cowork-data.

// Backup failure is NON-FATAL: the main write proceeds even if backup fails.

// Restore: fetch any data/backups/tasks_YYYY-MM-DD_HHMMSS.json via GitHub API.



async function createTasksBackup(cards) {

  try {

    var now = new Date();

    var ts = now.getUTCFullYear()

      + '-' + String(now.getUTCMonth()+1).padStart(2,'0')

      + '-' + String(now.getUTCDate()).padStart(2,'0')

      + '_' + String(now.getUTCHours()).padStart(2,'0')

      + String(now.getUTCMinutes()).padStart(2,'0')

      + String(now.getUTCSeconds()).padStart(2,'0');

    var backupPath = 'data/backups/tasks_' + ts + '.json';

    var cardCount = Object.keys(cards || {}).length;

    var backupContent = JSON.stringify({

      _meta: {

        backupOf: AUTHORIZED_DATA_FILE,

        backedUpAt: now.toISOString(),

        cardCount: cardCount,

        note: 'Auto-backup created by WriteGuard before write'

      },

      cards: cards

    }, null, 2);

    await writeBackupToGitHub(backupPath, backupContent);

    console.log('[Backup] Created:', backupPath, '(' + cardCount + ' cards)');

  } catch(e) {

    // Backup failure is non-fatal — write continues

    console.warn('[Backup] Failed (non-fatal, write will continue):', e.message);

  }

}



async function writeBackupToGitHub(path, content) {

  var token = getGHToken();

  if (!token) throw new Error('No token for backup');

  var encoded = encodeUtf8Base64(content);

  var res = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/contents/' + path, {

    method: 'PUT',

    headers: {

      Authorization: 'token ' + token,

      'Content-Type': 'application/json',

      Accept: 'application/vnd.github.v3+json'

    },

    body: JSON.stringify({

      message: 'backup: pre-write snapshot ' + new Date().toISOString().slice(0,19) + 'Z',

      content: encoded

    })

  });

  if (!res.ok) {

    var errText = '';

    try { errText = await res.text(); } catch(e2) {}

    throw new Error('Backup PUT failed HTTP ' + res.status + ': ' + errText.slice(0, 100));

  }

}



// ─── FIX 1: SAFE WRITE WITH SHA-RETRY ───────────────────────────────────────

// Every write: read current SHA -> apply changes -> write with SHA

// On 409 conflict: retry up to 3 times with fresh SHA



async function safeWriteToGitHub(path, content, message, maxRetries) {

  if (!_dataLoaded) {

    console.warn('[safeWriteToGitHub] Blocked: data not yet loaded. Path: ' + path);

    return;

  }



  // LAYER 4: Repo lock — verify write target matches authorized constants

  if (GH_DATA_REPO !== AUTHORIZED_DATA_REPO) {

    var lockMsg = '[REPO LOCK] BLOCKED: GH_DATA_REPO (' + GH_DATA_REPO +

      ') !== AUTHORIZED (' + AUTHORIZED_DATA_REPO + '). Write aborted.';

    console.error(lockMsg);

    throw new Error(lockMsg);

  }



  var token = getGHToken();

  if (!token) throw new Error('No GitHub token');

  var retries = maxRetries || 3;



  for (var attempt = 0; attempt < retries; attempt++) {

    try {

      // Step 1: Always fetch fresh SHA

      var sha = null;

      var remoteSize = 0;

      var getRes = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/contents/' + path, {

        headers: { Authorization: 'token ' + token, Accept: 'application/vnd.github.v3+json' }

      });

      if (getRes.ok) {

        var getData = await getRes.json();

        sha = getData.sha;

        remoteSize = getData.size || 0;

        if (ghSHA.hasOwnProperty(path)) ghSHA[path] = sha;

      } else if (getRes.status !== 404) {

        throw new Error('SHA fetch failed: HTTP ' + getRes.status);

      }



      // Step 2: Encode content (proper UTF-8)

      var contentSize = new TextEncoder().encode(content).length;

      // Step 2b: SizeGuard — block if new content < 85% of remote (data loss protection)

      if (remoteSize > 500 && contentSize < remoteSize * 0.85) {

        var sgMsg = '[SizeGuard] BLOCKED: ' + path + ' new size ' + contentSize + ' < 85% of remote ' + remoteSize + '. Possible data loss.';

        console.error(sgMsg);

        throw new Error(sgMsg);

      }

      var encoded = encodeUtf8Base64(content);



      // Step 3: Write with verified SHA

      var body = { message: message, content: encoded };

      if (sha) body.sha = sha;

      var putRes = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/contents/' + path, {

        method: 'PUT',

        headers: {

          Authorization: 'token ' + token,

          'Content-Type': 'application/json',

          Accept: 'application/vnd.github.v3+json'

        },

        body: JSON.stringify(body)

      });



      if (putRes.ok) {

        var result = await putRes.json();

        if (result.content && result.content.sha && ghSHA.hasOwnProperty(path)) {

          ghSHA[path] = result.content.sha;

        }

        setSyncStatus('synced');

        return result;

      }



      // Step 4: Handle 409 SHA conflict -- retry with backoff

      if (putRes.status === 409) {

        console.warn('[safeWriteToGitHub] SHA conflict on ' + path + ', retry ' + (attempt + 1) + '/' + retries);

        await new Promise(function(r) { setTimeout(r, 500 * (attempt + 1)); });

        continue;

      }



      // Other errors

      var errBody = '';

      try { errBody = await putRes.text(); } catch(e2) {}

      throw new Error('GitHub push failed: HTTP ' + putRes.status + ' ' + errBody);



    } catch(e) {

      if (attempt === retries - 1) {

        setSyncStatus('error');

        showToast('Sync-Fehler: ' + e.message, true);

        throw e;

      }

      console.warn('[safeWriteToGitHub] attempt ' + (attempt + 1) + ' failed:', e.message);

      await new Promise(function(r) { setTimeout(r, 500 * (attempt + 1)); });

    }

  }

}



// Legacy wrapper -- all writes go through safeWriteToGitHub

async function pushToGitHub(token, path, content, message) {

  return safeWriteToGitHub(path, content, message);

}



// ─── SYNC STATUS ─────────────────────────────────────────────────────────────

function setSyncStatus(status) {

  var dot = document.getElementById('sync-dot');

  if (!dot) return;

  dot.className = status;

  if (status === 'synced') {

    var ssbText = document.getElementById('ssb-text');

    if (ssbText) {

      var now = new Date();

      var hh = String(now.getHours()).padStart(2,'0');

      var mm = String(now.getMinutes()).padStart(2,'0');

      ssbText.textContent = '\uD83D\uDCBE Letzte Sync: ' + hh + ':' + mm;

    }

  }

}



// ─── ACTIVITY LOGGING (Phase 8) ──────────────────────────────────────────────

var _activityQueue = [];

function logActivity(action, entity, entityId, summary) {
  _activityQueue.push({
    id: 'act_' + Date.now(),
    ts: new Date().toISOString(),
    agent: 'lifeos',
    action: action,
    entity: entity,
    entityId: entityId || '',
    summary: summary || ''
  });
  // Live Awareness: Task-Events an JARVIS melden (nur auf app.moser.ai)
  notifyJarvis(action, entity, entityId, summary);
}
window.logActivity = logActivity;

function notifyJarvis(action, entity, entityId, summary) {
  var isApp = location.hostname === 'app.moser.ai';
  if (!isApp) return;
  try {
    fetch('/jarvis/api/log-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent: 'lifeos',
        event_type: entity + '_' + action,
        payload: { text: (summary || '') + ' (' + (entityId || '') + ')', entity: entity, entityId: entityId || '', action: action }
      })
    }).catch(function() {});
  } catch(e) {}
}

async function flushActivityQueue() {
  if (_activityQueue.length === 0) return;
  var batch = _activityQueue.splice(0);
  try {
    var resp = await fetchFromGitHub('data/activity.json');
    if (!resp || !resp.content) return;
    var raw = decodeBase64Utf8(resp.content);
    var data = JSON.parse(raw);
    var entries = data.entries || [];
    batch.forEach(function(e) { entries.unshift(e); });
    if (entries.length > 500) entries = entries.slice(0, 500);
    data.entries = entries;
    var json = JSON.stringify(data, null, 2);
    await safeWriteToGitHub('data/activity.json', json, 'activity: ' + batch.length + ' entries');
  } catch(e) {
    batch.forEach(function(b) { _activityQueue.push(b); });
  }
}

async function loadActivityFeed() {
  try {
    var resp = await fetchFromGitHub('data/activity.json');
    if (!resp || !resp.content) return [];
    var raw = decodeBase64Utf8(resp.content);
    var data = JSON.parse(raw);
    return data.entries || [];
  } catch(e) { return []; }
}
window.loadActivityFeed = loadActivityFeed;

// ─── AUTO SYNC — CARDS (unified through safeWriteToGitHub) ───────────────────

var syncDebounceTimer = null;



function scheduleSyncToGitHub() {

  if (!_dataLoaded) return;

  clearTimeout(syncDebounceTimer);

  setSyncStatus('syncing');

  syncDebounceTimer = setTimeout(syncToGitHub, 10000);

}



async function syncToGitHub() {

  if (!_dataLoaded) return;

  if (WriteGuard._pushInProgress) {

    console.warn('[syncToGitHub] Push already in progress, skipping');

    return;

  }

  var token = getGHToken();

  if (!token) return;



  WriteGuard.ensureBadge();

  WriteGuard.log({ status: 'pending', reason: 'auto-sync' });

  WriteGuard._pushInProgress = true;

  clearTimeout(WriteGuard._pushTimeout);

  WriteGuard._pushTimeout = setTimeout(function() {

    if (WriteGuard._pushInProgress) {

      console.warn('[WriteGuard] Push timeout after 30s — fetch may still be running');

      WriteGuard.log({ status: 'timeout', reason: 'Push timeout 30s' });

      WriteGuard._updateBadge();

      setSyncStatus('error');

    }

  }, 30000);

  setSyncStatus('syncing');



  // Atomic backup for rollback (in-memory)

  var backupCards = JSON.parse(JSON.stringify(_appState.cards || {}));



  try {

    var cards = _appState.cards || {};



    // ── WriteGuard: Pre-push checks ────────────────────────────────────────────

    var guard = await WriteGuard.canPush(cards);

    if (!guard.ok) {

      WriteGuard.log({ status: 'blocked', reason: 'pre-push checks', failed: guard.failed });

      setSyncStatus('error');

      showErrorBanner('\u26D4 Push blockiert: ' + guard.failed.join(', '));

      console.error('[WriteGuard] Push blocked:', guard.failed, guard.results);

      return;

    }



    // ── DataGuard: Floor check ─────────────────────────────────────────────────

    var totalCards = Object.values(cards).length;

    if (!DataGuard.canPush(totalCards)) {

      WriteGuard.log({ status: 'blocked', reason: 'DataGuard floor: ' + totalCards + ' < min ' + DataGuard.minTasksFloor });

      setSyncStatus('error');

      return;

    }



    // ── LAYER 2: HIGH_RISK assessment ─────────────────────────────────────────

    // Does NOT block human UI edits. Logs and warns. Automated agents must check this.

    var riskResult = WriteGuard.assessRisk(cards, backupCards);

    if (riskResult.isHighRisk) {

      var riskMsg = riskResult.risks.join(' | ');

      console.warn('[WriteGuard] HIGH_RISK write detected:', riskMsg);

      WriteGuard.log({ status: 'high_risk', reason: riskMsg, count: totalCards });

      showToast('\u26A0\uFE0F HIGH_RISK: ' + riskMsg, true);

      // Human UI: proceed with write but show warning

      // Automated agents: check WriteGuard.writeLog[0].status === 'high_risk' and abort

    }



    // ── LAYER 1: Pre-write backup to data/backups/ ─────────────────────────────

    await createTasksBackup(cards);



    var savedAt = new Date().toISOString();

    _appState.cards_savedAt = savedAt;

    var jsonStr = JSON.stringify({ _meta: { savedAt: savedAt, updatedBy: 'lifeos' }, cards: cards }, null, 2);

    await safeWriteToGitHub('data/tasks.json', jsonStr, 'sync: auto-save kanban cards');



    // ── LAYER 3: forceSetFloor after successful push (tracks exact current count)

    DataGuard.forceSetFloor(totalCards);

    WriteGuard.log({ status: 'ok', reason: 'auto-sync', count: totalCards });

    _clearLocalBackup(); // Sync succeeded — backup no longer needed
    flushActivityQueue().catch(function(){}); // Phase 8: fire-and-forget

  } catch(e) {

    // Rollback auf Backup-State

    _appState.cards = backupCards;

    WriteGuard.log({ status: 'error', reason: e.message });

    console.error('[syncToGitHub]', e);

    setSyncStatus('error');

    showToast('Sync fehlgeschlagen, Rollback: ' + e.message, true);

  } finally {

    clearTimeout(WriteGuard._pushTimeout);

    WriteGuard._pushInProgress = false;

  }

}



// ─── AUTO SYNC — PATIENTS ────────────────────────────────────────────────────

var patientsDebounceTimer = null;

function scheduleSavePatientsToGitHub() {

  if (!_dataLoaded) return;

  clearTimeout(patientsDebounceTimer);

  patientsDebounceTimer = setTimeout(savePatientsToGitHub, 10000);

}

async function savePatientsToGitHub() {

  await queuedWrite('data/patients.json', async function() {

    try {

      // ─── PATIENT-COUNT-GUARD ─────────────────────────────────────────
      // Verhindert dass ein Auto-Save mit veraltetem State Patienten ueberschreibt.
      // GET remote count → vergleiche mit lokal → bei Verlust: ABBRUCH.
      var localCount = (_appState.patients || []).length;
      try {
        var remoteCheck = await fetchFromGitHub('data/patients.json');
        if (remoteCheck && remoteCheck.content) {
          var remoteDecrypted = await decryptJSON(remoteCheck.content);
          var remotePatients = JSON.parse(remoteDecrypted) || [];
          var remoteCount = remotePatients.length;
          if (localCount < remoteCount) {
            console.error('[PATIENT-COUNT-GUARD] ABBRUCH: Lokal ' + localCount + ' < Remote ' + remoteCount + ' Patienten. Wuerde Daten verlieren.');
            setSyncStatus('error');
            showToast('Patient-Sync blockiert: ' + (remoteCount - localCount) + ' Patient(en) wuerden verloren gehen', true);
            return;
          }
        }
      } catch(guardErr) {
        console.error('[PATIENT-COUNT-GUARD] Pruefung fehlgeschlagen, schreibe trotzdem:', guardErr);
      }
      // ─── END PATIENT-COUNT-GUARD ─────────────────────────────────────

      var pJson = JSON.stringify(_appState.patients, null, 2);

      var pContent = await encryptJSON(pJson);

      await safeWriteToGitHub('data/patients.json', pContent, 'sync: auto-save patients');

    } catch(e) {

      console.error('[savePatientsToGitHub]', e);

      setSyncStatus('error');

      showToast('Patienten-Sync fehlgeschlagen', true);

    }

  });

}

async function syncPatientsToGitHub() { return savePatientsToGitHub(); }



// ─── BIDIRECTIONAL PATIENT SYNC (GET → merge → PUT) ──────────────────────────

async function pullMergePushPatients() {

  // Step 1: GET remote patients

  var remote = await fetchFromGitHub('data/patients.json');

  if (remote) {

    try {

      var decContent = await decryptJSON(remote.content);

      var remotePatients = JSON.parse(decContent) || [];

      var localPatients = _appState.patients || [];

      var localIds = {};

      localPatients.forEach(function(p) { if (p.id) localIds[p.id] = true; });

      // Step 2: Merge — add new patients + merge blog/entries for existing

      var added = 0; var updated = 0;

      var localMap = {};

      localPatients.forEach(function(p) { if (p.id) localMap[p.id] = p; });

      remotePatients.forEach(function(rp) {

        if (!rp.id) return;

        if (!localMap[rp.id]) {

          localPatients.push(rp);

          added++;

        } else {

          var lp = localMap[rp.id];

          // Field-level merge: if remote is newer, take remote fields (except sub-arrays)

          var rTime = rp.updatedAt || '';

          var lTime = lp.updatedAt || '';

          if (rTime > lTime) {

            // Remote is newer — update scalar fields

            ['notes','status','active','aufnahme','austrittsplanung','ampel'].forEach(function(f) {

              if (rp[f] !== undefined) lp[f] = rp[f];

            });

            lp.updatedAt = rp.updatedAt;

            updated++;

          }

          // Always merge blog entries additively (regardless of updatedAt)

          if (rp.blog && rp.blog.length > 0) {

            if (!lp.blog) lp.blog = [];

            var localBlogIds = {};

            lp.blog.forEach(function(b) { localBlogIds[b.id] = true; });

            rp.blog.forEach(function(b) {

              if (b.id && !localBlogIds[b.id]) { lp.blog.push(b); updated++; }

            });

          }

          // Always merge entries additively

          if (rp.entries && rp.entries.length > 0) {

            if (!lp.entries) lp.entries = [];

            var localEntryIds = {};

            lp.entries.forEach(function(e) { localEntryIds[e.id] = true; });

            rp.entries.forEach(function(e) {

              if (e.id && !localEntryIds[e.id]) { lp.entries.push(e); updated++; }

            });

          }

        }

      });

      _appState.patients = localPatients;

      if (added > 0 || updated > 0) {

        console.log('[pullMergePushPatients] Added ' + added + ' patients, merged ' + updated + ' entries from GitHub');

        renderPatients();

      }

    } catch(e) {

      console.error('[pullMergePushPatients] parse error:', e);

    }

  }

  // Step 3: PUT merged result

  await savePatientsToGitHub();

}



// ─── AUTO SYNC — AUTONOMY LOG ─────────────────────────────────────────────────

var autonomyDebounceTimer = null;

function scheduleAutonomyLogToGitHub() {

  if (!_dataLoaded) return;

  clearTimeout(autonomyDebounceTimer);

  autonomyDebounceTimer = setTimeout(saveAutonomyLogToGitHub, 10000);

}

async function saveAutonomyLogToGitHub() {

  try {

    await safeWriteToGitHub('data/autonomy-log.json', JSON.stringify(_appState.autonomy_log || [], null, 2), 'sync: auto-save autonomy log');

  } catch(e) {

    console.error('[saveAutonomyLogToGitHub]', e);

    setSyncStatus('error');

  }

}




// ─── AUTO SYNC — COLLECT ──────────────────────────────────────────────────────

var collectDebounceTimer = null;

function scheduleCollectToGitHub() {

  if (!_dataLoaded) return;

  clearTimeout(collectDebounceTimer);

  collectDebounceTimer = setTimeout(saveCollectToGitHub, 10000);

}

async function saveCollectToGitHub() {

  try {

    await safeWriteToGitHub('data/collect.json', JSON.stringify(_appState.collect || {categories:[],items:[]}, null, 2), 'sync: auto-save collect');

  } catch(e) {

    console.error('[saveCollectToGitHub]', e);

    setSyncStatus('error');

  }

}



// ─── AUTO SYNC — SETTINGS ─────────────────────────────────────────────────────

var settingsDebounceTimer = null;

function scheduleSettingsToGitHub() {

  if (!_dataLoaded) return;

  clearTimeout(settingsDebounceTimer);

  settingsDebounceTimer = setTimeout(saveSettingsToGitHub, 10000);

}

async function saveSettingsToGitHub() {

  try {

    var settingsObj = {

      budget: _appState.budget,

      gh_token: _appState.gh_token,

      collapsed: _appState.collapsed,

      seqs: _appState.seqs

    };

    await safeWriteToGitHub('data/settings.json', JSON.stringify(settingsObj, null, 2), 'sync: auto-save settings');

  } catch(e) {

    console.error('[saveSettingsToGitHub]', e);

    setSyncStatus('error');

  }

}



// ─── FIX 5: LOAD ALL FROM GITHUB (clean startup, no localStorage) ───────────

// ─── SCHEMA MIGRATIONS (LifeOS Substrate v2) ─────────────────────────────────
// Non-breaking: Adds optional fields with sensible defaults.
// Runs on every load (idempotent). Never removes fields.

function migrateTasksV2(cards) {
  if (!cards || typeof cards !== 'object') return cards;
  Object.keys(cards).forEach(function(key) {
    var c = cards[key];
    if (c.assignee === undefined) c.assignee = null;
    if (c.source === undefined) c.source = 'manual';
    if (!c.tags) c.tags = [];
    if (c.context === undefined) c.context = '';
    if (c.linkedPatient === undefined) c.linkedPatient = null;
    if (c.linkedProject === undefined) c.linkedProject = null;
    if (!c.dependsOn) c.dependsOn = [];
    if (c.recurrence === undefined) c.recurrence = null;
    if (!c.notes) c.notes = [];
    if (!c.updatedAt) c.updatedAt = c.createdAt || '';
    if (!c.updatedBy) c.updatedBy = '';
  });
  return cards;
}

function migratePatientsV2(patients) {
  if (!Array.isArray(patients)) return patients;
  patients.forEach(function(p) {
    if (!p.updatedAt) p.updatedAt = '';
    if (!p.updatedBy) p.updatedBy = '';
    if (!p.linkedTasks) p.linkedTasks = [];
    if (!p.diagnoses) p.diagnoses = [];
    if (!p.goals) p.goals = [];
    if (p.wochenplanung === undefined) p.wochenplanung = null;
  });
  return patients;
}

function migrateProjectsV2(projects) {
  if (!Array.isArray(projects)) return projects;
  projects.forEach(function(p) {
    if (p.description === undefined) p.description = '';
    if (!p.updatedAt) p.updatedAt = p.createdAt || '';
    if (!p.updatedBy) p.updatedBy = '';
    if (!p.linkedTasks) p.linkedTasks = [];
    if (p.owner === undefined) p.owner = null;
    if (p.deadline === undefined) p.deadline = null;
    if (!p.tags) p.tags = [];
    if (!p.milestones) p.milestones = [];
  });
  return projects;
}

async function loadFromGitHub() {

  var token = getGHToken();

  if (!token) {

    showToast('Kein GitHub-Token. Daten k\u00f6nnen nicht geladen werden.', true);

    return;

  }

  setSyncStatus('syncing');

  try {

    // Load cards — check for unsaved local changes first

    var tasksRemote = await fetchFromGitHub('data/tasks.json');

    if (tasksRemote) {

      try {

        var remoteData = JSON.parse(tasksRemote.content);

        var loadedCards = remoteData.cards || {};

        var remoteSavedAt = (remoteData._meta && remoteData._meta.savedAt) || '';



        // CHECK LOCAL BACKUP: if user made changes that never synced, keep them

        var localBackup = null;

        try { var raw = localStorage.getItem('cowork_cards_local'); if (raw) localBackup = JSON.parse(raw); } catch(e) {}

        if (localBackup && localBackup.savedAt && remoteSavedAt && new Date(localBackup.savedAt) > new Date(remoteSavedAt)) {

          console.warn('[loadFromGitHub] LOCAL BACKUP IS NEWER than GitHub (' + localBackup.savedAt + ' > ' + remoteSavedAt + ') — keeping local changes and re-syncing');

          _appState.cards = localBackup.cards;

          _appState.cards_savedAt = localBackup.savedAt;

          DataGuard.forceSetFloor(Object.values(_appState.cards).length);

          showToast('Lokale \u00c4nderungen wiederhergestellt \u2014 synchronisiere...', false);

          scheduleSyncToGitHub();

        } else {

          // GitHub is up to date — use remote data

          var validationErrors = validateAllTasks(loadedCards);

          if (validationErrors.length > 0) {

            console.warn('[loadFromGitHub] Validation errors:', validationErrors);

            _validationErrors = validationErrors;

            var cleanCards = {};

            Object.keys(loadedCards).forEach(function(key) {

              var task = loadedCards[key];

              var taskErrors = validateTask(task);

              var hasForbidden = taskErrors.some(function(e) { return e.startsWith('Forbidden'); });

              if (!hasForbidden) { cleanCards[key] = task; }

            });

            _appState.cards = cleanCards;

            if (validationErrors.length <= 5) {

              showToast('Warnung: ' + validationErrors.length + ' Validierungsfehler', true);

            } else {

              showErrorBanner(validationErrors.length + ' Validierungsfehler in Tasks');

            }

          } else {

            _appState.cards = loadedCards;

          }

          DataGuard.forceSetFloor(Object.values(_appState.cards).length);

          _appState.cards_savedAt = remoteSavedAt;

          _clearLocalBackup(); // GitHub is current, no backup needed

        }

      } catch(e) {

        console.error('[loadFromGitHub] tasks parse error:', e);

        showToast('Fehler beim Parsen der Tasks', true);

      }

    }

    // Substrate v2: Migrate tasks
    if (_appState.cards) migrateTasksV2(_appState.cards);

    // Load patients (PIN-derived AES-256-GCM encryption)

    var patientsRemote = await fetchFromGitHub('data/patients.json');

    if (patientsRemote) {

      // Wait for _encKey if PIN-derive-Race triggered loadFromGitHub before key is set
      var _keyWait = 0;
      while (!_encKey && _keyWait < 50) {  // max 5s total
        await new Promise(function(r){ setTimeout(r, 100); });
        _keyWait++;
      }

      try {

        var pContent = await decryptJSON(patientsRemote.content);

        // Integritäts-Check: Decrypt muss gültiges Array liefern, sonst WriteGuard aktivieren
        if (pContent === null || pContent === undefined) {
          console.error('[loadFromGitHub] patients decrypt returned null — blocking writes to prevent data loss');
          window._patientsLoadFailed = true;
          showErrorBanner && showErrorBanner('Patienten konnten nicht entschlüsselt werden — Bitte PIN-Reload (Schreibschutz aktiv)');
        } else {
          var parsed = JSON.parse(pContent);
          if (Array.isArray(parsed) && parsed.length > 0) {
            _appState.patients = parsed;
            window._patientsLoadFailed = false;
          } else if (Array.isArray(parsed) && parsed.length === 0) {
            // Leere Liste vom Server — ungewöhnlich aber legitim wenn wirklich keine Patienten existieren
            // NICHT überschreiben wenn wir vorher schon patients hatten
            if ((_appState.patients || []).length > 0) {
              console.error('[loadFromGitHub] empty patients from server but local had data — keeping local + blocking writes');
              window._patientsLoadFailed = true;
            } else {
              _appState.patients = parsed;
            }
          } else {
            console.error('[loadFromGitHub] unexpected patients format:', typeof parsed);
            window._patientsLoadFailed = true;
          }
        }

      } catch(e) { console.error('[loadFromGitHub] patients parse:', e); window._patientsLoadFailed = true; }

    }

    // Substrate v2: Migrate patients
    if (_appState.patients) migratePatientsV2(_appState.patients);

    // Load autonomy log

    var autonomyRemote = await fetchFromGitHub('data/autonomy-log.json');

    if (autonomyRemote) {

      try { _appState.autonomy_log = JSON.parse(autonomyRemote.content); }

      catch(e) { console.error('[loadFromGitHub] autonomy parse:', e); }

    }



    // Load collect

    var collectRemote = await fetchFromGitHub('data/collect.json');

    if (collectRemote) {

      try { _appState.collect = JSON.parse(collectRemote.content); }

      catch(e) { console.error('[loadFromGitHub] collect parse:', e); }

    }



    // Load projects

    var projectsRemote = await fetchFromGitHub('data/projects.json');

    if (projectsRemote) {

      try { _appState.projects = JSON.parse(projectsRemote.content) || []; }

      catch(e) { console.error('[loadFromGitHub] projects parse:', e); }

    } else {

      if (!_appState.projects) _appState.projects = [];

    }

    // Substrate v2: Migrate projects
    if (_appState.projects) migrateProjectsV2(_appState.projects);

    // Load finances (Substrate v2)
    var financesRemote = await fetchFromGitHub('data/finances.json');
    if (financesRemote) {
      try { _appState.finances = JSON.parse(financesRemote.content); }
      catch(e) { console.error('[loadFromGitHub] finances parse:', e); }
    }

    // Load settings

    var settingsRemote = await fetchFromGitHub('data/settings.json');

    if (settingsRemote) {

      try {

        var s = JSON.parse(settingsRemote.content);

        if (s.budget !== undefined) _appState.budget = s.budget;

        if (s.gh_token) _appState.gh_token = s.gh_token;

        if (s.collapsed) _appState.collapsed = s.collapsed;

        if (s.seqs) {

          Object.keys(s.seqs).forEach(function(k) { _appState.seqs[k] = s.seqs[k]; });

        }

      } catch(e) { console.error('[loadFromGitHub] settings parse:', e); }

    }



    // ─── FILE SIZE MONITORING (warn before GitHub API 1MB limit) ──────────────

    var _sizeChecks = [

      { name: 'collect.json', data: _appState.collect },

      { name: 'patients.json', data: _appState.patients },

      { name: 'tasks.json', data: _appState.cards }

    ];

    _sizeChecks.forEach(function(f) {

      if (!f.data) return;

      var size = new Blob([JSON.stringify(f.data)]).size;

      if (size > 900000) {

        console.error('[SizeMonitor] CRITICAL: ' + f.name + ' = ' + (size/1024).toFixed(0) + 'KB — approaching 1MB GitHub limit!');

        showToast(f.name + ' ist ' + (size/1024).toFixed(0) + 'KB — bald zu gross!', true);

      } else if (size > 700000) {

        console.warn('[SizeMonitor] WARNING: ' + f.name + ' = ' + (size/1024).toFixed(0) + 'KB');

      }

    });

    // FIX 5: Mark data as loaded -- writes now allowed

    _dataLoaded = true;

    setSyncStatus('synced');

// v2.1: Reset badge to OK after successful load

WriteGuard.log({ status: 'ok', reason: 'Data loaded successfully' });

  } catch(e) {

    console.error('[loadFromGitHub] fatal:', e);

    setSyncStatus('error');

    showErrorBanner('Fehler beim Laden. GitHub nicht erreichbar.');

  }

}



// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const LANES = [

  {id:'JZ', name:'Jetzt',       isJetzt:true, color:'#e03131'},

  {id:'HE', name:'Heute',       isHeute:true, color:'#ff6b6b'},

  {id:'BA', name:'Barmelweid',  isBA:true,    color:'#ffa94d'},

  {id:'WB', name:'PSP WB',                    color:'#69db7c'},

  {id:'IK', name:'ImperialKI',                color:'#4a90d9'},

  {id:'PA', name:'Patienten',                 color:'#74c0fc'},

  {id:'FI', name:'Finanzen',                  color:'#ffd43b'},

  {id:'FA', name:'Familie',                   color:'#f783ac'},

  {id:'FR', name:'Freunde',                   color:'#a9e34b'},

  {id:'EV', name:'Events',                    color:'#63e6be'},

  {id:'EX', name:'Explore',                   color:'#ff8787'},

  {id:'MA', name:'MOSER.AI',                  color:'#748ffc'},

  {id:'LO', name:'LifeOS',                    color:'#f472b6'},

  {id:'TB', name:'Tagebuch',                  color:'#868e96'},

  {id:'EK', name:'Einkaufsliste',             color:'#2f9e44'}

];



const BA_TPLS = [

  'Verlaufsbericht',

  'Erstgespr\u00e4ch-Bericht',

  'Austrittsbericht',

  'Verlaufs-/Austrittsbericht',

  'Gruppen-Verlaufsbericht',

  'Arzneimittelabgabe',

  'Dosisanpassung',

  'Notfall-Protokoll'

];



const STATUSES = {

  'offen':      {label:'Offen',      cls:'status-offen'},

  'blockiert':  {label:'Blockiert',  cls:'status-blockiert'},

  'in-arbeit':  {label:'In Arbeit',  cls:'status-in-arbeit'},

  'erledigt':   {label:'Erledigt',   cls:'status-erledigt'}

};



// ─── IN-MEMORY APP STATE (Fix 2: localStorage auf Minimum) ──────────────────

const _appState = {

  cards: {},

  cards_savedAt: null,

  patients: [],

  autonomy_log: null,


  collect: null,

  finances: null,

  projects: [],

  collapsed: {},

  laneOrder: [],

  budget: 100,

  gh_token: '',

  seqs: { JZ:0, HE:0, BA:0, WB:0, IK:0, PA:0, FI:0, FA:0, FR:0, PR:0, EV:0, EM:0, EX:0, MA:0, TB:0, EK:0 }

};



// Fix 2: Clean up stale localStorage keys on boot

(function cleanupLocalStorage() {

  var staleKeys = ['cowork_tasks_floor', 'cowork_backups', 'cowork_state',

                   'cowork_cards', 'cowork_patients', 'cowork_autonomy_log',

                   'cowork_collapsed', 'cowork_budget',

                   'cowork_settings', 'cowork_last_sha'];

  staleKeys.forEach(function(k) { try { localStorage.removeItem(k); } catch(e) {} });

  VALID_LANES.forEach(function(lane) { try { localStorage.removeItem('cowork_seq_' + lane); } catch(e) {} });

})();



// Convenience accessors (maps old key names to _appState)

function ls(key, def) {

  var map = {

    cowork_cards:          function() { return _appState.cards; },

    cowork_cards_savedAt:  function() { return _appState.cards_savedAt; },

    cowork_patients:       function() { return _appState.patients; },

    cowork_autonomy_log:   function() { return _appState.autonomy_log; },

    cowork_collect:        function() { return _appState.collect; },

    cowork_collapsed:      function() { return _appState.collapsed; },

    cowork_budget:         function() { return _appState.budget; },

    cowork_gh_token:       function() { return _appState.gh_token; },

    cowork_settings:       function() { return { gh_token: _appState.gh_token, budget: _appState.budget }; }

  };

  if (key.startsWith('cowork_seq_')) {

    var lane = key.replace('cowork_seq_', '');

    var v = _appState.seqs[lane];

    return v !== undefined ? v : (def !== undefined ? def : 0);

  }

  if (map[key]) {

    var v2 = map[key]();

    return v2 !== null && v2 !== undefined ? v2 : (def !== undefined ? def : null);

  }

  return def !== undefined ? def : null;

}



function lsSet(key, val) {

  var map = {

    cowork_cards:          function(v) { _appState.cards = v; },

    cowork_cards_savedAt:  function(v) { _appState.cards_savedAt = v; },

    cowork_patients:       function(v) {
      // WRITE-GUARD: Kein Push wenn Load fehlgeschlagen ist (Decrypt-Fehler, leere Liste)
      // Verhindert dass leerer lokaler State die GitHub-Version mit 28 Patienten überschreibt
      if (window._patientsLoadFailed === true && (!v || v.length === 0)) {
        console.error('[lsSet:patients] BLOCKED — _patientsLoadFailed=true und leerer Write (Datenverlust-Schutz)');
        showErrorBanner && showErrorBanner('Patienten-Write blockiert: Entschlüsselung lief noch nicht');
        return;
      }
      // Zusätzlich: sha-Shrink-Guard — wenn neue Liste drastisch kleiner als letzte serverseitige
      if (Array.isArray(v) && (_appState.patients||[]).length > 0 && v.length < Math.max(1, Math.floor((_appState.patients||[]).length * 0.5))) {
        console.error('[lsSet:patients] BLOCKED — neue Liste ' + v.length + ' < 50% der aktuellen ' + (_appState.patients||[]).length);
        showErrorBanner && showErrorBanner('Patienten-Schrumpf-Guard: Write blockiert (' + v.length + ' < ' + (_appState.patients||[]).length + ')');
        return;
      }
      _appState.patients = v;
      scheduleSavePatientsToGitHub();
    },

    cowork_autonomy_log:   function(v) { _appState.autonomy_log = v; scheduleAutonomyLogToGitHub(); },

    cowork_collect:        function(v) { _appState.collect = v; scheduleCollectToGitHub(); },

    cowork_collapsed:      function(v) { _appState.collapsed = v; scheduleSettingsToGitHub(); },

    cowork_budget:         function(v) { _appState.budget = v; scheduleSettingsToGitHub(); },

    cowork_gh_token:       function(v) { _appState.gh_token = v; scheduleSettingsToGitHub(); },

    cowork_settings:       function(v) {

      if (v && v.gh_token !== undefined) _appState.gh_token = v.gh_token;

      if (v && v.budget !== undefined) _appState.budget = v.budget;

      scheduleSettingsToGitHub();

    }

  };

  if (key.startsWith('cowork_seq_')) {

    var lane = key.replace('cowork_seq_', '');

    _appState.seqs[lane] = val;

    scheduleSettingsToGitHub();

    return;

  }

  if (map[key]) { map[key](val); }

}



