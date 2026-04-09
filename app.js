// ─── ENCRYPTION (AES-256-GCM) ────────────────────────────────────────────────

var _encKey = null;

// importEncKey/generateEncKeyHex removed — key is now derived from PIN via PBKDF2

function bytesToBase64(bytes) {
  var bin = '', len = bytes.length, chunk = 8192;
  for (var i = 0; i < len; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunk, len)));
  }
  return btoa(bin);
}

async function encryptJSON(jsonString) {
  if (!_encKey) return jsonString;
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var encoded = new TextEncoder().encode(jsonString);
  var ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, _encKey, encoded);
  return JSON.stringify({
    encrypted: true,
    version: 1,
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(ciphertext))
  }, null, 2);
}

async function decryptJSON(content) {
  try {
    var obj = typeof content === 'string' ? JSON.parse(content) : content;
    if (!obj.encrypted) return typeof content === 'string' ? content : JSON.stringify(content);
    if (!_encKey) { console.error('[decrypt] Kein Schluessel geladen'); return null; }
    var iv = Uint8Array.from(atob(obj.iv), function(c) { return c.charCodeAt(0); });
    var ciphertext = Uint8Array.from(atob(obj.data), function(c) { return c.charCodeAt(0); });
    var decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, _encKey, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch(e) {
    console.error('[decrypt] Fehler:', e);
    return typeof content === 'string' ? content : null;
  }
}

// _encKey is now derived from PIN at login — no localStorage dependency

// ─── SECURE TOKEN STORAGE (PIN-encrypted) ───────────────────────────────────

async function deriveKeyFromPin(pin, salt) {
  var enc = new TextEncoder();
  var keyMaterial = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: enc.encode(salt || 'cowork-vault'), iterations: 100000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptWithPin(plaintext, pin) {
  var key = await deriveKeyFromPin(pin);
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var encoded = new TextEncoder().encode(plaintext);
  var ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encoded);
  return JSON.stringify({ iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) });
}

async function decryptWithPin(encryptedJson, pin) {
  try {
    var obj = JSON.parse(encryptedJson);
    var key = await deriveKeyFromPin(pin);
    var iv = Uint8Array.from(atob(obj.iv), function(c) { return c.charCodeAt(0); });
    var ciphertext = Uint8Array.from(atob(obj.data), function(c) { return c.charCodeAt(0); });
    var decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch(e) {
    return null;
  }
}

async function storeSecureVault(pin) {
  var vault = JSON.stringify({
    gh_token: _appState.gh_token || localStorage.getItem('cowork_gh_token') || ''
  });
  var encrypted = await encryptWithPin(vault, pin);
  localStorage.setItem('cowork_vault', encrypted);
}

async function unlockSecureVault(pin) {
  var encrypted = localStorage.getItem('cowork_vault');
  if (!encrypted) return false;
  var vault = await decryptWithPin(encrypted, pin);
  if (!vault) return false;
  try {
    var v = JSON.parse(vault);
    if (v.gh_token) { _appState.gh_token = v.gh_token; }
    // enc_key no longer in vault — derived from PIN via PBKDF2
    return true;
  } catch(e) { return false; }
}

// ─── PIN SYSTEM ──────────────────────────────────────────────────────────────

var pinFailures = 0;

var pinLocked = false;

var pinLockUntil = 0;



function hashPin(pin) { return btoa(pin + 'cowork'); }



function showPinError(msg) {

  document.getElementById('pin-error').textContent = msg;

}



function showPinUnlockUI(stored) {

  document.getElementById('pin-title').textContent = 'LifeOS';

  document.getElementById('pin-subtitle').textContent = '';

  document.getElementById('pin-confirm-group').style.display = 'none';

  document.getElementById('pin-btn').innerHTML = '\u00a0';

  document.getElementById('pin-btn').addEventListener('click', function() {

    if (pinLocked && Date.now() < pinLockUntil) {

      var secs = Math.ceil((pinLockUntil - Date.now()) / 1000);

      showPinError('Gesperrt \u2014 ' + secs + 's warten');

      return;

    }

    pinLocked = false;

    var p = document.getElementById('pin-input').value.trim();

    var hash = _appState.pin_hash || stored;

    if (btoa(p + 'cowork') === hash) {

      pinFailures = 0;

      sessionStorage.setItem('cowork_pin_set', 'true');

      sessionStorage.setItem('cowork_pin_val', p);

      // Derive patient encryption key from PIN (deterministic — same PIN = same key)
      deriveKeyFromPin(p, 'lifeos-patient-enc').then(function(k) {
        _encKey = k;
        return unlockSecureVault(p);
      }).then(function(ok) {
        if (!ok && !_appState.gh_token) {
          var saved = localStorage.getItem('cowork_gh_token');
          if (saved) _appState.gh_token = saved;
        }
        unlockApp();
      });

    } else {

      pinFailures++;

      if (pinFailures >= 10) {

        pinLocked = true;

        pinLockUntil = Date.now() + 900000;

        showPinError('10 Fehlversuche \u2014 15 Min gesperrt');

      } else if (pinFailures >= 3) {

        pinLocked = true;

        var delay = Math.pow(2, pinFailures - 3) * 1000;

        pinLockUntil = Date.now() + delay;

        showPinError('Falscher PIN \u2014 ' + (delay/1000) + 's warten');

      } else {

        showPinError('Falscher PIN');

      }

    }

  });

}



function showPinSetupUI() {

  document.getElementById('pin-title').textContent = 'PIN einrichten';

  document.getElementById('pin-subtitle').textContent = 'W\u00e4hle einen PIN (4\u20136 Stellen)';

  document.getElementById('pin-confirm-group').style.display = 'block';

  document.getElementById('pin-btn').textContent = 'PIN einrichten';

  document.getElementById('pin-btn').addEventListener('click', async function() {

    var p1 = document.getElementById('pin-input').value;

    var p2 = document.getElementById('pin-confirm').value;

    if (p1.length < 4) { showPinError('Mindestens 4 Stellen'); return; }

    if (p1 !== p2) { showPinError('PINs stimmen nicht \u00fcberein'); return; }

    var pinHash = btoa(p1 + 'cowork');

    _appState.pin_hash = pinHash;

    sessionStorage.setItem('cowork_pin_set', 'true');

    try {

      var tmpLoaded = _dataLoaded; _dataLoaded = true;

      await safeWriteToGitHub('settings/pin.json', JSON.stringify({ pin_hash: pinHash }, null, 2), 'sync: update PIN');

      _dataLoaded = tmpLoaded;

    } catch(e) { showToast('PIN-Sync fehlgeschlagen', true); }

    unlockApp();

  });

}



if (location.search.includes('resetpin=1')) {

  _appState.pin_hash = null;

  sessionStorage.removeItem('cowork_pin_set');

  history.replaceState(null, '', location.pathname);

}



var DEFAULT_PIN_HASH = btoa('2611' + 'cowork');



async function initPinScreen() {

  document.getElementById('pin-subtitle').textContent = 'Daten werden geladen...';

  document.getElementById('pin-btn').disabled = true;

  var pinHash = DEFAULT_PIN_HASH;

  try {

    var remote = await fetchFromGitHub('settings/pin.json');

    if (remote === null) {

      document.getElementById('pin-subtitle').textContent = 'GitHub nicht erreichbar \u2014 Standard-PIN aktiv';

    } else {

      try {

        var data = JSON.parse(remote.content);

        pinHash = data.pin_hash || DEFAULT_PIN_HASH;

      } catch(e) { pinHash = DEFAULT_PIN_HASH; }

    }

  } catch(e) {

    document.getElementById('pin-subtitle').textContent = 'Fehler: GitHub nicht erreichbar.';

    document.getElementById('pin-btn').disabled = false;

    document.getElementById('pin-input').addEventListener('keydown', function(ev) {

      if (ev.key === 'Enter') document.getElementById('pin-btn').click();

    });

    document.getElementById('pin-input').focus();

    return;

  }

  _appState.pin_hash = pinHash;

  document.getElementById('pin-btn').disabled = false;

  showPinUnlockUI(pinHash);

  document.getElementById('pin-input').addEventListener('keydown', function(ev) {

    if (ev.key === 'Enter') document.getElementById('pin-btn').click();

  });

  document.getElementById('pin-input').focus();

}



function unlockApp() {

  document.getElementById('pin-screen').style.display = 'none';

  document.getElementById('app').style.display = 'block';

  initApp();

}



// ─── APP DATA ─────────────────────────────────────────────────────────────────

function getCards()    { return ls('cowork_cards', {}); }

function saveCards(c) {

  lsSet('cowork_cards', c);

  var ts = new Date().toISOString();

  lsSet('cowork_cards_savedAt', ts);

  // LOCAL BACKUP: survive page reload if sync fails

  try { localStorage.setItem('cowork_cards_local', JSON.stringify({cards: c, savedAt: ts})); } catch(e) {}

  scheduleSyncToGitHub();

}

function _clearLocalBackup() {

  try { localStorage.removeItem('cowork_cards_local'); } catch(e) {}

}

function getPatients() { return ls('cowork_patients', []); }

function savePatients(p, touchedId) {
  var id = touchedId || (typeof _currentPatId !== 'undefined' ? _currentPatId : null);
  if (id) {
    var pat = p.find(function(x) { return x.id === id; });
    if (pat) pat.updatedAt = new Date().toISOString();
  }
  lsSet('cowork_patients', p);
}

function getALLog()    { return ls('cowork_autonomy_log', null); }

function saveALLog(l)  { lsSet('cowork_autonomy_log', l); }



function nextCardId(laneId) {

  var key = 'cowork_seq_' + laneId;

  var n = (ls(key, 0)) + 1;

  lsSet(key, n);

  return laneId + String(n).padStart(3, '0');

}



// ─── TABS ─────────────────────────────────────────────────────────────────────

var currentTab = 'kanban';

// Hash-Aliases fuer alte URLs (backward compat nach Navbar-Umstrukturierung 08.04.2026)
var TAB_ALIAS = {
  'patienten': 'kba',
  'money':     'life',
  'rag':       'system',
  'on':        'system'
};

function resolveTab(id) {
  if (TAB_ALIAS[id]) return TAB_ALIAS[id];
  return id;
}

function switchTab(id) {

  id = resolveTab(id);

  currentTab = id;

  if (location.hash !== '#' + id) location.hash = id;

  document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.toggle('active', b.dataset.tab === id); });

  document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.toggle('active', c.id === 'tab-' + id); });

  if (id === 'heute')      renderHeute();
  if (id === 'kanban')     { renderHannahSummary(); renderKanban(); }
  if (id === 'kba')        renderPatients();
  if (id === 'projekte')   showProjectsTab();
  if (id === 'life')       renderMoneyTab();
  if (id === 'imperialki') showImperialKITab();
  if (id === 'system')     {
    showSystemTab();
    try { showRAGTab(); } catch (e) { console.warn('showRAGTab failed:', e); setSystemAlert('system-rag-dropdown', true); }
    try { showONTab(); }  catch (e) { console.warn('showONTab failed:',  e); setSystemAlert('system-on-dropdown',  true); }
    initSettings();
    updateSystemAlerts();
  }

}

// ─── System Alert API ────────────────────────────────────────
// Setzt das rote Blitz-Icon im Dropdown-Header + aktualisiert Navbar-Alert
function setSystemAlert(dropdownId, hasProblem) {
  var el = document.getElementById(dropdownId);
  if (!el) return;
  el.classList.toggle('has-alert', !!hasProblem);
  var alertIcon = el.querySelector(':scope > summary > .sys-alert');
  if (alertIcon) alertIcon.hidden = !hasProblem;
  updateSystemAlerts();
}
window.setSystemAlert = setSystemAlert;

function updateSystemAlerts() {
  var sysTab = document.getElementById('tab-system');
  if (!sysTab) return;
  var hasAny = sysTab.querySelector('.sys-dropdown.has-alert') !== null;
  var navAlert = document.getElementById('nav-system-alert');
  if (navAlert) navAlert.hidden = !hasAny;
}
window.updateSystemAlerts = updateSystemAlerts;



// ─── HEUTE / STATUS ───────────────────────────────────────────────────────────

function moveToToday(cardId) {

  var cards = getCards();

  if (!cards[cardId]) return;

  var card = cards[cardId];

  if (!card.originalLane) card.originalLane = card.lane || 'BA';

  card.lane = 'HE';

  card.todayFlag = true;

  saveCards(cards);

  renderStatusTab();

  renderKanban();

}



function moveFromToday(cardId) {

  var cards = getCards();

  if (!cards[cardId]) return;

  var card = cards[cardId];

  card.lane = card.originalLane || 'BA';

  card.todayFlag = false;

  delete card.originalLane;

  saveCards(cards);

  renderStatusTab();

  renderKanban();

}



// ─── CALENDAR ────────────────────────────────────────────────────────────────

async function loadCalendarEvents() {

  if (!window._calEvents) window._calEvents = { events: [] };

  var token = getGHToken();

  if (!token) return;

  try {

    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/calendar.json',

      { headers: { Authorization: 'token ' + token } });

    if (!r.ok) return;

    var d = await r.json();

    window._calEvents = JSON.parse(decodeBase64Utf8(d.content));

  } catch(e) { console.warn('calendar load failed', e); }

}



// ─── HANNAH SUMMARY ──────────────────────────────────────────────────────────

async function loadHannahSummary() {

  var token = getGHToken();

  if (!token) return;

  try {

    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/hannah_summary.json',

      { headers: { Authorization: 'token ' + token } });

    if (!r.ok) return;

    var d = await r.json();

    window._hannahSummary = JSON.parse(decodeBase64Utf8(d.content));

    renderHannahSummary();

  } catch(e) { console.warn('hannah summary load failed', e); }

}



function getHannahCollapsed() {

  try { return JSON.parse(localStorage.getItem('lifeos_hannah_collapsed') || '{}'); } catch(e) { return {}; }

}



function toggleHannahBox(which) {

  // Sync-Behavior: beide Boxen immer im selben Zustand
  var allBoxes = document.querySelectorAll('.hannah-box');

  if (!allBoxes.length) return;

  // Zielzustand aus der geklickten Box ableiten (toggle)
  var target = document.querySelector('.hannah-box[data-hannah="' + which + '"]');

  if (!target) return;

  var shouldCollapse = !target.classList.contains('collapsed');

  allBoxes.forEach(function(b) {

    if (shouldCollapse) b.classList.add('collapsed');
    else b.classList.remove('collapsed');

  });

  var state = { today: shouldCollapse, week: shouldCollapse };

  try { localStorage.setItem('lifeos_hannah_collapsed', JSON.stringify(state)); } catch(e) {}

}



function renderHannahSummary() {

  var el = document.getElementById('hannah-summary');

  if (!el) return;

  var s = window._hannahSummary;

  if (!s || !s.today || !s.week) { el.innerHTML = ''; return; }

  var genAt = '';

  if (s.generatedAt) {

    try {

      genAt = new Date(s.generatedAt).toLocaleString('de-CH', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});

    } catch(e) {}

  }

  // Default: beide collapsed, wenn noch nie gesetzt
  // Sync-Behavior: beide Boxen immer im selben Zustand (nutze 'today' als Source of Truth)

  var state = getHannahCollapsed();

  if (state.today === undefined) state.today = true;

  // week folgt immer today (Sync-Behavior)
  state.week = state.today;

  function box(which, label, data) {

    var cls = 'hannah-box' + (state[which] ? ' collapsed' : '');

    return '<div class="' + cls + '" data-hannah="' + which + '">'

      + '<div class="hannah-box-header" onclick="toggleHannahBox(\'' + which + '\')">'

      + '<span class="hannah-label">' + label + '</span>'

      + '<span class="hannah-count">' + (data.count||0) + ' Termine</span>'

      + '<span class="hannah-chevron">\u25be</span>'

      + '</div>'

      + '<div class="hannah-text">' + esc(data.text||'') + '</div>'

      + '</div>';

  }

  var html = '<div class="hannah-grid">'

    + box('today', 'Hannah heute',       s.today)

    + box('week',  'Hannah diese Woche', s.week)

    + '</div>';

  if (genAt) html += '<div class="hannah-footer">Aktualisiert: ' + genAt + '</div>';

  el.innerHTML = html;

}



var CAL_COLORS = { christian: '#a78bfa', hannah: '#f9a8d4', kikurs: '#fb923c' };

var CAL_NAMES  = { christian: 'Christian', hannah: 'Hannah', kikurs: 'KI Kurs' };



function getEventsForDay(isoDate) {

  if (!window._calEvents) return [];

  return (window._calEvents.events || [])

    .filter(function(e) { var d = e.allDay ? e.start : e.start.substring(0,10); return d === isoDate; })

    .sort(function(a,b) { return (a.start||'').localeCompare(b.start||''); });

}



function formatEventTime(e) {

  if (e.allDay) return '\uD83D\uDCC5';

  return new Date(e.start).toLocaleTimeString('de-CH', {hour:'2-digit',minute:'2-digit'});

}



function renderCalEventChip(e) {

  var color = CAL_COLORS[e.calendar] || '#888';

  var name  = CAL_NAMES[e.calendar]  || e.calendar;

  var time  = formatEventTime(e);

  return '<div style="display:flex;align-items:center;gap:6px;padding:4px 8px;margin:2px 0;border-radius:6px;background:rgba(0,0,0,0.03);border-left:3px solid '+color+';font-size:12px;">'

    +'<span style="color:'+color+';font-size:10px;min-width:32px">'+time+'</span>'

    +'<span style="color:var(--text);flex:1">'+esc(e.summary||'')+'</span>'

    +'<span style="color:'+color+';font-size:9px;opacity:0.7">'+name+'</span></div>';

}



function renderStatusTab() {

  var cards = getCards();

  var events = (window._calEvents && window._calEvents.events) ? window._calEvents.events : [];

  var now = new Date();

  var todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  var todayISO = now.toISOString().split('T')[0];



  var heuteCards = Object.values(cards).filter(function(c) { return !c.archived && (c.lane === 'JZ' || c.todayFlag || c.lane === 'HE' || c.deadline === todayISO); });

  heuteCards.sort(function(a, b) { var aJZ = a.lane === 'JZ' ? 0 : 1; var bJZ = b.lane === 'JZ' ? 0 : 1; return aJZ - bJZ; });

  var heuteList = document.getElementById('heute-list');

  if (heuteList) {

    if (heuteCards.length === 0) {

      heuteList.innerHTML = '<div class="empty-state">Keine heutigen Items</div>';

    } else {

      heuteList.innerHTML = heuteCards.map(function(c) {

        var orig = c.originalLane ? '<div class="card-meta">Von: '+esc(c.originalLane)+'</div>' : '';

        return '<div class="status-card"><div style="flex:1;min-width:0;"><div style="display:flex;align-items:center;gap:6px;"><span class="card-prefix">'+esc(c.id||'')+'</span><span class="card-title">'+esc(c.title||'')+'</span></div>'+orig+'</div><button class="today-btn is-today" onclick="moveFromToday(\''+esc(c.id)+'\')" title="Zur\u00fcck">\u21a9</button></div>';

      }).join('');

    }

    var todayCalEvs = getEventsForDay(todayISO);

    if (todayCalEvs.length > 0) {

      var calHtml = '<div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border)"><div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.5px">\uD83D\uDCC5 Kalender heute</div>';

      calHtml += todayCalEvs.map(renderCalEventChip).join('');

      if (window._calEvents && window._calEvents.syncedAt) {

        calHtml += '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;opacity:0.6">Sync: vor '+Math.round((Date.now()-new Date(window._calEvents.syncedAt))/60000)+' Min.</div>';

      }

      calHtml += '</div>';

      heuteList.innerHTML += calHtml;

    }

  }



  var in7 = new Date(todayStart.getTime() + 7*86400000);

  var weekCards = Object.values(cards).filter(function(c) { if (c.archived || !c.deadline) return false; var d=new Date(c.deadline); return d>=todayStart && d<in7; });

  function dayLabel(dateStr) { var d=new Date(dateStr); var diff=Math.floor((d-todayStart)/86400000); if(diff===0) return 'Heute'; if(diff===1) return 'Morgen'; if(diff===2) return '\u00dcbermorgen'; return 'Diese Woche'; }

  var grouped = {};

  weekCards.forEach(function(c) { var lbl=dayLabel(c.deadline); if(!grouped[lbl]) grouped[lbl]=[]; grouped[lbl].push(c); });

  events.filter(function(e) { if(!e.start) return false; var d=new Date(e.start); return d>=todayStart && d<in7; }).forEach(function(e) { var lbl=dayLabel(e.start); if(!grouped[lbl]) grouped[lbl]=[]; grouped[lbl].push(Object.assign({},e,{_isEvent:true})); });



  var order = ['Heute','Morgen','\u00dcbermorgen','Diese Woche'];

  var wocheList = document.getElementById('woche-list');

  if (wocheList) {

    if (Object.keys(grouped).length === 0) {

      wocheList.innerHTML = '<div class="empty-state">Keine F\u00e4lligkeiten diese Woche</div>';

    } else {

      var html = '';

      order.forEach(function(lbl) {

        if (!grouped[lbl]) return;

        html += '<div class="day-group-header">'+lbl+'</div>';

        grouped[lbl].forEach(function(c) {

          if (c._isEvent) {

            html += '<div class="status-card"><div style="flex:1;min-width:0;"><div class="card-title">\ud83d\udcc5 '+esc(c.title||c.summary||'')+'</div></div></div>';

          } else {

            var isHE=c.todayFlag||c.lane==='HE'; var cId=esc(c.id||'');

            html += '<div class="status-card"><div style="flex:1;min-width:0;"><div style="display:flex;align-items:center;gap:6px;"><span class="card-prefix">'+cId+'</span><span class="card-title">'+esc(c.title||'')+'</span></div></div><button class="today-btn'+(isHE?' is-today':'')+'" onclick="'+(isHE?"moveFromToday('"+cId+"')":"moveToToday('"+cId+"')")+'" title="'+(isHE?'Zur\u00fcck':'Heute')+'">'+(isHE?'\u21a9':'\u2192')+'</button></div>';

          }

        });

        var _isoMap={'Heute':todayISO,'Morgen':new Date(todayStart.getTime()+86400000).toISOString().split('T')[0],'\u00dcbermorgen':new Date(todayStart.getTime()+2*86400000).toISOString().split('T')[0]};

        if(_isoMap[lbl]) getEventsForDay(_isoMap[lbl]).forEach(function(e){html+=renderCalEventChip(e);});

      });

      wocheList.innerHTML = html;

    }

  }



  var weitereCards = Object.values(cards).filter(function(c) { if(c.archived) return false; if(c.todayFlag||c.lane==='HE'||c.lane==='JZ') return false; if(c.deadline){return new Date(c.deadline)>=in7;} return c.priority==='hoch'||c.priority==='high'; });

  var weitereList = document.getElementById('weitere-list');

  if (weitereList) {

    if (weitereCards.length === 0) {

      weitereList.innerHTML = '<div class="empty-state">Keine weiteren Pl\u00e4ne</div>';

    } else {

      weitereList.innerHTML = weitereCards.map(function(c) {

        var isHE=c.todayFlag||c.lane==='HE'; var cId=esc(c.id||'');

        var dl=c.deadline?'<div class="card-meta">'+esc(c.deadline)+'</div>':'';

        return '<div class="status-card"><div style="flex:1;min-width:0;"><div style="display:flex;align-items:center;gap:6px;"><span class="card-prefix">'+cId+'</span><span class="card-title">'+esc(c.title||'')+'</span></div>'+dl+'</div><button class="today-btn'+(isHE?' is-today':'')+'" onclick="'+(isHE?"moveFromToday('"+cId+"')":"moveToToday('"+cId+"')")+'" title="'+(isHE?'Zur\u00fcck':'Heute')+'">'+(isHE?'\u21a9':'\u2192')+'</button></div>';

      }).join('');

    }

  }

}



function renderHeute() { renderStatusTab(); }

function getWeekStart() { var d=new Date(); var day=d.getDay(); d.setDate(d.getDate()-(day===0?6:day-1)); d.setHours(0,0,0,0); return d; }

function hexToRgb(hex) { return parseInt(hex.slice(1,3),16)+','+parseInt(hex.slice(3,5),16)+','+parseInt(hex.slice(5,7),16); }

function fmtDateShort(dateStr) { if(!dateStr) return ''; var p=String(dateStr).split('T')[0].split('-'); return p.length===3?p[2]+'.'+p[1]+'.'+p[0]:dateStr; }



function renderCardItem(card, laneColor) {

  var statusCls=(STATUSES[card.status]&&STATUSES[card.status].cls)||'status-offen';

  var dlBadge=card.deadline?'<span class="card-date-dl">\uD83D\uDCC5 '+fmtDateShort(card.deadline)+'</span>':'';

  var crBadge=card.createdAt?'<span class="card-date-cr">'+fmtDateShort(card.createdAt)+'</span>':'';

  var datesHtml=(dlBadge||crBadge)?'<div class="card-dates">'+dlBadge+crBadge+'</div>':'';

  var hasDesc=!!(card.desc&&card.desc.trim());

  var cardId=esc(card.id);

  var descExpanded=hasDesc&&(descExpandState[cardId]||false);

  var descToggle=hasDesc?'<span class="card-desc-toggle" onclick="event.stopPropagation();toggleDescExpand(\''+cardId+'\')">(...)</span>':'';

  var descBox=descExpanded?'<div class="card-desc-box">'+esc(card.desc)+'</div>':'';

  var isHE=card.todayFlag||card.lane==='HE';

  // Card-Hintergrund: nur Status-Farbe mit Transparenz (Feature v6.43)
  var statusColors={offen:'156,163,175',blockiert:'239,68,68','in-arbeit':'245,158,11',erledigt:'34,197,94'};
  var stRgb=statusColors[card.status]||statusColors.offen;
  var bgStyle='background:rgba('+stRgb+',0.12);';

  return '<div class="card-item card-status-'+esc(card.status||'offen')+'" draggable="true" data-id="'+cardId+'" style="position:relative;'+bgStyle+'"><div style="flex:1;min-width:0;"><div style="display:flex;align-items:center;gap:10px;"><span class="card-prefix">'+esc(card.id)+'</span><span class="card-title">'+esc(card.title||'(kein Titel)')+'</span>'+descToggle+'<span class="status-dot '+statusCls+'"></span></div>'+datesHtml+descBox+'</div><button class="kanban-today-btn'+(isHE?' is-today':'')+'" onclick="event.stopPropagation();'+(isHE?"moveFromToday('"+cardId+"')":"moveToToday('"+cardId+"')")+'" title="'+(isHE?'Zur\u00fcck':'Heute')+'">'+(isHE?'\u21a9':'\u2192')+'</button></div>';

}



// ─── KANBAN ───────────────────────────────────────────────────────────────────

var doneExpandState = {};

var descExpandState = {};

function toggleDescExpand(cardId) { descExpandState[cardId]=!descExpandState[cardId]; renderKanban(); }

function toggleDoneArchive(laneId) { doneExpandState[laneId]=!doneExpandState[laneId]; renderKanban(); }

var trashExpanded = false;

function toggleTrash() { trashExpanded = !trashExpanded; renderKanban(); }

function restoreCard(cardId) { var cards=getCards(); if(cards[cardId]){cards[cardId].archived=false; saveCards(cards); showToast(cardId+' wiederhergestellt'); renderKanban(); if(currentTab==='heute')renderHeute();} }

function permanentDeleteCard(cardId) { confirmAction('Endgültig löschen?','Diese Karte wird UNWIDERRUFLICH gelöscht.',function(){var cards=getCards(); delete cards[cardId]; saveCards(cards); showToast(cardId+' gelöscht'); renderKanban();}); }

function toggleKanbanView(){var g=document.getElementById('kanban-grid');var t=document.getElementById('tab-kanban');var btn=document.getElementById('kanban-view-toggle');if(g.classList.contains('kanban-board')){g.classList.remove('kanban-board');t.classList.remove('board-active');btn.textContent='Board-Ansicht';localStorage.setItem('kanban_view','grid');}else{g.classList.add('kanban-board');t.classList.add('board-active');btn.textContent='Grid-Ansicht';localStorage.setItem('kanban_view','board');}}

(function(){if(localStorage.getItem('kanban_view')==='board'){var g=document.getElementById('kanban-grid');var t=document.getElementById('tab-kanban');if(g)g.classList.add('kanban-board');if(t)t.classList.add('board-active');var b=document.getElementById('kanban-view-toggle');if(b)b.textContent='Grid-Ansicht';}})();

// Horizontal wheel scroll for kanban board view
document.getElementById('kanban-grid').addEventListener('wheel',function(e){if(!this.classList.contains('kanban-board'))return;if(Math.abs(e.deltaY)>Math.abs(e.deltaX)){e.preventDefault();this.scrollLeft+=e.deltaY;}},{passive:false});



function getLaneOrder() {
  try {
    var stored = JSON.parse(localStorage.getItem('lifeos_lane_order') || 'null');
    if (stored && Array.isArray(stored)) return stored;
  } catch(e) {}
  return null;
}

function saveLaneOrder(order) {
  try { localStorage.setItem('lifeos_lane_order', JSON.stringify(order)); } catch(e) {}
  _appState.laneOrder = order;
}

function getOrderedLanes() {
  var order = getLaneOrder();
  if (!order || !order.length) return LANES.slice();
  var byId = {};
  LANES.forEach(function(l) { byId[l.id] = l; });
  var ordered = [];
  order.forEach(function(id) { if (byId[id]) { ordered.push(byId[id]); delete byId[id]; } });
  // Append any new lanes not yet in order (e.g., after adding a new lane)
  LANES.forEach(function(l) { if (byId[l.id]) ordered.push(l); });
  return ordered;
}

function renderKanban() {

  var cards=getCards(); var grid=document.getElementById('kanban-grid'); var collapsed=_appState.collapsed;

  var todayISO=new Date().toISOString().split('T')[0];

  grid.innerHTML = getOrderedLanes().map(function(lane) {

    var all=Object.values(cards).filter(function(c){return !c.archived&&(lane.isHeute?(c.todayFlag||c.deadline===todayISO||c.lane==='HE'):c.lane===lane.id);});

    var active=all.filter(function(c){return c.status!=='erledigt';}).sort(function(a,b){return(a.order-b.order)||a.id.localeCompare(b.id);});

    var done=all.filter(function(c){return c.status==='erledigt';}).sort(function(a,b){return(a.order-b.order)||a.id.localeCompare(b.id);});

    var isCol=collapsed[lane.id]; var doneExp=doneExpandState[lane.id]||false;

    var ch=active.map(function(c){return renderCardItem(c,lane.color);}).join('')||'<div class="empty-state" style="padding:16px 8px;font-size:12px">Keine Karten</div>';

    var dh=done.length>0?'<button class="done-archive-toggle" onclick="event.stopPropagation();toggleDoneArchive(\''+lane.id+'\')">Erledigt ('+done.length+') '+(doneExp?'\u25b4':'\u25be')+'</button>'+(doneExp?'<div class="done-archive-list">'+done.map(function(c){return renderCardItem(c,lane.color);}).join('')+'</div>':''):'';

    var hasCards=active.length>0;

    return '<div class="lane'+(isCol?' lane-collapsed':'')+(hasCards?' lane-has-cards':'')+'" id="lane-'+lane.id+'" data-lane="'+lane.id+'"><div class="lane-header" onclick="toggleCollapse(\''+lane.id+'\')" style="cursor:pointer"><span class="lane-drag-handle" draggable="true" onclick="event.stopPropagation()" title="Lane verschieben">\u22ee\u22ee</span><span class="lane-title">'+esc(lane.name)+'</span><span class="lane-count">'+active.length+'</span><button class="btn-add-card" onclick="event.stopPropagation();openCardModal(null,\''+lane.id+'\')">+ Karte</button><button class="lane-collapse" onclick="event.stopPropagation();toggleCollapse(\''+lane.id+'\')">'+(isCol?'\u25b6':'\u25bc')+'</button></div><div class="lane-body'+(isCol?' collapsed':'')+'" id="lb-'+lane.id+'">'+ch+dh+'</div></div>';

  }).join('');

  // Remove old trash section before re-render

  var oldTrashEl = document.querySelector('.trash-section');

  if (oldTrashEl) oldTrashEl.remove();

  // Papierkorb (Trash) section

  var archivedCards = Object.values(cards).filter(function(c){ return c.archived; }).sort(function(a,b){ return (b.order||0) - (a.order||0); });

  if (archivedCards.length > 0) {

    var trashHtml = '<div class="trash-section">';

    trashHtml += '<div class="trash-header" onclick="toggleTrash()">';

    trashHtml += '<span class="trash-icon">🗑️</span> Papierkorb <span class="lane-count">' + archivedCards.length + '</span>';

    trashHtml += '<span class="trash-chevron">' + (trashExpanded ? '▴' : '▾') + '</span></div>';

    if (trashExpanded) {

      trashHtml += '<div class="trash-body">';

      archivedCards.forEach(function(c) {

        trashHtml += '<div class="trash-card"><span class="trash-card-id">' + esc(c.id) + '</span>';

        trashHtml += '<span class="trash-card-title">' + esc(c.title || '(kein Titel)') + '</span>';

        trashHtml += '<span class="trash-card-lane">' + esc(c.lane || '?') + '</span>';

        trashHtml += '<button class="btn-restore" onclick="event.stopPropagation();restoreCard(\'' + esc(c.id) + '\')">↩ Wiederherstellen</button>';

        trashHtml += '<button class="btn-perm-delete" onclick="event.stopPropagation();permanentDeleteCard(\'' + esc(c.id) + '\')">✕</button>';

        trashHtml += '</div>';

      });

      trashHtml += '</div>';

    }

    trashHtml += '</div>';

    grid.insertAdjacentHTML('afterend', trashHtml);

  }

  grid.querySelectorAll('.card-item').forEach(function(el){el.addEventListener('click',function(){openCardModal(el.dataset.id);});});

}



function toggleCollapse(laneId) { _appState.collapsed[laneId]=!_appState.collapsed[laneId]; lsSet('cowork_collapsed',_appState.collapsed); renderKanban(); }



// ─── CARD MODAL ───────────────────────────────────────────────────────────────

var cmCardId=null; var cmLaneId=null;

function openCardModal(cardId,laneId) {

  cmCardId=cardId; cmLaneId=laneId;

  var cards=getCards(); var card=cardId?cards[cardId]:null; var isNew=!card;

  document.getElementById('card-modal-title').textContent=isNew?'Neue Karte':card.id;

  document.getElementById('cm-title').value=(card&&card.title)||'';

  document.getElementById('cm-deadline').value=(card&&card.deadline)||'';

  document.getElementById('cm-desc').value=(card&&card.desc)||'';

  var status=(card&&card.status)||'offen';

  document.querySelectorAll('[name=cm-status]').forEach(function(r){r.checked=r.value===status;});

  document.getElementById('cm-delete').style.display=isNew?'none':'';

  document.getElementById('cm-heute').style.display=(card&&card.lane!=='HE')?'':'none';

  document.getElementById('card-modal-overlay').classList.add('open');

}

function closeCardModal() { document.getElementById('card-modal-overlay').classList.remove('open'); cmCardId=null; cmLaneId=null; }

document.getElementById('cm-cancel').addEventListener('click',closeCardModal);

document.getElementById('card-modal-overlay').addEventListener('click',function(e){if(e.target===e.currentTarget)closeCardModal();});

document.getElementById('cm-save').addEventListener('click',function() {

  var title=document.getElementById('cm-title').value.trim(); var deadline=document.getElementById('cm-deadline').value;

  var desc=document.getElementById('cm-desc').value.trim(); var se=document.querySelector('[name=cm-status]:checked'); var status=se?se.value:'offen';

  if(!title){document.getElementById('cm-title').focus();return;}

  var cards=getCards();

  if(cmCardId){Object.assign(cards[cmCardId],{title:title,deadline:deadline,desc:desc,status:status});if(!cards[cmCardId].createdAt)cards[cmCardId].createdAt=new Date().toISOString();}

  else{var id=nextCardId(cmLaneId);cards[id]={id:id,lane:cmLaneId,title:title,deadline:deadline,desc:desc,status:status,archived:false,order:Date.now(),createdAt:new Date().toISOString()};}

  saveCards(cards); syncPACardsToPatients(); savePatientsToGitHub(); closeCardModal(); if(currentTab==='heute')renderHeute(); if(currentTab==='kanban')renderKanban();

});

document.getElementById('cm-delete').addEventListener('click',function(){confirmAction('In Papierkorb?','Karte kann im Papierkorb wiederhergestellt werden.',function(){var cards=getCards();if(cmCardId){cards[cmCardId].archived=true;saveCards(cards);}closeCardModal();if(currentTab==='heute')renderHeute();if(currentTab==='kanban')renderKanban();});});

document.getElementById('cm-heute').addEventListener('click',function(){var cards=getCards();if(cmCardId&&cards[cmCardId]){cards[cmCardId].lane='HE';saveCards(cards);}closeCardModal();if(currentTab==='heute')renderHeute();if(currentTab==='kanban')renderKanban();});



// ─── PATIENTEN ────────────────────────────────────────────────────────────────

var _patCurrentView = 'list';

var _patCurrentId = null;

var _patSortMode = 'alpha';

var pmPatId = null;

var _peEntryId = null;



function migratePatientEntries(pat) {

  if (!pat.entries) pat.entries = [];

  if (!pat.ampel) pat.ampel = { austritt:{status:'offen',date:'',log:[]}, ambulant:{status:'offen',date:'',log:[]}, tagesstruktur:{status:'offen',date:'',log:[]}, wiedereingliederung:{status:'offen',date:'',log:[]} };

  ['austritt','ambulant','tagesstruktur','wiedereingliederung'].forEach(function(k){

    if(!pat.ampel[k]) pat.ampel[k]={status:'offen',date:'',log:[]};

    if(!pat.ampel[k].log) pat.ampel[k].log=[];

    if(pat.ampel[k].date===undefined) pat.ampel[k].date='';

  });

  if (!pat.austrittsplanung) pat.austrittsplanung = { datum:'', farbe:'', kommentar:'' };

  if (pat.notizen && pat.entries.length === 0) {

    pat.entries.push({ id:'mig'+Date.now(), date:pat.aufnahme?(new Date(pat.aufnahme)).toISOString():(new Date()).toISOString(), title:'Notiz (migriert)', content:pat.notizen, type:'notiz' });

    delete pat.notizen;

  }

  return pat;

}



function showPatientList() {

  _patCurrentView = 'list';

  _patCurrentId = null;

  renderPatients();

}



function renderPatients(filter) {

  var container = document.getElementById('pat-view');

  var patients = getPatients().map(migratePatientEntries);

  var q = filter || (document.getElementById('pat-search') ? document.getElementById('pat-search').value.trim().toLowerCase() : '');

  if (q) patients = patients.filter(function(p){ return p.code.toLowerCase().includes(q) || (p.entries||[]).some(function(e){ return (e.title||'').toLowerCase().includes(q)||(e.content||e.text||'').toLowerCase().includes(q); }); });



  var html = '<div class="pat-header"><h2>Patienten</h2><div style="display:flex;gap:8px;align-items:center">'

    + '<input type="search" class="search-input" id="pat-search" placeholder="Suchen…">'

    + '<select class="pat-sort-select" id="pat-sort"><option value="alpha"'+ (_patSortMode==='alpha'?' selected':'') +'>A–Z</option><option value="austritt"'+ (_patSortMode==='austritt'?' selected':'') +'>Austritt</option><option value="todo"'+ (_patSortMode==='todo'?' selected':'') +'>To-Do</option></select>'

    + '<button class="btn-secondary" id="sync-patients-btn">↑↓ Sync</button>'

    + '<button class="btn-primary" id="btn-pat-add">+ Patient</button></div></div>';

  // Wochenplanung Dropdown
  var wpOpen = window._wochenplanungOpen || false;
  html += '<div class="wp-section">'
    + '<button class="wp-toggle" onclick="window._wochenplanungOpen=!window._wochenplanungOpen;renderPatients();">'
    + 'Wochenplanung ' + (wpOpen ? '\u25b4' : '\u25be') + '</button>';
  if (wpOpen) {
    var wpData = window._wochenplanungData || {};
    var dayNames = ['So','Mo','Di','Mi','Do','Fr','Sa'];
    var activePats = (getPatients().map(migratePatientEntries)).filter(function(p){ return p.status !== 'archiviert'; });
    activePats.sort(function(a,b){ return (a.code||'').localeCompare(b.code||''); });
    html += '<div class="wp-table-wrap"><table class="wp-table"><thead><tr>'
      + '<th>Patient</th><th>WEBEs</th><th>1. Termin</th><th>2. Termin</th>'
      + '</tr></thead><tbody>';
    activePats.forEach(function(p) {
      var pid = p.id;
      var wp = wpData[pid] || { webes:'standard', webesText:'', t1date:'', t1time:'', t1min:45, t2date:'', t2time:'', t2min:45 };
      // WEBEs cell
      var webesCell = '<select class="wp-select" onchange="wpSetWebes(\'' + pid + '\',this.value)">'
        + '<option value="standard"' + (wp.webes==='standard'?' selected':'') + '>Standard</option>'
        + '<option value="textfeld"' + (wp.webes==='textfeld'?' selected':'') + '>Textfeld</option>'
        + '<option value="station"' + (wp.webes==='station'?' selected':'') + '>auf Station</option>'
        + '</select>';
      if (wp.webes === 'textfeld') {
        webesCell += '<input type="text" class="wp-text-input wp-text-red" value="' + esc(wp.webesText||'') + '" placeholder="Eingabe..." onchange="wpSetWebesText(\'' + pid + '\',this.value)">';
      } else if (wp.webes === 'station') {
        webesCell = '<span class="wp-station-label">auf Station</span>';
      }
      // Termin helper
      function renderTermin(prefix, dateVal, timeVal, minVal) {
        var display = '';
        if (dateVal && timeVal) {
          var dt = new Date(dateVal + 'T' + timeVal);
          display = dayNames[dt.getDay()] + ' ' + timeVal;
          if (minVal) display += ' (' + minVal + 'min)';
        }
        return '<div class="wp-termin">'
          + '<input type="date" class="wp-date" value="' + esc(dateVal||'') + '" onchange="wpSetTermin(\'' + pid + '\',\'' + prefix + '\',\'date\',this.value)">'
          + '<input type="time" class="wp-time" value="' + esc(timeVal||'') + '" onchange="wpSetTermin(\'' + pid + '\',\'' + prefix + '\',\'time\',this.value)">'
          + '<input type="number" class="wp-min" value="' + (minVal||45) + '" min="5" max="120" step="5" onchange="wpSetTermin(\'' + pid + '\',\'' + prefix + '\',\'min\',this.value)">'
          + (display ? '<div class="wp-termin-display">' + display + '</div>' : '')
          + '</div>';
      }
      html += '<tr><td class="wp-pat-code">' + esc(p.code) + '</td>'
        + '<td class="wp-webes-cell">' + webesCell + '</td>'
        + '<td>' + renderTermin('t1', wp.t1date, wp.t1time, wp.t1min) + '</td>'
        + '<td>' + renderTermin('t2', wp.t2date, wp.t2time, wp.t2min) + '</td>'
        + '</tr>';
    });
    html += '</tbody></table></div>';
  }
  html += '</div>';

  // Sort
  var cards = typeof getCards === 'function' ? getCards() : {};
  var paCards = {};
  Object.values(cards).forEach(function(c){ if (!c.archived && c.lane === 'PA') paCards[c.title] = c; });

  var active = patients.filter(function(p){ return p.status !== 'archiviert'; });

  if (_patSortMode === 'alpha') {
    active.sort(function(a,b){ return (a.code||'').localeCompare(b.code||''); });
  } else if (_patSortMode === 'austritt') {
    active.sort(function(a,b){
      var da = (a.austrittsplanung||{}).datum || '';
      var db = (b.austrittsplanung||{}).datum || '';
      if (da && !db) return -1;
      if (!da && db) return 1;
      if (da && db) return da.localeCompare(db);
      return (a.code||'').localeCompare(b.code||'');
    });
  } else if (_patSortMode === 'todo') {
    active.sort(function(a,b){
      var findCard = function(pat) {
        var code = (pat.code||'').toUpperCase();
        var found = null;
        Object.values(paCards).forEach(function(c){
          if ((c.title||'').toUpperCase().includes(code)) found = c;
        });
        return found;
      };
      var ca = findCard(a), cb = findCard(b);
      var ha = ca ? 1 : 0, hb = cb ? 1 : 0;
      if (ha !== hb) return hb - ha;
      if (ca && cb) {
        var dda = ca.deadline || '9999', ddb = cb.deadline || '9999';
        return dda.localeCompare(ddb);
      }
      return (a.code||'').localeCompare(b.code||'');
    });
  }

  var archived = patients.filter(function(p){ return p.status === 'archiviert'; });



  var _ampelIcons = {
    austritt: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    ambulant: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11v4"/><path d="M14 13h-4"/><path d="M16 6V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/><path d="M18 6v14"/><path d="M6 6v14"/><rect width="20" height="14" x="2" y="6" rx="2"/></svg>',
    tagesstruktur: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4"/><path d="M3 10h18"/><path d="M8 2v4"/><path d="M17 14h-6"/><path d="M13 18H7"/><path d="M7 14h.01"/><path d="M17 18h.01"/></svg>',
    wiedereingliederung: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 12-9.373 9.373a1 1 0 0 1-3.001-3L12 9"/><path d="m18 15 4-4"/><path d="m21.5 11.5-1.914-1.914A2 2 0 0 1 19 8.172v-.344a2 2 0 0 0-.586-1.414l-1.657-1.657A6 6 0 0 0 12.516 3H9l1.243 1.243A6 6 0 0 1 12 8.485V10l2 2h1.172a2 2 0 0 1 1.414.586L18.5 14.5"/></svg>'
  };

  var _ampelTooltipLabels = { austritt:'Wohnsituation', ambulant:'Ambulant', tagesstruktur:'Tagesstruktur', wiedereingliederung:'Wiedereingliederung' };

  function renderPatRow(p) {

    var ampelIcons = ['austritt','ambulant','tagesstruktur','wiedereingliederung'].map(function(k){
      var s = (p.ampel && p.ampel[k]) ? p.ampel[k].status : 'offen';
      var colors = { gruen:'#22c55e', gelb:'#eab308', rot:'#ef4444', offen:'#94a3b8' };
      var a = (p.ampel && p.ampel[k]) || {};
      var lastLog = (a.log && a.log.length > 0) ? a.log[a.log.length-1] : null;
      var tooltip = _ampelTooltipLabels[k] + ': ' + (s === 'offen' ? 'Offen' : s.charAt(0).toUpperCase()+s.slice(1));
      if (lastLog) tooltip += '\n' + lastLog.date + ': ' + lastLog.text;
      return '<span class="pat-ampel-icon" style="color:'+(colors[s]||'#94a3b8')+'" title="'+esc(tooltip)+'">'+_ampelIcons[k]+'</span>';
    }).join('');

    var lastEntry = (p.entries||[]).length > 0 ? p.entries[0] : null;
    var entryInfo = '';
    if (lastEntry) {
      var eDate = lastEntry.date ? lastEntry.date.substring(0,10) : '';
      var eDateFmt = eDate;
      if (eDate && eDate.includes('-')) { var dp=eDate.split('-'); eDateFmt=dp[2]+'.'+dp[1]+'.'+dp[0].substring(2); }
      entryInfo = esc((lastEntry.title||'').substring(0,40)) + (eDateFmt ? ' ('+eDateFmt+')' : '');
    }

    var ap = p.austrittsplanung || {};
    var austrittBadge = '';
    if (ap.datum) {
      var dd = ap.datum.split('-'); var fmtDate = dd.length===3 ? dd[2]+'.'+dd[1]+'.'+dd[0].substring(2) : ap.datum;
      austrittBadge = '<span class="pat-austritt-badge'+(ap.farbe?' pat-austritt-'+ap.farbe:'')+'">Austritt: '+esc(fmtDate)+(ap.kommentar?' — '+esc(ap.kommentar):'')+'</span>';
    }
    var bp = p.bericht || {};
    var berichtBadge = '<span class="pat-bericht-badge'+(bp.farbe?' pat-bericht-'+bp.farbe:'')+'" title="'+(bp.kommentar?esc(bp.kommentar):'Kein Bericht')+'">Bericht</span>';
    var dauerBadge = '';
    if (p.aufnahme) {
      var aufDt = new Date(p.aufnahme + 'T00:00:00');
      var diffDays = Math.floor((new Date() - aufDt) / 86400000);
      if (diffDays >= 0) { var m = Math.floor(diffDays / 30); var remDays = diffDays % 30; var w = Math.floor(remDays / 7); var d = remDays % 7; dauerBadge = '<span class="pat-dauer-badge">' + (m > 0 ? m + 'M ' : '') + w + 'W ' + d + 'T</span>'; }
    }
    return '<div class="patient-row'+(p.status==='archiviert'?' pat-archived':'')+'" onclick="showPatientDetail(\''+esc(p.id)+'\')"><span class="pat-code" style="font-weight:600;min-width:80px">'+esc(p.code)+'</span>'+austrittBadge+'<span class="pat-ampel-icons">'+ampelIcons+'</span><span class="pat-info" style="flex:1;font-size:12px;color:var(--text-muted)">'+entryInfo+'</span>'+dauerBadge+berichtBadge+'<span class="pat-status-badge pat-status-'+(p.status||'aktiv')+'">'+(p.status||'aktiv')+'</span></div>';

  }



  if (active.length === 0 && archived.length === 0) {

    html += '<div class="empty-state">Keine Patienten gefunden.</div>';

  } else {

    if (active.length === 0) { html += '<div class="empty-state">Keine aktiven Patienten.</div>'; }

    else { html += active.map(renderPatRow).join(''); }

    if (archived.length > 0) {

      html += '<div class="pat-archive-section"><button class="done-archive-toggle" onclick="window._patArchiveOpen=!window._patArchiveOpen;renderPatients();">Archiv ('+archived.length+') '+(window._patArchiveOpen?'\u25b4':'\u25be')+'</button>';

      if (window._patArchiveOpen) { html += '<div class="pat-archive-list">'+archived.map(renderPatRow).join('')+'</div>'; }

      html += '</div>';

    }

  }

  container.innerHTML = html;



  document.getElementById('pat-search').addEventListener('input', function(){ renderPatients(); });

  document.getElementById('pat-sort').addEventListener('change', function(){ _patSortMode = this.value; renderPatients(); });

  document.getElementById('btn-pat-add').addEventListener('click', function(){ openPatModal(null); });

  var syncBtn = document.getElementById('sync-patients-btn');

  if (syncBtn) {

    syncBtn.addEventListener('click', async function() {

      syncBtn.textContent = '⏳ Sync…'; syncBtn.disabled = true;

      try { await pullMergePushPatients(); syncBtn.textContent = '✓ OK'; setTimeout(function(){ syncBtn.textContent = '↑↓ Sync'; syncBtn.disabled = false; }, 2000); }

      catch(e) { syncBtn.textContent = '✗ Fehler'; setTimeout(function(){ syncBtn.textContent = '↑↓ Sync'; syncBtn.disabled = false; }, 2000); }

    });

  }

}



// --- VORBERICHTE SUMMARY + ERSTKONTAKT VORBEREITUNG ---
function getVorberichte(pat) {
  return (pat.entries||[]).filter(function(e){ return e.type === 'vorbericht'; })
    .sort(function(a,b){ return new Date(a.date)-new Date(b.date); });
}
function generateVorberichtSummary(pat) {
  var vbs = getVorberichte(pat);
  if (vbs.length === 0) return null;
  var allText = vbs.map(function(v){ return (v.title?v.title+': ':'')+(v.content||v.text||''); }).join('\n\n');
  var sentences = allText.replace(/\n+/g,' ').split(/(?<=[.!?])\s+/).filter(function(s){ return s.trim().length > 10; });
  if (sentences.length === 0) return allText.substring(0,500);
  var summary = sentences.slice(0,6).join(' ');
  if (summary.length > 600) summary = summary.substring(0,597) + '...';
  return summary;
}
function generateErstkontaktVorbereitung(pat) {
  var vbs = getVorberichte(pat);
  if (vbs.length === 0) return null;
  var allText = vbs.map(function(v){ return (v.title?v.title+': ':'')+(v.content||v.text||''); }).join('\n\n');
  var sections = [];
  var diagMatch = allText.match(/diagnos[en]*[:\s]+([^\n.]{5,120})/i);
  sections.push('Diagnosen: ' + (diagMatch ? diagMatch[1].trim() : 'Aus Vorberichten entnehmen'));
  var stoerMatch = allText.match(/st[\u00f6o]rungsmodell[:\s]+([^\n]{5,150})/i) || allText.match(/st[\u00f6o]rungsbild[:\s]+([^\n]{5,150})/i);
  sections.push('St\u00f6rungsmodell: ' + (stoerMatch ? stoerMatch[1].trim() : 'Noch zu kl\u00e4ren'));
  var therapieMatch = allText.match(/therapie[verlauf]*[:\s]+([^\n]{5,150})/i) || allText.match(/behandlung[sverlauf]*[:\s]+([^\n]{5,150})/i);
  sections.push('Bisheriger Therapieverlauf: ' + (therapieMatch ? therapieMatch[1].trim() : 'Aus Vorberichten entnehmen'));
  sections.push('\u2500\u2500\u2500 Offene Fragen f\u00fcr Erstkontakt \u2500\u2500\u2500');
  sections.push('\u25a1 Wohnsituation nach Austritt?');
  sections.push('\u25a1 Tagesstruktur vorhanden?');
  sections.push('\u25a1 Reintegrationsplan (beruflich/sozial)?');
  sections.push('\u25a1 Ambulante Therapie gesichert?');
  sections.push('\u25a1 Suizidalit\u00e4t aktuell?');
  sections.push('\u25a1 Selbstverletzung aktuell/Vergangenheit?');
  return sections.join('\n');
}
var _vorberichtBoxExpanded = {};
function toggleVorberichtBox(boxId) {
  _vorberichtBoxExpanded[boxId] = !_vorberichtBoxExpanded[boxId];
  var box = document.getElementById(boxId);
  if (!box) return;
  box.classList.toggle('expanded', !!_vorberichtBoxExpanded[boxId]);
  var toggle = box.querySelector('.vb-box-toggle');
  if (toggle) toggle.textContent = _vorberichtBoxExpanded[boxId] ? '\u25b2' : '\u25bc';
}
function copyBoxContent(boxId) {
  var box = document.getElementById(boxId + '-text');
  if (!box) return;
  navigator.clipboard.writeText(box.textContent).then(function(){
    var btn = box.parentElement.querySelector('.vb-copy-btn');
    if (btn) { btn.textContent = '\u2713 Kopiert'; setTimeout(function(){ btn.textContent = '\u2398 Copy'; }, 1500); }
  });
}
function changeEntryType(entryId, newType) {
  var patients = getPatients().map(migratePatientEntries);
  var pat = patients.find(function(p){ return p.id === _patCurrentId; });
  if (!pat) return;
  var entry = (pat.entries||[]).find(function(e){ return e.id === entryId; });
  if (!entry) return;
  entry.type = newType;
  savePatients(patients);
  showPatientDetail(_patCurrentId);
}

function showPatientDetail(patId) {

  _patCurrentView = 'detail';

  _patCurrentId = patId;

  var container = document.getElementById('pat-view');

  var patients = getPatients().map(migratePatientEntries);

  var pat = patients.find(function(p){ return p.id === patId; });

  if (!pat) { showPatientList(); return; }



  var ampelLabels = { austritt:'Wohnsituation', ambulant:'Ambulant', tagesstruktur:'Tagesstruktur', wiedereingliederung:'Wiedereingliederung' };



  var html = '<div class="pat-detail-header">'

    + '<button class="pat-detail-back" onclick="showPatientList()">← Zurück</button>'

    + '<span class="pat-detail-code">'+esc(pat.code)+'</span>'

    + '<span class="pat-status-badge pat-status-'+(pat.status||'aktiv')+'">'+(pat.status||'aktiv')+'</span>'

    + '<span class="pat-detail-meta">Aufnahme: <input type="date" class="pat-aufnahme-input" value="'+esc(pat.aufnahme||'')+'" onchange="setAufnahmedatum(this.value)"></span>'

    + '<div class="pat-detail-actions">'

    + '<button class="btn-secondary" onclick="openPatModal(\''+esc(pat.id)+'\')">Bearbeiten</button>'

    + (pat.status !== 'archiviert'

      ? '<button class="btn-secondary" onclick="archivePatient(\''+esc(pat.id)+'\')" style="color:#f59e0b">Archivieren</button>'

      : '<button class="btn-secondary" onclick="reactivatePatient(\''+esc(pat.id)+'\')" style="color:#22c55e">Reaktivieren</button>')

    + '<button class="btn-secondary" id="sync-patients-btn-detail">↑↓ Sync</button>'

    + '</div></div>';



  // --- PLANUNG: 5 Kategorien einheitlich ---
  var _detailIcons = {
    austritt: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8"/><path d="M3 10a2 2 0 0 1 .709-1.528l7-6a2 2 0 0 1 2.582 0l7 6A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    ambulant: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11v4"/><path d="M14 13h-4"/><path d="M16 6V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/><path d="M18 6v14"/><path d="M6 6v14"/><rect width="20" height="14" x="2" y="6" rx="2"/></svg>',
    tagesstruktur: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4"/><path d="M3 10h18"/><path d="M8 2v4"/><path d="M17 14h-6"/><path d="M13 18H7"/><path d="M7 14h.01"/><path d="M17 18h.01"/></svg>',
    wiedereingliederung: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 12-9.373 9.373a1 1 0 0 1-3.001-3L12 9"/><path d="m18 15 4-4"/><path d="m21.5 11.5-1.914-1.914A2 2 0 0 1 19 8.172v-.344a2 2 0 0 0-.586-1.414l-1.657-1.657A6 6 0 0 0 12.516 3H9l1.243 1.243A6 6 0 0 1 12 8.485V10l2 2h1.172a2 2 0 0 1 1.414.586L18.5 14.5"/></svg>',
    austrittsplanung: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 20V6a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v14"/><path d="M2 20h20"/><path d="M14 12v.01"/></svg>'
  };

  html += '<details class="pat-status-dropdown"><summary class="pat-status-dropdown-header">Statusuebersicht</summary>';
  html += '<div class="pat-planung-list">';

  // 4 Ampel-Kategorien — gleiches Layout wie Austrittsplanung
  ['austritt','ambulant','tagesstruktur','wiedereingliederung'].forEach(function(k){
    var a = pat.ampel[k] || {status:'offen',date:'',log:[]};
    var statusColors = { gruen:'#22c55e', gelb:'#eab308', rot:'#ef4444', offen:'#94a3b8' };
    var iconColor = statusColors[a.status] || '#94a3b8';
    var lastLog = (a.log && a.log.length > 0) ? a.log[a.log.length-1] : null;
    var kommentarVal = lastLog ? lastLog.text : '';

    html += '<div class="pat-planung-card">'
      + '<div class="pat-planung-header">'
      + '<span class="pat-planung-icon" style="color:'+iconColor+'">'+(_detailIcons[k]||'')+'</span>'
      + '<span class="pat-planung-title">'+esc(ampelLabels[k])+'</span>'
      + '</div>'
      + '<div class="pat-planung-body"><div class="pat-planung-row">'
      + '<div class="pat-ap-field"><label>Status</label><div class="pat-ap-colors">'
      + '<div class="pat-ap-color-btn'+(a.status==='offen'?' selected':'')+'" data-val="offen" style="background:#94a3b8" onclick="setAmpelStatus(\''+k+'\',\'offen\')"></div>'
      + '<div class="pat-ap-color-btn'+(a.status==='gruen'?' selected':'')+'" data-val="gruen" style="background:#22c55e" onclick="setAmpelStatus(\''+k+'\',\'gruen\')"></div>'
      + '<div class="pat-ap-color-btn'+(a.status==='gelb'?' selected':'')+'" data-val="gelb" style="background:#eab308" onclick="setAmpelStatus(\''+k+'\',\'gelb\')"></div>'
      + '<div class="pat-ap-color-btn'+(a.status==='rot'?' selected':'')+'" data-val="rot" style="background:#ef4444" onclick="setAmpelStatus(\''+k+'\',\'rot\')"></div>'
      + '</div></div>'
      + '<div class="pat-ap-field"><label>Datum</label><input type="date" class="pat-ap-date" id="ampel-date-'+k+'" value="'+esc(a.date||'')+'" onchange="setAmpelDate(\''+k+'\',this.value)"></div>'
      + '<div class="pat-ap-field pat-ap-field-wide"><label>Kommentar</label><input type="text" class="pat-ap-kommentar" id="ampel-log-text-'+k+'" value="'+esc(kommentarVal)+'" placeholder="z.B. Anmeldung laeuft..." onchange="addAmpelLog(\''+k+'\')"></div>'
      + '</div></div></div>';
  });

  // Austrittsplanung als 5. Karte — identisches Layout
  var apData = pat.austrittsplanung || { datum:'', farbe:'', kommentar:'' };
  var apColors = { gruen:'#22c55e', gelb:'#eab308', blau:'#3b82f6', rot:'#ef4444' };
  var apIconColor = apColors[apData.farbe] || '#94a3b8';

  html += '<div class="pat-planung-card">'
    + '<div class="pat-planung-header">'
    + '<span class="pat-planung-icon" style="color:'+apIconColor+'">'+_detailIcons.austrittsplanung+'</span>'
    + '<span class="pat-planung-title">Austrittsplanung</span>'
    + '</div>'
    + '<div class="pat-planung-body"><div class="pat-planung-row">'
    + '<div class="pat-ap-field"><label>Farbe</label><div class="pat-ap-colors">'
    + '<div class="pat-ap-color-btn'+(apData.farbe==='gruen'?' selected':'')+'" data-val="gruen" style="background:#22c55e" onclick="setAustrittsplanung(\'farbe\',\'gruen\')"></div>'
    + '<div class="pat-ap-color-btn'+(apData.farbe==='gelb'?' selected':'')+'" data-val="gelb" style="background:#eab308" onclick="setAustrittsplanung(\'farbe\',\'gelb\')"></div>'
    + '<div class="pat-ap-color-btn'+(apData.farbe==='blau'?' selected':'')+'" data-val="blau" style="background:#3b82f6" onclick="setAustrittsplanung(\'farbe\',\'blau\')"></div>'
    + '<div class="pat-ap-color-btn'+(apData.farbe==='rot'?' selected':'')+'" data-val="rot" style="background:#ef4444" onclick="setAustrittsplanung(\'farbe\',\'rot\')"></div>'
    + '</div></div>'
    + '<div class="pat-ap-field"><label>Datum</label><input type="date" class="pat-ap-date" id="ap-datum" value="'+esc(apData.datum||'')+'" onchange="setAustrittsplanung(\'datum\',this.value)"></div>'
    + '<div class="pat-ap-field pat-ap-field-wide"><label>Kommentar</label><input type="text" class="pat-ap-kommentar" id="ap-kommentar" value="'+esc(apData.kommentar||'')+'" placeholder="z.B. Wohnung gefunden, wartet auf Platz..." onchange="setAustrittsplanung(\'kommentar\',this.value)"></div>'
    + '</div></div></div>';

  // Bericht-Karte — Farbe + Kommentar
  var brData = pat.bericht || { farbe:'', kommentar:'' };
  var brColors = { gruen:'#22c55e', gelb:'#eab308', grau:'#4b5563', rot:'#ef4444' };
  var brIconColor = brColors[brData.farbe] || '#94a3b8';

  html += '<div class="pat-planung-card">'
    + '<div class="pat-planung-header">'
    + '<span class="pat-planung-icon" style="color:'+brIconColor+'"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg></span>'
    + '<span class="pat-planung-title">Bericht</span>'
    + '</div>'
    + '<div class="pat-planung-body"><div class="pat-planung-row">'
    + '<div class="pat-ap-field"><label>Farbe</label><div class="pat-ap-colors">'
    + '<div class="pat-ap-color-btn'+(brData.farbe==='gruen'?' selected':'')+'" data-val="gruen" style="background:#22c55e" onclick="setBerichtStatus(\'farbe\',\'gruen\')"></div>'
    + '<div class="pat-ap-color-btn'+(brData.farbe==='gelb'?' selected':'')+'" data-val="gelb" style="background:#eab308" onclick="setBerichtStatus(\'farbe\',\'gelb\')"></div>'
    + '<div class="pat-ap-color-btn'+(brData.farbe==='grau'?' selected':'')+'" data-val="grau" style="background:#4b5563" onclick="setBerichtStatus(\'farbe\',\'grau\')"></div>'
    + '<div class="pat-ap-color-btn'+(brData.farbe==='rot'?' selected':'')+'" data-val="rot" style="background:#ef4444" onclick="setBerichtStatus(\'farbe\',\'rot\')"></div>'
    + '</div></div>'
    + '<div class="pat-ap-field pat-ap-field-wide"><label>Kommentar</label><input type="text" class="pat-ap-kommentar" id="br-kommentar" value="'+esc(brData.kommentar||'')+'" placeholder="z.B. Bericht fertig, zur Kontrolle..." onchange="setBerichtStatus(\'kommentar\',this.value)"></div>'
    + '</div></div></div>';

  html += '</div></details>';

  // --- VORBERICHTE SUMMARY BOXES ---
  var vbSummary = generateVorberichtSummary(pat);
  var ekVorbereitung = generateErstkontaktVorbereitung(pat);
  if (vbSummary || ekVorbereitung) {
    html += '<div class="vb-boxes-row">';
    if (vbSummary) {
      var vbExp = _vorberichtBoxExpanded['vb-summary-box'];
      html += '<div class="vb-box vb-box-blue'+(vbExp?' expanded':'')+'" id="vb-summary-box">'
        + '<div class="vb-box-header" onclick="toggleVorberichtBox(\x27vb-summary-box\x27)">'
        + '<span class="vb-box-title">Zusammenfassung Vorberichte</span>'
        + '<span class="vb-box-toggle">'+(vbExp?'\u25b2':'\u25bc')+'</span>'
        + '</div>'
        + '<div class="vb-box-content" id="vb-summary-box-text">'+esc(vbSummary)+'</div>'
        + '<button class="vb-copy-btn" onclick="event.stopPropagation();copyBoxContent(\x27vb-summary-box\x27)">\u2398 Copy</button>'
        + '</div>';
    }
    if (ekVorbereitung) {
      var ekExp = _vorberichtBoxExpanded['vb-erstk-box'];
      html += '<div class="vb-box vb-box-orange'+(ekExp?' expanded':'')+'" id="vb-erstk-box">'
        + '<div class="vb-box-header" onclick="toggleVorberichtBox(\x27vb-erstk-box\x27)">'
        + '<span class="vb-box-title">Vorbereitung Erstkontakt</span>'
        + '<span class="vb-box-toggle">'+(ekExp?'\u25b2':'\u25bc')+'</span>'
        + '</div>'
        + '<div class="vb-box-content" id="vb-erstk-box-text">'+esc(ekVorbereitung).replace(/\n/g,'<br>')+'</div>'
        + '<button class="vb-copy-btn" onclick="event.stopPropagation();copyBoxContent(\x27vb-erstk-box\x27)">\u2398 Copy</button>'
        + '</div>';
    }
    html += '</div>';
  }

  html += '<div class="pat-entries-section">'

    + '<div class="pat-entries-header"><h3>Verlauf</h3>'

    + '<button class="btn-primary" onclick="openEntryModal(null)">+ Neuer Eintrag</button></div>';



  var entries = (pat.entries||[]).slice().sort(function(a,b){ return new Date(b.date||b.ts||0)-new Date(a.date||a.ts||0); });

  if (entries.length === 0) {

    html += '<div class="empty-state">Keine Einträge vorhanden.</div>';

  } else {

    entries.forEach(function(e){

      var rawDate = e.date || e.ts || null;
      var d = rawDate ? new Date(rawDate) : null;
      var validDate = d && !isNaN(d.getTime());

      var curType = e.type||'notiz';
      var dateStr = validDate
        ? d.toLocaleDateString('de-CH',{day:'2-digit',month:'2-digit',year:'numeric'}) + ' ' + d.toLocaleTimeString('de-CH',{hour:'2-digit',minute:'2-digit'})
        : '';

      html += '<div class="pat-entry-card type-'+esc(curType)+'">'

        + '<div class="pat-entry-meta">'

        + '<span class="pat-entry-date">'+esc(dateStr)+'</span>'

        + '<select class="pat-entry-type-select" onchange="changeEntryType(\x27'+esc(e.id)+'\x27,this.value)">'
        + '<option value="verlaufsbericht"'+(curType==='verlaufsbericht'?' selected':'')+'>Verlaufsbericht</option>'
        + '<option value="vorbericht"'+(curType==='vorbericht'?' selected':'')+'>Vorbericht</option>'
        + '<option value="notiz"'+(curType==='notiz'?' selected':'')+'>Notiz</option>'
        + '</select>'
        + '</div>'

        + '<div class="pat-entry-title">'+esc(e.title||'')+'</div>'

        + (function(){ var t=e.content||e.text||''; var ls=t.split('\n'); var lo=ls.length>5||t.length>400; var ex=_entryExpanded[e.id]; return '<div class="pat-entry-content'+(lo&&!ex?' collapsed':'')+'">' + esc(t) + '</div>' + (lo ? '<button class="pat-entry-expand" onclick="toggleEntryExpand(\x27'+esc(e.id)+'\x27)">'+(ex?'Weniger':'Mehr anzeigen...')+'</button>' : ''); }())

        + '<div class="pat-entry-actions">'

        + '<button onclick="openEntryModal(\''+esc(e.id)+'\')">Bearbeiten</button>'

        + '<button onclick="deleteEntry(\''+esc(e.id)+'\')">Löschen</button>'

        + '</div></div>';

    });

  }

  html += '</div>';



  container.innerHTML = html;



  var syncBtnD = document.getElementById('sync-patients-btn-detail');

  if (syncBtnD) {

    syncBtnD.addEventListener('click', async function() {

      syncBtnD.textContent = '⏳ Sync…'; syncBtnD.disabled = true;

      try { await pullMergePushPatients(); syncBtnD.textContent = '✓ OK'; setTimeout(function(){ syncBtnD.textContent = '↑↓ Sync'; syncBtnD.disabled = false; }, 2000); }

      catch(e) { syncBtnD.textContent = '✗ Fehler'; setTimeout(function(){ syncBtnD.textContent = '↑↓ Sync'; syncBtnD.disabled = false; }, 2000); }

    });

  }

}



function toggleAmpelPopup(key) {

  var popup = document.getElementById('ampel-popup-'+key);

  if (!popup) return;

  document.querySelectorAll('.pat-ampel-popup.open').forEach(function(p){ if(p.id!=='ampel-popup-'+key) p.classList.remove('open'); });

  popup.classList.toggle('open');

}

function closeAmpelPopup(key) {

  var popup = document.getElementById('ampel-popup-'+key);

  if (popup) popup.classList.remove('open');

}

function _getPatAndSave(fn) {

  var patients = getPatients().map(migratePatientEntries);

  var idx = patients.findIndex(function(p){ return p.id === _patCurrentId; });

  if (idx === -1) return;

  fn(patients[idx]);

  savePatients(patients);

  showPatientDetail(_patCurrentId);

}

function setAmpelStatus(key, status) {

  _getPatAndSave(function(pat){ pat.ampel[key].status = status; });

}

function setAufnahmedatum(dateVal) {
  _getPatAndSave(function(pat){ pat.aufnahme = dateVal; });
}

function setAmpelDate(key, dateVal) {

  _getPatAndSave(function(pat){ pat.ampel[key].date = dateVal; });

}

function addAmpelLog(key) {

  var input = document.getElementById('ampel-log-text-'+key);

  if (!input) return;

  var text = input.value.trim();

  if (!text) { input.focus(); return; }

  _getPatAndSave(function(pat){

    pat.ampel[key].log.push({ date: new Date().toISOString().substring(0,10), text: text });

  });

}



function setAustrittsplanung(field, value) {
  _getPatAndSave(function(pat){
    if (!pat.austrittsplanung) pat.austrittsplanung = { datum:'', farbe:'', kommentar:'' };
    pat.austrittsplanung[field] = value;
  });
}

function setBerichtStatus(field, value) {
  _getPatAndSave(function(pat){
    if (!pat.bericht) pat.bericht = { farbe:'', kommentar:'' };
    pat.bericht[field] = value;
  });
}

// ─── WOCHENPLANUNG ───────────────────────────────────────────────────────────
if (!window._wochenplanungData) window._wochenplanungData = {};

function _wpGet(pid) {
  if (!window._wochenplanungData[pid]) window._wochenplanungData[pid] = { webes:'standard', webesText:'', t1date:'', t1time:'', t1min:45, t2date:'', t2time:'', t2min:45 };
  return window._wochenplanungData[pid];
}

function wpSetWebes(pid, val) {
  var wp = _wpGet(pid);
  wp.webes = val;
  if (val !== 'textfeld') wp.webesText = '';
  renderPatients();
}

function wpSetWebesText(pid, val) {
  _wpGet(pid).webesText = val;
}

function wpSetTermin(pid, prefix, field, val) {
  var wp = _wpGet(pid);
  if (field === 'date') wp[prefix + 'date'] = val;
  if (field === 'time') wp[prefix + 'time'] = val;
  if (field === 'min') wp[prefix + 'min'] = parseInt(val) || 45;
  renderPatients();
}

function openEntryModal(entryId) {

  _peEntryId = entryId;

  var entry = null;

  if (entryId && _patCurrentId) {

    var patients = getPatients().map(migratePatientEntries);

    var pat = patients.find(function(p){ return p.id === _patCurrentId; });

    if (pat) entry = (pat.entries||[]).find(function(e){ return e.id === entryId; });

  }

  document.getElementById('pe-modal-title').textContent = entry ? 'Eintrag bearbeiten' : 'Neuer Eintrag';

  document.getElementById('pe-type').value = (entry && entry.type) || 'notiz';

  document.getElementById('pe-title').value = (entry && entry.title) || '';

  document.getElementById('pe-content').value = (entry && (entry.content || entry.text)) || '';

  document.getElementById('pe-delete').style.display = entry ? '' : 'none';

  document.getElementById('pat-entry-modal-overlay').classList.add('open');

  setTimeout(function(){ document.getElementById('pe-title').focus(); }, 50);

}

function closeEntryModal() {

  document.getElementById('pat-entry-modal-overlay').classList.remove('open');

  _peEntryId = null;

}

document.getElementById('pe-cancel').addEventListener('click', closeEntryModal);

document.getElementById('pat-entry-modal-overlay').addEventListener('click', function(e){ if(e.target===e.currentTarget) closeEntryModal(); });

document.getElementById('pe-save').addEventListener('click', function(){

  var title = document.getElementById('pe-title').value.trim();

  var content = document.getElementById('pe-content').value.trim();

  var type = document.getElementById('pe-type').value;

  if (!title) { document.getElementById('pe-title').focus(); return; }

  var patients = getPatients().map(migratePatientEntries);

  var idx = patients.findIndex(function(p){ return p.id === _patCurrentId; });

  if (idx === -1) return;

  if (_peEntryId) {

    var eIdx = patients[idx].entries.findIndex(function(e){ return e.id === _peEntryId; });

    if (eIdx !== -1) {

      patients[idx].entries[eIdx] = Object.assign({}, patients[idx].entries[eIdx], { title:title, content:content, text:content, type:type });

    }

  } else {

    patients[idx].entries.push({ id:'e'+Date.now(), date:new Date().toISOString(), title:title, content:content, type:type });

  }

  savePatients(patients);

  closeEntryModal();

  showPatientDetail(_patCurrentId);

});

document.getElementById('pe-delete').addEventListener('click', function(){

  if (!_peEntryId) return;

  confirmAction('Eintrag löschen?','Dieser Eintrag wird unwiderruflich gelöscht.', function(){

    var patients = getPatients().map(migratePatientEntries);

    var idx = patients.findIndex(function(p){ return p.id === _patCurrentId; });

    if (idx !== -1) {

      patients[idx].entries = patients[idx].entries.filter(function(e){ return e.id !== _peEntryId; });

      savePatients(patients);

    }

    closeEntryModal();

    showPatientDetail(_patCurrentId);

  });

});



function archivePatient(patId) {

  confirmAction('Patient archivieren?','Der Patient wird ins Archiv verschoben und kann jederzeit reaktiviert werden.', function(){

    var patients = getPatients().map(migratePatientEntries);

    var idx = patients.findIndex(function(p){ return p.id === patId; });

    if (idx !== -1) { patients[idx].status = 'archiviert'; savePatients(patients); }

    showPatientList();

  });

}

function reactivatePatient(patId) {

  var patients = getPatients().map(migratePatientEntries);

  var idx = patients.findIndex(function(p){ return p.id === patId; });

  if (idx !== -1) { patients[idx].status = 'aktiv'; savePatients(patients); }

  showPatientDetail(patId);

}



function deleteEntry(entryId) {

  confirmAction('Eintrag löschen?','Dieser Eintrag wird unwiderruflich gelöscht.', function(){

    var patients = getPatients().map(migratePatientEntries);

    var idx = patients.findIndex(function(p){ return p.id === _patCurrentId; });

    if (idx !== -1) {

      patients[idx].entries = patients[idx].entries.filter(function(e){ return e.id !== entryId; });

      savePatients(patients);

    }

    showPatientDetail(_patCurrentId);

  });

}



function openPatModal(patId) {

  pmPatId = patId;

  var patients = getPatients().map(migratePatientEntries);

  var pat = patId ? patients.find(function(p){ return p.id === patId; }) : null;

  var isNew = !pat;

  document.getElementById('pat-modal-title').textContent = isNew ? 'Neuer Patient' : pat.code + ' bearbeiten';

  document.getElementById('pm-code').value = (pat && pat.code) || '';

  document.getElementById('pm-aufnahme').value = (pat && pat.aufnahme) || '';

  document.getElementById('pm-status').value = (pat && pat.status) || 'aktiv';

  document.getElementById('pm-delete').style.display = isNew ? 'none' : '';

  document.getElementById('pat-modal-overlay').classList.add('open');

}

function closePatModal() {

  document.getElementById('pat-modal-overlay').classList.remove('open');

  pmPatId = null;

}

document.getElementById('pm-cancel').addEventListener('click', closePatModal);

document.getElementById('pat-modal-overlay').addEventListener('click', function(e){ if(e.target===e.currentTarget) closePatModal(); });

document.getElementById('pm-save').addEventListener('click', function(){

  var code = document.getElementById('pm-code').value.trim();

  var aufnahme = document.getElementById('pm-aufnahme').value;

  var status = document.getElementById('pm-status').value;

  if (!code) { document.getElementById('pm-code').focus(); return; }

  var patients = getPatients().map(migratePatientEntries);

  if (pmPatId) {

    var idx = patients.findIndex(function(p){ return p.id === pmPatId; });

    if (idx !== -1) patients[idx] = Object.assign({}, patients[idx], { code:code, aufnahme:aufnahme, status:status });

  } else {

    patients.push({ id:'PAT'+Date.now(), code:code, aufnahme:aufnahme, status:status, entries:[], ampel:{ austritt:{status:'offen',date:'',log:[]}, ambulant:{status:'offen',date:'',log:[]}, tagesstruktur:{status:'offen',date:'',log:[]}, wiedereingliederung:{status:'offen',date:'',log:[]} }, austrittsplanung:{ datum:'', farbe:'', kommentar:'' }, bericht:{ farbe:'', kommentar:'' } });

  }

  savePatients(patients);

  closePatModal();

  if (_patCurrentView === 'detail' && pmPatId) { showPatientDetail(pmPatId); }

  else { showPatientList(); }

});

document.getElementById('pm-delete').addEventListener('click', function(){

  confirmAction('Patient löschen?','Dieser Patient wird unwiderruflich gelöscht.', function(){

    var patients = getPatients();

    patients = patients.filter(function(p){ return p.id !== pmPatId; });

    savePatients(patients);

    closePatModal();

    showPatientList();

  });

});

// ─── AUTONOMIE-LOG ────────────────────────────────────────────────────────────

function initAL(){var log=getALLog();if(!log){log=[{id:'al001',ts:new Date().toISOString(),title:'System gestartet',desc:'LifeOS mit strukturellen Fixes initialisiert.',badge:'\u2705',read:false}];saveALLog(log);}}

function renderAL(){var list=document.getElementById('al-list');if(!list)return;var log=getALLog()||[];var unread=log.filter(function(e){return !e.read;}).length;var badge=document.getElementById('al-badge');if(badge){if(unread>0){badge.style.display='';badge.textContent=unread;}else{badge.style.display='none';}}if(log.length===0){list.innerHTML='<div class="empty-state">Keine Eintr\u00e4ge.</div>';return;}list.innerHTML=log.map(function(e){return '<div class="al-card'+(e.read?' read':'')+'" id="alc-'+e.id+'"><div class="al-card-header"><span class="al-badge">'+(e.badge||'\uD83D\uDCCB')+'</span><div class="al-meta"><div class="al-title">'+esc(e.title)+'</div><div class="al-ts">'+new Date(e.ts).toLocaleString('de-CH')+'</div></div></div><div class="al-desc">'+esc(e.desc||'')+'</div>'+(!e.read?'<button class="al-read-btn" onclick="markALRead(\''+e.id+'\')">Okay, gelesen \u2713</button>':'<button class="al-read-btn">Gelesen \u2713</button>')+'</div>';}).join('');}

function markALRead(id){var log=getALLog()||[];var entry=log.find(function(e){return e.id===id;});if(entry)entry.read=true;saveALLog(log);renderAL();updateALBadge();}

function updateALBadge(){var badge=document.getElementById('al-badge');if(!badge)return;var log=getALLog()||[];var unread=log.filter(function(e){return !e.read;}).length;if(unread>0){badge.style.display='';badge.textContent=unread;}else badge.style.display='none';}



// ─── BACKLOG ──────────────────────────────────────────────────────────────────



// ─── EINSTELLUNGEN ────────────────────────────────────────────────────────────

function initSettings(){var settings=ls('cowork_settings',{});var token=settings.gh_token||ls('cowork_gh_token','')||localStorage.getItem('cowork_gh_token')||'';document.getElementById('gh-token-input').value=token;if(!_appState.gh_token&&token){_appState.gh_token=token;}document.getElementById('budget-input').value=settings.budget||ls('cowork_budget',100);document.getElementById('enc-status').textContent=_encKey?'PIN-Verschl\u00fcsselung aktiv (PBKDF2)':'Kein Key \u2014 Patientendaten unverschl\u00fcsselt';}

(function(){var saved=localStorage.getItem('cowork_gh_token');if(saved&&!_appState.gh_token){_appState.gh_token=saved;}})();

document.getElementById('btn-gh-save').addEventListener('click',async function(){var v=document.getElementById('gh-token-input').value.trim();lsSet('cowork_gh_token',v);localStorage.setItem('cowork_gh_token',v);_appState.gh_token=v;var pin=sessionStorage.getItem('cowork_pin_val');if(pin)await storeSecureVault(pin);if(v){try{await safeWriteToGitHub('settings/config.json',JSON.stringify({updated:new Date().toISOString()},null,2),'sync: update config');showToast('\u2705 Token gespeichert & verschl\u00fcsselt');}catch(e){showToast('\u2705 Token lokal gespeichert');}}else{showToast('\u2705 Token gespeichert');}});

document.getElementById('btn-budget-save').addEventListener('click',function(){var v=parseInt(document.getElementById('budget-input').value)||100;lsSet('cowork_budget',v);showToast('\u2705 Budget gespeichert');if(currentTab==='heute')renderHeute();});

document.getElementById('btn-pin-change').addEventListener('click',async function(){var val=document.getElementById('new-pin-input').value.trim();if(val.length<4||val.length>6||!/^\d+$/.test(val)){showToast('PIN muss 4\u20136 Ziffern sein',true);return;}
// Re-encrypt patients with new PIN-derived key before changing PIN
try{
  var oldKey=_encKey;
  var newKey=await deriveKeyFromPin(val,'lifeos-patient-enc');
  // Load current patients (already decrypted in _appState)
  var patients=_appState.patients;
  if(Array.isArray(patients)&&patients.length>0){
    // Switch to new key and save
    _encKey=newKey;
    await savePatientsToGitHub();
    console.log('[PIN-change] Patienten mit neuem Key re-encrypted');
  }else{
    _encKey=newKey;
  }
  // Now update PIN hash and session
  var newHash=hashPin(val);_appState.pin_hash=newHash;
  sessionStorage.setItem('cowork_pin_set','true');
  sessionStorage.setItem('cowork_pin_val',val);
  var pin=val;if(pin)await storeSecureVault(pin);
  document.getElementById('new-pin-input').value='';
  await safeWriteToGitHub('settings/pin.json',JSON.stringify({pin_hash:newHash},null,2),'sync: update PIN');
  showToast('\u2705 PIN ge\u00e4ndert & Patienten re-encrypted');
}catch(e){
  console.error('[PIN-change]',e);
  showToast('\u274c PIN-\u00c4nderung fehlgeschlagen: '+e.message,true);
}});

// Encryption key buttons disabled — key is now auto-derived from PIN (PBKDF2)
if(document.getElementById('btn-enc-save'))document.getElementById('btn-enc-save').addEventListener('click',function(){showToast('Key wird automatisch aus PIN abgeleitet');});
if(document.getElementById('btn-enc-generate'))document.getElementById('btn-enc-generate').addEventListener('click',function(){showToast('Key wird automatisch aus PIN abgeleitet');});

document.getElementById('btn-export').addEventListener('click',function(){var data={cards:ls('cowork_cards',{}),patients:ls('cowork_patients',[]),autonomy:ls('cowork_autonomy_log',[]),seqs:_appState.seqs,exportedAt:new Date().toISOString()};var blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});var url=URL.createObjectURL(blob);var a=document.createElement('a');a.href=url;a.download='cowork-export-'+new Date().toISOString().slice(0,10)+'.json';a.click();URL.revokeObjectURL(url);});

document.getElementById('btn-import').addEventListener('click',function(){document.getElementById('import-file').click();});

document.getElementById('import-file').addEventListener('change',function(e){var file=e.target.files[0];if(!file)return;var reader=new FileReader();reader.onload=function(ev){try{var data=JSON.parse(ev.target.result);if(data.cards)lsSet('cowork_cards',data.cards);if(data.patients)lsSet('cowork_patients',data.patients);if(data.autonomy)lsSet('cowork_autonomy_log',data.autonomy);showToast('Daten importiert');switchTab(currentTab);}catch(err){showToast('Fehler beim Importieren',true);}};reader.readAsText(file);e.target.value='';});

document.getElementById('btn-reset').addEventListener('click',function(){confirmAction('Alle Daten l\u00f6schen?','ALLE Karten, Patienten und Logs werden gel\u00f6scht.',function(){_appState.cards={};_appState.cards_savedAt=null;_appState.patients=[];_appState.autonomy_log=null;_appState.collapsed={};_appState.budget=100;LANES.forEach(function(l){_appState.seqs[l.id]=0;});if(getGHToken()){scheduleSyncToGitHub();scheduleSettingsToGitHub();}showToast('Alle Daten gel\u00f6scht');switchTab('heute');});});



// ─── CONFIRM / TOAST ──────────────────────────────────────────────────────────

var confirmCallback=null;

function confirmAction(title,msg,cb){document.getElementById('confirm-title').textContent=title;document.getElementById('confirm-msg').textContent=msg;confirmCallback=cb;document.getElementById('confirm-overlay').classList.add('open');}

document.getElementById('confirm-no').addEventListener('click',function(){document.getElementById('confirm-overlay').classList.remove('open');confirmCallback=null;});

document.getElementById('confirm-yes').addEventListener('click',function(){document.getElementById('confirm-overlay').classList.remove('open');if(confirmCallback){confirmCallback();confirmCallback=null;}});

var toastTimer=null;

function showToast(msg,isError){var t=document.getElementById('toast');if(!t){t=document.createElement('div');t.id='toast';t.style.cssText='position:fixed;bottom:24px;right:24px;padding:10px 18px;border-radius:8px;font-size:13px;font-weight:500;z-index:9999;transition:opacity 0.3s;';document.body.appendChild(t);}t.textContent=msg;t.style.background=isError?'#ef4444':'#1a1a1a';t.style.color='#fff';t.style.opacity='1';clearTimeout(toastTimer);toastTimer=setTimeout(function(){t.style.opacity='0';},2500);}



// ─── PROJEKTE ─────────────────────────────────────────────────────────────────

var _localProjectsMeta={};

async function loadProjects(){var token=getGHToken();if(!token)return null;try{var r=await fetch(GH_API_BASE+'/repos/'+GH_DATA_REPO+'/contents/projects',{headers:{Authorization:'token '+token,Accept:'application/vnd.github.v3+json'}});if(r.status===404)return[];if(!r.ok)return null;var items=await r.json();return items.filter(function(i){return i.type==='dir';}).map(function(i){return i.name;});}catch(e){console.error('[loadProjects]',e);return null;}}

async function loadProjectMeta(id){var result=await fetchFromGitHub('projects/'+id+'/meta.json');if(!result)return null;try{return JSON.parse(result.content);}catch(e){return null;}}

async function loadProjectLog(id){var result=await fetchFromGitHub('projects/'+id+'/log.md');if(!result)return{content:'',sha:null};return result;}

async function saveProject(meta){await safeWriteToGitHub('projects/'+meta.id+'/meta.json',JSON.stringify(meta,null,2),'project: save '+meta.name);_localProjectsMeta[meta.id]=meta;var existingLog=await fetchFromGitHub('projects/'+meta.id+'/log.md');if(!existingLog){await safeWriteToGitHub('projects/'+meta.id+'/log.md','','project: init log for '+meta.name);}}

function migrateLogToEntries(logContent){
if(!logContent||!logContent.trim())return[];
var parts=logContent.split(/\n---\n/).filter(function(p){return p.trim();});
var entries=[];
for(var i=0;i<parts.length;i++){
var p=parts[i].replace(/^---\n/,'').trim();if(!p)continue;
var m=p.match(/^\*\*\[(\d{2}\.\d{2}\.\d{4})\s+(\d{2}:\d{2})\]\*\*\s*([\s\S]*)/);
if(m){var dp=m[1].split('.');var iso=dp[2]+'-'+dp[1]+'-'+dp[0]+'T'+m[2]+':00';
entries.push({id:'e'+Date.now().toString(36)+i,text:m[3].trim(),createdAt:new Date(iso).toISOString(),deleted:false});
}else{entries.push({id:'e'+Date.now().toString(36)+i,text:p,createdAt:new Date().toISOString(),deleted:false});}
}return entries;}

async function addProjectEntry(projectId,text){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta)return;
if(!meta.entries)meta.entries=[];
meta.entries.unshift({id:'e'+Date.now().toString(36),text:text,createdAt:new Date().toISOString(),deleted:false});
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

async function editProjectEntry(projectId,entryId,newText){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta||!meta.entries)return;
var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
entry.text=newText;entry.updatedAt=new Date().toISOString();
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

async function deleteProject(projectId,projectName){
confirmAction('Projekt in Papierkorb?','\"'+projectName+'\" kann im Papierkorb wiederhergestellt werden.',async function(){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta)return;
meta.deleted=true;meta.deletedAt=new Date().toISOString();meta.updatedAt=new Date().toISOString();
await saveProject(meta);showToast('In Papierkorb verschoben');showProjectsTab();});}

async function restoreProject(projectId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta)return;
meta.deleted=false;delete meta.deletedAt;meta.updatedAt=new Date().toISOString();
await saveProject(meta);showToast('Wiederhergestellt');showProjectsTab();}

async function archiveProject(projectId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta)return;
meta.status='archiviert';meta.updatedAt=new Date().toISOString();
await saveProject(meta);showToast('Archiviert');showProjectsTab();}

async function deleteProjectEntry(projectId,entryId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta||!meta.entries)return;
var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
entry.deleted=true;entry.deletedAt=new Date().toISOString();
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

async function restoreProjectEntry(projectId,entryId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta||!meta.entries)return;
var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
entry.deleted=false;delete entry.deletedAt;
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

async function archiveProjectEntry(projectId,entryId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta||!meta.entries)return;
var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
entry.archived=true;entry.archivedAt=new Date().toISOString();
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

async function unarchiveProjectEntry(projectId,entryId){
var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);if(!meta||!meta.entries)return;
var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
entry.archived=false;delete entry.archivedAt;
meta.updatedAt=new Date().toISOString();
await saveProject(meta);}

// ─── SIMPLE MARKDOWN ─────────────────────────────────────────────────────────

function parseSimpleMarkdown(text){
  if(!text)return'';
  var lines=text.split('\n');var html='';var inUl=false;var inOl=false;
  for(var i=0;i<lines.length;i++){
    var raw=lines[i];var line=esc(raw);
    // close open lists if line is not a list item
    if(inUl&&!/^\s*- /.test(raw)){html+='</ul>';inUl=false;}
    if(inOl&&!/^\s*\d+\.\s/.test(raw)){html+='</ol>';inOl=false;}
    // inline formatting
    line=line.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>');
    line=line.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g,'<em>$1</em>');
    line=line.replace(/\[([^\]]+)\]\(((?:https?:|mailto:)[^\)]+)\)/g,'<a href="$2" target="_blank" rel="noopener">$1</a>');
    // block formatting
    if(/^### /.test(raw)){html+='<h3>'+line.substring(4)+'</h3>';}
    else if(/^## /.test(raw)){html+='<h2>'+line.substring(3)+'</h2>';}
    else if(/^# /.test(raw)){html+='<h1>'+line.substring(2)+'</h1>';}
    else if(/^\s*- /.test(raw)){if(!inUl){html+='<ul>';inUl=true;}html+='<li>'+line.replace(/^\s*-\s/,'')+'</li>';}
    else if(/^\s*\d+\.\s/.test(raw)){if(!inOl){html+='<ol>';inOl=true;}html+='<li>'+line.replace(/^\s*\d+\.\s/,'')+'</li>';}
    else if(line.trim()===''){html+='<br>';}
    else{html+='<p>'+line+'</p>';}
  }
  if(inUl)html+='</ul>';if(inOl)html+='</ol>';
  return html;
}

function renderMarkdownToolbar(textareaId){
  return '<div class="md-toolbar">'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'bold\')" title="Fett"><b>B</b></button>'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'italic\')" title="Kursiv"><i>I</i></button>'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'h2\')" title="Überschrift">H2</button>'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'h3\')" title="Unter-Überschrift">H3</button>'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'ul\')" title="Liste">&#8226;</button>'
    +'<button type="button" class="md-toolbar-btn" onclick="insertMarkdown(\''+textareaId+'\',\'link\')" title="Link">&#128279;</button>'
    +'<button type="button" class="md-toolbar-btn" onclick="toggleMarkdownPreview(\''+textareaId+'\')" title="Vorschau">&#128065;</button>'
    +'</div>';
}

function insertMarkdown(textareaId,type){
  var ta=document.getElementById(textareaId);if(!ta)return;
  var s=ta.selectionStart;var e=ta.selectionEnd;var txt=ta.value;var sel=txt.substring(s,e)||'Text';
  var before=txt.substring(0,s);var after=txt.substring(e);var insert='';var cursorOffset=0;
  switch(type){
    case'bold':insert='**'+sel+'**';cursorOffset=2;break;
    case'italic':insert='*'+sel+'*';cursorOffset=1;break;
    case'h2':insert='\n## '+sel;cursorOffset=4;break;
    case'h3':insert='\n### '+sel;cursorOffset=5;break;
    case'ul':insert='\n- '+sel;cursorOffset=3;break;
    case'link':var url=prompt('URL eingeben:','https://');if(!url)return;insert='['+sel+']('+url+')';cursorOffset=1;break;
    default:return;
  }
  ta.value=before+insert+after;ta.focus();
  var newPos=s+insert.length;ta.setSelectionRange(newPos,newPos);
}

function toggleMarkdownPreview(textareaId){
  var previewId='preview-'+textareaId;var preview=document.getElementById(previewId);
  var ta=document.getElementById(textareaId);if(!ta||!preview)return;
  if(preview.style.display==='none'||!preview.style.display){
    preview.innerHTML=parseSimpleMarkdown(ta.value);preview.style.display='block';
  }else{preview.style.display='none';}
}

// ─── DRAG AND DROP (Project Entries) ─────────────────────────────────────────

function initEntryDragDrop(projectId){
  var container=document.getElementById('pjd-entries-list');if(!container)return;
  var cards=container.querySelectorAll('.proj-entry-card');
  if(cards.length<2)return;
  var _draggedId=null;var _touchStartY=0;var _touchCard=null;var _isDragging=false;

  // Desktop DnD
  cards.forEach(function(card){
    card.setAttribute('draggable','true');
    card.addEventListener('dragstart',function(ev){
      if(!ev.target.closest('.proj-entry-drag-handle'))return ev.preventDefault();
      _draggedId=card.dataset.entryId;
      card.classList.add('proj-entry-dragging');
      ev.dataTransfer.effectAllowed='move';
      ev.dataTransfer.setData('text/plain',_draggedId);
    });
    card.addEventListener('dragend',function(){
      card.classList.remove('proj-entry-dragging');
      _draggedId=null;clearDropIndicators(container);
    });
    card.addEventListener('dragover',function(ev){
      ev.preventDefault();ev.dataTransfer.dropEffect='move';
      if(card.dataset.entryId===_draggedId)return;
      clearDropIndicators(container);
      var rect=card.getBoundingClientRect();
      if(ev.clientY<rect.top+rect.height/2){card.classList.add('proj-entry-drop-above');}
      else{card.classList.add('proj-entry-drop-below');}
    });
    card.addEventListener('dragleave',function(){card.classList.remove('proj-entry-drop-above','proj-entry-drop-below');});
    card.addEventListener('drop',function(ev){
      ev.preventDefault();
      var targetId=card.dataset.entryId;if(!_draggedId||_draggedId===targetId)return;
      var rect=card.getBoundingClientRect();var insertBefore=ev.clientY<rect.top+rect.height/2;
      clearDropIndicators(container);
      reorderEntry(projectId,_draggedId,targetId,insertBefore);
    });
  });

  // Touch DnD
  container.addEventListener('touchstart',function(ev){
    var handle=ev.target.closest('.proj-entry-drag-handle');if(!handle)return;
    var card=handle.closest('.proj-entry-card');if(!card)return;
    _touchCard=card;_touchStartY=ev.touches[0].clientY;_isDragging=false;
    _draggedId=card.dataset.entryId;
  },{passive:true});

  container.addEventListener('touchmove',function(ev){
    if(!_touchCard||!_draggedId)return;
    var dy=Math.abs(ev.touches[0].clientY-_touchStartY);
    if(dy>15&&!_isDragging){_isDragging=true;_touchCard.classList.add('proj-entry-dragging');}
    if(!_isDragging)return;
    ev.preventDefault();
    clearDropIndicators(container);
    var elem=document.elementFromPoint(ev.touches[0].clientX,ev.touches[0].clientY);
    if(!elem)return;
    var target=elem.closest('.proj-entry-card');
    if(target&&target.dataset.entryId!==_draggedId){
      var rect=target.getBoundingClientRect();
      if(ev.touches[0].clientY<rect.top+rect.height/2){target.classList.add('proj-entry-drop-above');}
      else{target.classList.add('proj-entry-drop-below');}
    }
  },{passive:false});

  container.addEventListener('touchend',function(ev){
    if(!_isDragging||!_draggedId){_touchCard=null;_draggedId=null;_isDragging=false;return;}
    _touchCard.classList.remove('proj-entry-dragging');
    var target=container.querySelector('.proj-entry-drop-above,.proj-entry-drop-below');
    if(target){
      var insertBefore=target.classList.contains('proj-entry-drop-above');
      var targetId=target.dataset.entryId;
      clearDropIndicators(container);
      if(targetId!==_draggedId)reorderEntry(projectId,_draggedId,targetId,insertBefore);
    }else{clearDropIndicators(container);}
    _touchCard=null;_draggedId=null;_isDragging=false;
  },{passive:true});
}

function clearDropIndicators(container){
  container.querySelectorAll('.proj-entry-drop-above,.proj-entry-drop-below').forEach(function(el){
    el.classList.remove('proj-entry-drop-above','proj-entry-drop-below');
  });
}

async function reorderEntry(projectId,draggedId,targetId,insertBefore){
  var meta=_localProjectsMeta[projectId]||await loadProjectMeta(projectId);
  if(!meta||!meta.entries)return;
  var entries=meta.entries;
  var dragIdx=entries.findIndex(function(e){return e.id===draggedId;});
  if(dragIdx===-1)return;
  var dragged=entries.splice(dragIdx,1)[0];
  var targetIdx=entries.findIndex(function(e){return e.id===targetId;});
  if(targetIdx===-1){entries.push(dragged);}
  else{entries.splice(insertBefore?targetIdx:targetIdx+1,0,dragged);}
  meta.entries=entries;meta.updatedAt=new Date().toISOString();
  await saveProject(meta);showProjectDetail(projectId);
}

async function showProjectsTab(){

  var container=document.getElementById('projekte-view');var token=getGHToken();

  var hdr='<div class="proj-header"><h2>Projekte</h2><button class="btn-primary" onclick="openCreateProjectModal()">+ Neues Projekt</button></div>';

  if(!token){container.innerHTML=hdr+'<div class="empty-state">Bitte GitHub Token eintragen.</div>';return;}

  container.innerHTML=hdr+'<div style="text-align:center;padding:32px;color:var(--text-muted);font-size:13px">Lade Projekte\u2026</div>';

  try{

    var ghIds=await loadProjects();if(ghIds===null){container.innerHTML=hdr+'<div class="empty-state">Fehler beim Laden.</div>';return;}

    var localOnly=Object.keys(_localProjectsMeta).filter(function(id){return !ghIds.includes(id);});var pIds=ghIds.concat(localOnly);

    if(pIds.length===0){container.innerHTML=hdr+'<div class="empty-state">Noch keine Projekte.</div>';return;}

    var metas=await Promise.all(pIds.map(function(id){return _localProjectsMeta[id]?Promise.resolve(_localProjectsMeta[id]):loadProjectMeta(id);}));

    var logs=await Promise.all(pIds.map(function(id){return loadProjectLog(id);}));

    var statusColors={aktiv:'#22c55e',pausiert:'#eab308',abgeschlossen:'#22c55e',archiviert:'#555'};

    // Sort by saved order
    var savedOrder=JSON.parse(localStorage.getItem('projOrder')||'[]');
    var activeList=[];var deletedList=[];
    pIds.forEach(function(id,i){var meta=metas[i];if(!meta)return;if(meta.deleted){deletedList.push({id:id,meta:meta,log:logs[i]});}else{activeList.push({id:id,meta:meta,log:logs[i]});}});
    if(savedOrder.length>0){activeList.sort(function(a,b){var ai=savedOrder.indexOf(a.id);var bi=savedOrder.indexOf(b.id);if(ai===-1)ai=9999;if(bi===-1)bi=9999;return ai-bi;});}

    var activeCards='';var deletedCards='';

    activeList.forEach(function(item){var id=item.id;var meta=item.meta;var lc=(item.log&&item.log.content)||'';var fl=lc.split('\n').map(function(l){return l.trim();}).find(function(l){return l&&l!=='---'&&!l.startsWith('**[');})||'';
    var sc=meta.statusColor||statusColors[meta.status]||'#22c55e';
    var circleTitle=meta.statusText?(' title="'+esc(meta.statusText)+'"'):'';
    var statusCircle='<span class="proj-status-circle" style="background:'+esc(sc)+'"'+circleTitle+'></span>';
    activeCards+='<div class="proj-card" draggable="true" data-proj-id="'+esc(id)+'" onclick="showProjectDetail(\''+esc(id)+'\')">'+'<div class="proj-card-color-bar" style="background:'+esc(sc)+'"></div>'+'<div class="proj-card-name-row">'+statusCircle+'<span class="proj-card-name">'+esc(meta.name||id)+'</span></div>'+(meta.description?'<div class="proj-card-desc">'+esc(meta.description)+'</div>':'')+(fl?'<div class="proj-card-log">'+esc(fl)+'</div>':'')+'</div>';});

    deletedList.forEach(function(item){var id=item.id;var meta=item.meta;
    var sc=meta.statusColor||statusColors[meta.status]||'#22c55e';
    var circleTitle=meta.statusText?(' title="'+esc(meta.statusText)+'"'):'';
    var statusCircle='<span class="proj-status-circle" style="background:'+esc(sc)+'"'+circleTitle+'></span>';
    deletedCards+='<div class="proj-card proj-card-deleted">'+'<div class="proj-card-color-bar" style="background:'+esc(sc)+'"></div>'+'<div class="proj-card-name-row">'+statusCircle+'<span class="proj-card-name">'+esc(meta.name||id)+'</span></div>'+(meta.description?'<div class="proj-card-desc">'+esc(meta.description)+'</div>':'')+'<button class="proj-card-restore" onclick="event.stopPropagation();restoreProject(\''+esc(id)+'\')">Wiederherstellen</button></div>';});

    var trashHtml=deletedCards?'<div class="proj-trash-section"><details><summary class="proj-trash-toggle">Papierkorb</summary><div class="proj-grid" style="margin-top:12px">'+deletedCards+'</div></details></div>':'';
    container.innerHTML=hdr+'<div class="proj-grid" id="proj-grid-active">'+activeCards+'</div>'+trashHtml;
    initProjectDragDrop();

  }catch(e){container.innerHTML=hdr+'<div class="empty-state">Fehler: '+esc(e.message)+'</div>';}

}



function initProjectDragDrop(){
  var grid=document.getElementById('proj-grid-active');if(!grid)return;
  var dragEl=null;
  grid.addEventListener('dragstart',function(e){
    var card=e.target.closest('.proj-card[data-proj-id]');if(!card)return;
    dragEl=card;card.classList.add('proj-card-dragging');
    e.dataTransfer.effectAllowed='move';
    e.dataTransfer.setData('text/plain',card.dataset.projId);
  });
  grid.addEventListener('dragend',function(e){
    if(dragEl)dragEl.classList.remove('proj-card-dragging');
    grid.querySelectorAll('.proj-card-dragover').forEach(function(c){c.classList.remove('proj-card-dragover');});
    dragEl=null;
  });
  grid.addEventListener('dragover',function(e){
    e.preventDefault();e.dataTransfer.dropEffect='move';
    var target=e.target.closest('.proj-card[data-proj-id]');
    grid.querySelectorAll('.proj-card-dragover').forEach(function(c){c.classList.remove('proj-card-dragover');});
    if(target&&target!==dragEl)target.classList.add('proj-card-dragover');
  });
  grid.addEventListener('drop',function(e){
    e.preventDefault();
    var target=e.target.closest('.proj-card[data-proj-id]');
    if(!target||!dragEl||target===dragEl)return;
    var cards=Array.from(grid.querySelectorAll('.proj-card[data-proj-id]'));
    var fromIdx=cards.indexOf(dragEl);var toIdx=cards.indexOf(target);
    if(fromIdx<toIdx){target.after(dragEl);}else{target.before(dragEl);}
    var newOrder=Array.from(grid.querySelectorAll('.proj-card[data-proj-id]')).map(function(c){return c.dataset.projId;});
    localStorage.setItem('projOrder',JSON.stringify(newOrder));
  });
}

async function showProjectDetail(projectId){
  var container=document.getElementById('projekte-view');
  container.innerHTML='<div style="padding:32px;text-align:center;color:var(--text-muted)">Lade\u2026</div>';
  try{
    var meta=await loadProjectMeta(projectId);if(!meta){container.innerHTML='<div class="empty-state">Nicht gefunden.</div>';return;}

    // Migration: log.md -> entries[] (einmalig)
    if(!meta.entries||meta.entries.length===0){
      var logData=await loadProjectLog(projectId);var logContent=(logData&&logData.content)||'';
      if(logContent.trim()){meta.entries=migrateLogToEntries(logContent);meta.updatedAt=new Date().toISOString();await saveProject(meta);}
      else{meta.entries=[];}
    }

    var cards=getCards();var linked=(meta.kanbanCards||[]).map(function(id){return cards[id];}).filter(Boolean);
    var defaultStatusColors={aktiv:'#22c55e',pausiert:'#eab308',abgeschlossen:'#22c55e',archiviert:'#555'};
    var cb=meta.color?' style="border-top:4px solid '+esc(meta.color)+'"':'';

    var activeEntries=(meta.entries||[]).filter(function(e){return !e.deleted&&!e.archived;});
    activeEntries.sort(function(a,b){return new Date(b.updatedAt||b.createdAt)-new Date(a.updatedAt||a.createdAt);});
    var archivedEntries=(meta.entries||[]).filter(function(e){return e.archived&&!e.deleted;});
    var deletedEntries=(meta.entries||[]).filter(function(e){return e.deleted;});

    function fmtDateDE(iso){var d=new Date(iso);var dd=String(d.getDate()).padStart(2,'0');var mm=String(d.getMonth()+1).padStart(2,'0');var yy=d.getFullYear();var hh=String(d.getHours()).padStart(2,'0');var mi=String(d.getMinutes()).padStart(2,'0');return dd+'.'+mm+'.'+yy+' '+hh+':'+mi;}

    var _svgEdit='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>';
    var _svgArchive='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>';
    var _svgTrash='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>';
    var _svgRestore='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>';

    function renderEntryCard(e,mode){
      var lines=e.text.split('\n').filter(function(l){return l.trim();});
      var title=lines[0]||'(Kein Titel)';
      title=title.replace(/^#+\s*/,'').replace(/^\*\*(.*)\*\*$/,'$1');
      var previewLines=lines.slice(1,6).join('\n');
      var displayDate=e.updatedAt||e.createdAt;
      var dateLabel=e.updatedAt?'Bearbeitet':'Erstellt';

      if(mode==='active'){
        var html='<div class="proj-entry-card" data-entry-id="'+esc(e.id)+'" data-expanded="false">';
        html+='<span class="proj-entry-drag-handle" title="Verschieben">&#x2630;</span>';
        html+='<div class="proj-entry-body">';
        html+='<div class="proj-entry-top" onclick="toggleProjectEntryExpand(this.closest(\'.proj-entry-card\'))">';
        html+='<span class="proj-entry-title">'+esc(title)+'</span>';
        html+='<span class="proj-entry-date">'+dateLabel+': '+fmtDateDE(displayDate)+'</span></div>';
        if(previewLines){html+='<div class="proj-entry-preview" onclick="toggleProjectEntryExpand(this.closest(\'.proj-entry-card\'))">'+esc(previewLines)+'</div>';}
        html+='<div class="proj-entry-full proj-entry-md">'+parseSimpleMarkdown(e.text)+'</div>';
        html+='<div class="proj-entry-actions">';
        html+='<button class="proj-entry-btn proj-entry-edit" onclick="event.stopPropagation();startEditProjectEntry(\''+esc(projectId)+'\',\''+esc(e.id)+'\')" title="Bearbeiten">'+_svgEdit+' Bearbeiten</button>';
        html+='<button class="proj-entry-btn proj-entry-archive" onclick="event.stopPropagation();(async function(){await archiveProjectEntry(\''+esc(projectId)+'\',\''+esc(e.id)+'\');showToast(\'Archiviert\');showProjectDetail(\''+esc(projectId)+'\');})()" title="Archivieren">'+_svgArchive+' Archivieren</button>';
        html+='<button class="proj-entry-btn proj-entry-del" onclick="event.stopPropagation();(async function(){await deleteProjectEntry(\''+esc(projectId)+'\',\''+esc(e.id)+'\');showToast(\'In Papierkorb verschoben\');showProjectDetail(\''+esc(projectId)+'\');})()" title="L\u00f6schen">'+_svgTrash+' L\u00f6schen</button>';
        html+='</div></div></div>';
        return html;
      }
      // Fallback for trash/archived
      var html='<div class="proj-entry-card" data-entry-id="'+esc(e.id)+'" style="padding:10px 14px;margin-bottom:6px;cursor:default">';
      html+='<div class="proj-entry-body">';
      html+='<div class="proj-entry-top"><span class="proj-entry-title" style="font-size:13px">'+esc(title)+'</span>';
      html+='<span class="proj-entry-date">'+dateLabel+': '+fmtDateDE(displayDate)+'</span></div>';
      html+='<div class="proj-entry-text proj-entry-md" style="font-size:12px;opacity:0.7;margin-top:4px">'+parseSimpleMarkdown(e.text)+'</div>';
      html+='<div style="display:flex;gap:6px;margin-top:8px">';
      if(mode==='trash'){html+='<button class="proj-entry-btn proj-entry-restore" onclick="(async function(){await restoreProjectEntry(\''+esc(projectId)+'\',\''+esc(e.id)+'\');showToast(\'Wiederhergestellt\');showProjectDetail(\''+esc(projectId)+'\');})()" title="Wiederherstellen">'+_svgRestore+' Wiederherstellen</button>';}
      else if(mode==='archived'){html+='<button class="proj-entry-btn proj-entry-restore" onclick="(async function(){await unarchiveProjectEntry(\''+esc(projectId)+'\',\''+esc(e.id)+'\');showToast(\'Wiederhergestellt\');showProjectDetail(\''+esc(projectId)+'\');})()" title="Wiederherstellen">'+_svgRestore+' Wiederherstellen</button>';}
      html+='</div></div></div>';
      return html;
    }

    var entriesHtml='';
    if(activeEntries.length===0){entriesHtml='<div style="font-size:13px;color:var(--text-muted)">Noch keine Eintr\u00e4ge.</div>';}
    else{entriesHtml='<div class="proj-entries-list">';for(var i=0;i<activeEntries.length;i++){entriesHtml+=renderEntryCard(activeEntries[i],'active');}entriesHtml+='</div>';}

    var archiveHtml='';
    if(archivedEntries.length>0){
      archiveHtml='<div class="proj-entry-archive"><details><summary class="proj-entry-archive-toggle">\ud83d\udce6 Archiv ('+archivedEntries.length+')</summary><div class="proj-entry-archive-list">';
      for(var k=0;k<archivedEntries.length;k++){archiveHtml+=renderEntryCard(archivedEntries[k],'archived');}
      archiveHtml+='</div></details></div>';
    }

    var trashHtml='';
    if(deletedEntries.length>0){
      trashHtml='<div class="proj-entry-trash"><details><summary class="proj-entry-trash-toggle">\ud83d\uddd1 Papierkorb ('+deletedEntries.length+')</summary><div class="proj-entry-trash-list">';
      for(var j=0;j<deletedEntries.length;j++){trashHtml+=renderEntryCard(deletedEntries[j],'trash');}
      trashHtml+='</div></details></div>';
    }

    var detailSc=meta.statusColor||defaultStatusColors[meta.status]||'#22c55e';
    var detailCircleTitle=meta.statusText?(' title="'+esc(meta.statusText)+'"'):'';
    container.innerHTML='<div class="proj-detail-header"><button class="proj-detail-back" onclick="showProjectsTab()">\u2190 Zur\u00fcck</button><span class="proj-status-circle proj-status-circle-lg" style="background:'+esc(detailSc)+'"'+detailCircleTitle+'></span><span class="proj-detail-name">'+esc(meta.name||projectId)+'</span><div style="margin-left:auto;display:flex;gap:8px"><button class="proj-action-btn" onclick="deleteProject(\''+esc(projectId)+'\',\''+esc(meta.name||projectId)+'\')" title="In Papierkorb" style="font-size:16px">\ud83d\uddd1</button></div></div>'
      +'<div class="proj-section section-info"'+cb+'><h3>Info</h3><div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;align-items:flex-end"><div><label class="form-label">Name</label><input type="text" class="form-input" id="pjd-name" value="'+esc(meta.name||'')+'" style="width:auto;min-width:200px"></div><div><label class="form-label">Status-Farbe</label><div class="proj-sc-picker" id="pjd-sc-picker"><span class="proj-sc-opt'+(detailSc==='#22c55e'?' selected':'')+'" data-color="#22c55e" style="background:#22c55e" onclick="pickProjSc(this)"></span><span class="proj-sc-opt'+(detailSc==='#eab308'?' selected':'')+'" data-color="#eab308" style="background:#eab308" onclick="pickProjSc(this)"></span><span class="proj-sc-opt'+(detailSc==='#ef4444'?' selected':'')+'" data-color="#ef4444" style="background:#ef4444" onclick="pickProjSc(this)"></span><span class="proj-sc-opt'+(detailSc==='#555'?' selected':'')+'" data-color="#555" style="background:#555" onclick="pickProjSc(this)"></span></div></div><div><label class="form-label">Status-Text (Hover)</label><input type="text" class="form-input" id="pjd-status-text" value="'+esc(meta.statusText||'')+'" placeholder="z.B. Aktiv, Pausiert\u2026" style="width:auto;min-width:140px"></div></div><button class="btn-primary" id="pjd-save-btn">Speichern</button><span id="pjd-save-status" style="font-size:12px;color:var(--text-muted);margin-left:10px"></span></div>'
      +(meta.description?'<div class="proj-section"><h3>Beschreibung</h3><div class="proj-description">'+esc(meta.description)+'</div></div>':'')
      +'<div class="proj-section section-entries"><h3>Beitr\u00e4ge</h3><div class="proj-log-form">'+renderMarkdownToolbar('pjd-log-entry')+'<textarea class="proj-log-input" id="pjd-log-entry" placeholder="Neuer Eintrag\u2026"></textarea><div class="md-preview" id="preview-pjd-log-entry" style="display:none"></div><button class="btn-primary" id="pjd-log-btn">Hinzuf\u00fcgen</button></div><div id="pjd-entries-list" style="margin-top:16px">'+entriesHtml+'</div>'+archiveHtml+trashHtml+'</div>'
      +'<div class="proj-section section-links"><h3>Verkn\u00fcpfte Karten</h3>'+(linked.length===0?'<div style="font-size:13px;color:var(--text-muted)">Keine</div>':'<div class="proj-kanban-chips">'+linked.map(function(c){return '<span class="proj-kanban-chip"><strong>'+esc(c.id)+'</strong> '+esc(c.title||'')+'</span>';}).join('')+'</div>')+'</div>';

    document.getElementById('pjd-save-btn').addEventListener('click',async function(){var btn=document.getElementById('pjd-save-btn');var st=document.getElementById('pjd-save-status');var nn=document.getElementById('pjd-name').value.trim();if(!nn){showToast('Name darf nicht leer sein',true);return;}var scEl=document.querySelector('.proj-sc-opt.selected');var nsc=scEl?scEl.dataset.color:'#22c55e';var nst=document.getElementById('pjd-status-text').value.trim();btn.disabled=true;st.textContent='Speichert\u2026';try{await saveProject(Object.assign({},meta,{name:nn,statusColor:nsc,statusText:nst||'',updatedAt:new Date().toISOString()}));st.textContent='Gespeichert \u2713';showToast('Projekt gespeichert');setTimeout(function(){if(st)st.textContent='';},3000);}catch(e){showToast('Fehler',true);st.textContent='';}btn.disabled=false;});

    document.getElementById('pjd-log-btn').addEventListener('click',async function(){var btn=document.getElementById('pjd-log-btn');var text=document.getElementById('pjd-log-entry').value.trim();if(!text){document.getElementById('pjd-log-entry').focus();return;}btn.disabled=true;btn.textContent='Speichert\u2026';try{await addProjectEntry(projectId,text);document.getElementById('pjd-log-entry').value='';showToast('Eintrag hinzugef\u00fcgt');showProjectDetail(projectId);}catch(e){showToast('Fehler',true);}btn.disabled=false;btn.textContent='Hinzuf\u00fcgen';});

    initEntryDragDrop(projectId);

  }catch(e){container.innerHTML='<div class="empty-state">Fehler: '+esc(e.message)+'</div>';}
}

function toggleProjectEntryExpand(card){
  if(!card)return;
  var expanded=card.getAttribute('data-expanded')==='true';
  card.setAttribute('data-expanded',expanded?'false':'true');
}

function startEditProjectEntry(projectId,entryId){
  var card=document.querySelector('.proj-entry-card[data-entry-id="'+entryId+'"]');if(!card)return;
  var meta=_localProjectsMeta[projectId];if(!meta||!meta.entries)return;
  var entry=meta.entries.find(function(e){return e.id===entryId;});if(!entry)return;
  card.setAttribute('data-expanded','true');
  var fullEl=card.querySelector('.proj-entry-full');
  var previewEl=card.querySelector('.proj-entry-preview');
  var actionsEl=card.querySelector('.proj-entry-actions');
  var target=fullEl||previewEl;if(!target)return;
  if(previewEl)previewEl.style.display='none';
  if(actionsEl)actionsEl.style.display='none';
  var origText=entry.text;
  target.outerHTML='<div class="proj-entry-edit-form">'+renderMarkdownToolbar('edit-'+esc(entryId))+'<textarea class="proj-entry-edit-input" id="edit-'+esc(entryId)+'">'+esc(origText)+'</textarea><div class="md-preview" id="preview-edit-'+esc(entryId)+'" style="display:none"></div><div class="proj-entry-edit-actions"><button class="btn-primary proj-entry-save-btn" id="save-'+esc(entryId)+'">Speichern</button><button class="proj-entry-cancel-btn" id="cancel-'+esc(entryId)+'">Abbrechen</button></div></div>';
  var textarea=document.getElementById('edit-'+entryId);if(textarea)textarea.focus();
  document.getElementById('save-'+entryId).addEventListener('click',async function(){
    var newText=document.getElementById('edit-'+entryId).value.trim();if(!newText){showToast('Text darf nicht leer sein',true);return;}
    try{await editProjectEntry(projectId,entryId,newText);showToast('Gespeichert');showProjectDetail(projectId);}catch(e){showToast('Fehler',true);}
  });
  document.getElementById('cancel-'+entryId).addEventListener('click',function(){showProjectDetail(projectId);});
}



function openCreateProjectModal(){document.getElementById('pjm-name').value='';document.getElementById('pjm-desc').value='';document.getElementById('pjm-status-text').value='';document.querySelectorAll('#pjm-sc-picker .proj-sc-opt').forEach(function(s,i){s.classList.toggle('selected',i===0);});document.querySelectorAll('.proj-color-swatch').forEach(function(s,i){s.classList.toggle('selected',i===0);});var errEl=document.getElementById('pjm-error');if(errEl){errEl.textContent='';errEl.style.display='none';}document.getElementById('proj-modal-overlay').classList.add('open');setTimeout(function(){document.getElementById('pjm-name').focus();},50);}

function selectProjColor(el){document.querySelectorAll('.proj-color-swatch').forEach(function(s){s.classList.remove('selected');});el.classList.add('selected');}

function pickProjSc(el){el.parentElement.querySelectorAll('.proj-sc-opt').forEach(function(s){s.classList.remove('selected');});el.classList.add('selected');}

document.getElementById('pjm-cancel').addEventListener('click',function(){document.getElementById('proj-modal-overlay').classList.remove('open');});

document.getElementById('proj-modal-overlay').addEventListener('click',function(e){if(e.target===e.currentTarget)document.getElementById('proj-modal-overlay').classList.remove('open');});

document.getElementById('pjm-save').addEventListener('click',async function(){var name=document.getElementById('pjm-name').value.trim();if(!name){document.getElementById('pjm-name').focus();return;}var token=getGHToken();if(!token){showToast('Bitte Token eintragen',true);return;}var desc=document.getElementById('pjm-desc').value.trim();var scEl=document.querySelector('#pjm-sc-picker .proj-sc-opt.selected');var statusColor=scEl?scEl.dataset.color:'#22c55e';var statusText=document.getElementById('pjm-status-text').value.trim();var colorEl=document.querySelector('.proj-color-swatch.selected');var color=colorEl?colorEl.dataset.color:'#cc785c';var slug=name.toLowerCase().replace(/[^a-z0-9]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'');var id=slug+'-'+Date.now().toString(36);var meta={id:id,name:name,description:desc,status:'aktiv',statusColor:statusColor,statusText:statusText||'',color:color,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),kanbanCards:[]};var btn=document.getElementById('pjm-save');btn.disabled=true;btn.textContent='Erstellt\u2026';try{await saveProject(meta);document.getElementById('proj-modal-overlay').classList.remove('open');showToast('Projekt erstellt');showProjectsTab();}catch(e){var errEl=document.getElementById('pjm-error');if(errEl){errEl.textContent='Fehler: '+e.message;errEl.style.display='block';}showToast('Fehler: '+e.message,true);}btn.disabled=false;btn.textContent='Erstellen';});



// ─── UTILS ────────────────────────────────────────────────────────────────────

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}



// ─── THEME TOGGLE ─────────────────────────────────────────────────────────────

function initTheme(){
  var saved=localStorage.getItem('lifeos-theme')||'dark';
  document.documentElement.className=saved==='light'?'light-theme':'dark-theme';
  updateThemeIcon();
}

function toggleTheme(){
  var isLight=document.documentElement.className==='light-theme';
  var next=isLight?'dark':'light';
  document.documentElement.className=next+'-theme';
  localStorage.setItem('lifeos-theme',next);
  updateThemeIcon();
}

function updateThemeIcon(){
  var btn=document.getElementById('theme-toggle');if(!btn)return;
  var isLight=document.documentElement.classList.contains('light-theme');
  btn.textContent=isLight?'\u263E':'\u2600';
  btn.title=isLight?'Dark Mode':'Light Mode';
}

var themeBtn=document.getElementById('theme-toggle');
if(themeBtn)themeBtn.addEventListener('click',toggleTheme);
initTheme();

// ─── TAB BINDING ──────────────────────────────────────────────────────────────

document.querySelectorAll('.tab-btn').forEach(function(btn){btn.addEventListener('click',function(){switchTab(btn.dataset.tab);});});



// ─── FIX 5: CLEAN INIT ──────────────────────────────────────────────────────

async function initApp() {

  renderHeutePlaceholder();

  await loadFromGitHub();   // Step 1: Always fresh from GitHub

  // Step 2: _dataLoaded now true



  // ── STARTUP INTEGRITY CHECK (v1.9) ────────────────────────────────────────

  WriteGuard.ensureBadge();

  (function startupIntegrityCheck() {

    var cards = _appState.cards || {};

    var tasks = Object.values(cards);

    var issues = [];

    if (!cards || typeof cards !== 'object') {

      issues.push('cards fehlt oder ung\u00fcltig');

    } else {

      var count = tasks.length;

      var floor = DataGuard.floor;

      if (count < floor) issues.push('Zu wenig Tasks: ' + count + ' < ' + floor);

      var schemaErrors = validateAllTasks(cards);

      if (schemaErrors.length > 0) issues.push(schemaErrors.length + ' Schema-Fehler in Tasks');

      var emptyCards = tasks.filter(function(t) { return !t.id || !t.lane || !t.title; });

      if (emptyCards.length > 0) issues.push(emptyCards.length + ' Tasks ohne Pflichtfelder');

    }

    if (issues.length > 0) {

      showErrorBanner('\u26A0\uFE0F Integrity-Check: ' + issues.join('; '));

      console.warn('[startupIntegrity] Issues:', issues);

      WriteGuard.log({ status: 'error', reason: 'startup: ' + issues[0] });

    } else {

      var taskCount = tasks.length;

      // LAYER 3: forceSetFloor (not setFloor) — GitHub load is authoritative.

      // forceSetFloor resets stale floor values from previous sessions.

      DataGuard.forceSetFloor(taskCount);

      WriteGuard.log({ status: 'ok', reason: 'startup OK, ' + taskCount + ' Tasks' });

      console.log('[startupIntegrity] OK:', taskCount, 'Tasks, floor:', DataGuard.floor);

    }

  })();



  if (!_appState.collapsed || Object.keys(_appState.collapsed).length === 0) {

    LANES.forEach(function(lane) { if (lane.id !== 'HE') _appState.collapsed[lane.id] = true; });

  }

  initAL(); initCollect(); updateALBadge();

  loadCalendarEvents().catch(function(e) { console.warn('cal fail', e); });

  loadHannahSummary().catch(function(e) { console.warn('hannah fail', e); });

  var hashTab = resolveTab(location.hash.replace('#', ''));

  switchTab(hashTab && document.getElementById('tab-' + hashTab) ? hashTab : 'kanban');

  setTimeout(startProcessStatusPolling, 2000);

}

window.addEventListener('hashchange', function() {

  var h = resolveTab(location.hash.replace('#', ''));

  if (h && h !== currentTab && document.getElementById('tab-' + h)) switchTab(h);

});

function renderHeutePlaceholder(){['heute-list','woche-list','weitere-list'].forEach(function(id){var el=document.getElementById(id);if(el)el.innerHTML='<div class="empty-state">Daten werden geladen\u2026</div>';});}



// ─── THEME (Settings Buttons → unified with nav toggle) ──────────────────────

function applyTheme(theme){
  document.documentElement.className=theme+'-theme';
  localStorage.setItem("lifeos-theme",theme);
  var bd=document.getElementById("btn-theme-dark");var bl=document.getElementById("btn-theme-light");
  if(bd)bd.classList.toggle("active",theme==="dark");if(bl)bl.classList.toggle("active",theme!=="dark");
  updateThemeIcon();
  if(typeof _mermaidLoaded!=='undefined'&&_mermaidLoaded){var dd=document.getElementById('uebersicht-dropdown');if(dd&&dd.open)initUebersichtMermaid();}
}

(function(){var t=localStorage.getItem("lifeos-theme")||"dark";var bd=document.getElementById("btn-theme-dark");var bl=document.getElementById("btn-theme-light");if(bd)bd.classList.toggle("active",t==="dark");if(bl)bl.classList.toggle("active",t!=="dark");})();

document.getElementById("btn-theme-dark").addEventListener("click",function(){applyTheme("dark");});

document.getElementById("btn-theme-light").addEventListener("click",function(){applyTheme("light");});



// ─── RECOVERY & CACHE-RESET ───────────────────────────────────────────────────

document.getElementById('btn-recovery')?.addEventListener('click', async () => {

  if (!confirm('Möchten Sie die Tasks aus dem letzten Backup wiederherstellen?')) return;

  try {

    showToast('Lade Backups...', 'info');

    const token = getGHToken();

    const resp = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/backups', {

      headers: { 'Authorization': 'token ' + token }

    });

    if (!resp.ok) throw new Error('Keine Backups gefunden');

    const files = await resp.json();

    const backups = files.filter(f => f.name.startsWith('tasks_')).sort((a,b) => b.name.localeCompare(a.name));

    if (backups.length === 0) throw new Error('Keine Backups vorhanden');

    const latest = backups[0];

    const backupResp = await fetch(latest.download_url, { headers: { 'Authorization': 'token ' + token }});

    const backupData = await backupResp.json();

    const cardCount = Object.keys(backupData.cards || {}).length;

    if (!confirm(`Backup "${latest.name}" mit ${cardCount} Karten wiederherstellen?`)) return;

    _appState.cards = backupData.cards;

    _appState._meta = backupData._meta;

    renderBoard();

    showToast(`✅ ${cardCount} Karten aus Backup wiederhergestellt. Speichere...`, 'success');

    await saveAllCards('recovery: restore from ' + latest.name);

  } catch (err) {

    showToast('❌ Recovery fehlgeschlagen: ' + err.message, 'error');

    console.error('Recovery error:', err);

  }

});



document.getElementById('btn-cache-reset')?.addEventListener('click', () => {

  if (!confirm('Cache leeren und Daten neu von GitHub laden? Nicht gespeicherte Änderungen gehen verloren.')) return;

  localStorage.removeItem('cowork_tasks_cache');

  localStorage.removeItem('cowork_tasks_sha');

  localStorage.removeItem('cowork_dataguard_floor');

  showToast('Cache gelöscht — lade neu...', 'info');

  setTimeout(() => location.reload(), 500);

});





// ─── PROCESS STATUS BOX ─────────────────────────────────────────────────────

var _procStatusInterval = null;

var _procDoneTimers = {};



async function fetchProcessStatus() {

  var box = document.getElementById('process-status-box');

  if (!box) return;

  var result = await fetchFromGitHub('data/process_status.json');

  if (!result) return;

  var data;

  try { data = JSON.parse(result.content); } catch(e) { return; }

  var procs = (data && data.processes) || [];

  var now = Date.now();



  // Filter: hide 'done' entries older than 5 minutes

  procs = procs.filter(function(p) {

    if (p.status === 'done') {

      var updated = p.updated ? new Date(p.updated).getTime() : 0;

      return (now - updated) < 5 * 60 * 1000;

    }

    return true;

  });



  if (procs.length === 0) {

    box.style.display = 'none';

    return;

  }



  box.style.display = 'block';

  var html = '<div class="proc-box-header">⚙️ Hintergrundprozesse <span>(' + procs.length + ' aktiv)</span></div>';



  procs.forEach(function(p) {

    var icon = p.status === 'done' ? '✅' : p.status === 'error' ? '❌' : '⚙️';

    var pct = typeof p.progress === 'number' ? p.progress : 0;

    var startedStr = '';

    if (p.started) {

      var d = new Date(p.started);

      startedStr = d.toLocaleTimeString('de-CH', {hour:'2-digit', minute:'2-digit'});

    }

    var etaStr = '';

    if (p.eta_seconds && p.status === 'running') {

      var mins = Math.round(p.eta_seconds / 60);

      etaStr = ' • noch ca. ' + mins + ' Min.';

    }

    var barClass = p.status === 'done' ? 'done' : p.status === 'error' ? 'error' : 'running';

    html += '<div class="proc-item status-' + p.status + '">';

    html += '<div class="proc-item-header">';

    html += '<span class="proc-item-icon">' + icon + '</span>';

    html += '<span class="proc-item-name">' + (p.name || p.id) + '</span>';

    if (startedStr) html += '<span class="proc-item-time">Start: ' + startedStr + etaStr + '</span>';

    html += '</div>';

    if (p.step) html += '<div class="proc-item-step">' + p.step + '</div>';

    html += '<div class="proc-bar-wrap"><div class="proc-bar-fill ' + barClass + '" style="width:' + pct + '%"></div></div>';

    html += '<div class="proc-bar-pct">' + pct + '%</div>';

    html += '</div>';

  });



  box.innerHTML = html;

}



// ─── USAGE WIDGET ────────────────────────────────────────────────────────────

async function fetchUsageData() {
  try {
    var token = getGHToken();
    if (!token) return;
    var res = await fetch(GH_API_BASE + '/repos/' + GH_DATA_REPO + '/contents/data/usage.json', {
      headers: { Authorization: 'token ' + token, Accept: 'application/vnd.github.v3+json' }
    });
    if (!res.ok) return;
    var data = await res.json();
    var usage = JSON.parse(decodeBase64Utf8(data.content));
    renderUsageWidget(usage);
  } catch(e) {
    console.warn('[usage] fetch failed', e);
  }
}

function usageColor(pct) {
  if (pct < 50) return 'green';
  if (pct < 80) return 'yellow';
  return 'red';
}

function fmtMinutes(min) {
  if (!min || min <= 0) return 'jetzt';
  var h = Math.floor(min / 60);
  var m = min % 60;
  if (h > 0 && m > 0) return h + 'h ' + m + 'min';
  if (h > 0) return h + 'h';
  return m + 'min';
}

function fmtTimestampDE(iso) {
  try {
    var d = new Date(iso);
    return d.toLocaleDateString('de-CH', {day:'2-digit', month:'2-digit', year:'numeric'}) + ', ' +
           d.toLocaleTimeString('de-CH', {hour:'2-digit', minute:'2-digit'}) + ' Uhr';
  } catch(e) { return '?'; }
}

function renderUsageWidget(u) {
  var el = document.getElementById('usage-widget');
  if (!el || !u) return;

  var updatedStr = u.updatedAt ? fmtTimestampDE(u.updatedAt) : '?';

  var sessionPct = (u.session && u.session.pct) || 0;
  var sessionColor = usageColor(sessionPct);
  var sessionReset = u.session && u.session.resetsInMin ? 'Reset in ' + fmtMinutes(u.session.resetsInMin) : '';

  var allPct = (u.weekly && u.weekly.allModels && u.weekly.allModels.pct) || 0;
  var allColor = usageColor(allPct);
  var allReset = u.weekly && u.weekly.allModels && u.weekly.allModels.resetsLabel ? 'Reset ' + u.weekly.allModels.resetsLabel : '';

  var sonnetPct = (u.weekly && u.weekly.sonnetOnly && u.weekly.sonnetOnly.pct) || 0;
  var sonnetColor = usageColor(sonnetPct);
  var sonnetReset = u.weekly && u.weekly.sonnetOnly && u.weekly.sonnetOnly.resetsLabel ? 'Reset ' + u.weekly.sonnetOnly.resetsLabel : '';

  var extraHtml = '';
  if (u.extra && u.extra.enabled) {
    var sym = u.extra.currency === 'EUR' ? '\u20ac' : '$';
    var extraPct = u.extra.pct || 0;
    var extraColor = usageColor(extraPct);
    var extraResetStr = u.extra.resetsLabel ? 'Reset ' + u.extra.resetsLabel : '';
    extraHtml =
      '<div class="usage-section-title">Extra Usage</div>' +
      '<div class="usage-meter">' +
        '<div class="usage-meter-label">' +
          '<span class="usage-meter-name">' + sym + (u.extra.spent || 0).toFixed(2) + ' / ' + sym + u.extra.limit + '</span>' +
          '<span class="usage-meter-pct ' + extraColor + '">' + extraPct + '%</span>' +
        '</div>' +
        '<div class="usage-bar-wrap"><div class="usage-bar-fill ' + extraColor + '" style="width:' + Math.min(extraPct, 100) + '%"></div></div>' +
        '<div class="usage-meter-sub">' + extraResetStr + ' \u00b7 Guthaben: ' + sym + (u.extra.balance || 0).toFixed(2) + '</div>' +
      '</div>';
  }

  el.innerHTML =
    '<div class="usage-header">' +
      '<span class="usage-header-title">Claude Usage</span>' +
      '<span class="usage-header-ts">' + updatedStr + '</span>' +
      '<span class="usage-header-plan">' + (u.plan || '').toUpperCase() + '</span>' +
    '</div>' +

    '<div class="usage-meter">' +
      '<div class="usage-meter-label">' +
        '<span class="usage-meter-name">Session</span>' +
        '<span class="usage-meter-pct ' + sessionColor + '">' + sessionPct + '%</span>' +
      '</div>' +
      '<div class="usage-bar-wrap"><div class="usage-bar-fill ' + sessionColor + '" style="width:' + Math.min(sessionPct, 100) + '%"></div></div>' +
      '<div class="usage-meter-sub">' + sessionReset + '</div>' +
    '</div>' +

    '<div class="usage-section-title">Weekly Limits</div>' +

    '<div class="usage-meter">' +
      '<div class="usage-meter-label">' +
        '<span class="usage-meter-name">All models</span>' +
        '<span class="usage-meter-pct ' + allColor + '">' + allPct + '%</span>' +
      '</div>' +
      '<div class="usage-bar-wrap"><div class="usage-bar-fill ' + allColor + '" style="width:' + Math.min(allPct, 100) + '%"></div></div>' +
      '<div class="usage-meter-sub">' + allReset + '</div>' +
    '</div>' +

    '<div class="usage-meter">' +
      '<div class="usage-meter-label">' +
        '<span class="usage-meter-name">Sonnet only</span>' +
        '<span class="usage-meter-pct ' + sonnetColor + '">' + sonnetPct + '%</span>' +
      '</div>' +
      '<div class="usage-bar-wrap"><div class="usage-bar-fill ' + sonnetColor + '" style="width:' + Math.min(sonnetPct, 100) + '%"></div></div>' +
      '<div class="usage-meter-sub">' + sonnetReset + '</div>' +
    '</div>' +

    extraHtml +

    buildPacingChart(allPct, u.weekly && u.weekly.allModels && u.weekly.allModels.resetsInMin);

  el.style.display = 'block';
}

function buildPacingChart(weeklyPct, resetsInMin) {
  var days = ['Mo','Di','Mi','Do','Fr','Sa','So'];
  var now = new Date();
  var jsDay = now.getDay();
  var todayIdx = jsDay === 0 ? 6 : jsDay - 1;
  var dailyBudget = 100 / 7;
  var remaining = weeklyPct;
  var barsHtml = '';
  var overallColor = weeklyPct < 60 ? 'green' : weeklyPct < 85 ? 'yellow' : 'red';

  for (var i = 0; i < 7; i++) {
    var dayPct = 0;
    if (remaining >= dailyBudget) {
      dayPct = 100;
      remaining -= dailyBudget;
    } else if (remaining > 0) {
      dayPct = Math.round((remaining / dailyBudget) * 100);
      remaining = 0;
    }
    var fillClass = dayPct > 0 ? overallColor : 'empty';
    var todayClass = i === todayIdx ? ' today' : '';
    barsHtml +=
      '<div class="usage-pacing-day' + todayClass + '">' +
        '<div class="usage-pacing-bar">' +
          '<div class="usage-pacing-bar-fill ' + fillClass + '" style="height:' + dayPct + '%"></div>' +
        '</div>' +
        '<span class="usage-pacing-label">' + days[i] + '</span>' +
      '</div>';
  }

  var usedDays = Math.floor(weeklyPct / dailyBudget);
  var partialDay = Math.round(weeklyPct % dailyBudget / dailyBudget * 100);
  var remainPct = 100 - weeklyPct;
  var summaryText = weeklyPct + '% verbraucht \u00b7 ' + remainPct + '% uebrig';

  return '<div class="usage-pacing">' +
    '<div class="usage-section-title">Wochen-Kontingent</div>' +
    '<div class="usage-pacing-bars">' + barsHtml + '</div>' +
    '<div class="usage-pacing-summary">' +
      '<span class="usage-pacing-status ' + overallColor + '">' + summaryText + '</span>' +
    '</div>' +
  '</div>';
}



function startProcessStatusPolling() {

  fetchProcessStatus();
  fetchScraperProgress();
  fetchUsageData();

  if (_procStatusInterval) clearInterval(_procStatusInterval);

  _procStatusInterval = setInterval(function() {
    fetchProcessStatus();
    fetchScraperProgress();
  }, 30000);

}


// ─── BOOKMARK SCRAPER PROGRESS ───────────────────────────────────────────────

async function fetchScraperProgress() {
  var box = document.getElementById('scraper-progress-box');
  if (!box) return;
  var result = await fetchFromGitHub('data/scraper-progress.json');
  if (!result) { box.style.display = 'none'; return; }
  var data;
  try { data = JSON.parse(result.content); } catch(e) { box.style.display = 'none'; return; }
  if (!data) { box.style.display = 'none'; return; }

  var platforms = ['instagram', 'tiktok'];
  var allDone = true;
  var hasAny = false;

  platforms.forEach(function(p) {
    if (data[p] && data[p].status !== 'completed') allDone = false;
    if (data[p]) hasAny = true;
  });

  if (!hasAny || allDone) { box.style.display = 'none'; return; }

  box.style.display = 'block';
  var html = '<div class="scraper-header">Bookmark Scraper</div>';

  platforms.forEach(function(key) {
    var p = data[key];
    if (!p) return;
    var label = key.charAt(0).toUpperCase() + key.slice(1);
    var statusClass = p.status || 'pending';
    var icon = statusClass === 'running' ? '⬇️' : statusClass === 'error' ? '❌' : statusClass === 'completed' ? '✅' : '⏳';

    // Calculate progress: average of 3 phases (collect, download, upload)
    var total = p.total_bookmarks || 0;
    var pct = 0;
    if (total > 0) {
      var collectPct = Math.min(100, (p.urls_collected || 0) / total * 100);
      var dlPct = Math.min(100, (p.media_downloaded || 0) / total * 100);
      var ulPct = Math.min(100, (p.media_uploaded || 0) / total * 100);
      pct = Math.round((collectPct + dlPct + ulPct) / 3);
    }

    // Step description
    var step = '';
    if (statusClass === 'pending') {
      step = 'Ausstehend';
    } else if (statusClass === 'running') {
      if ((p.media_uploaded || 0) > 0) step = 'Upload: ' + p.media_uploaded + '/' + total;
      else if ((p.media_downloaded || 0) > 0) step = 'Download: ' + p.media_downloaded + '/' + total;
      else if ((p.urls_collected || 0) > 0) step = 'URLs: ' + p.urls_collected + '/' + (total || '?');
      else step = 'Starte...';
    } else if (statusClass === 'error') {
      step = p.errors + ' Fehler';
    } else if (statusClass === 'completed') {
      step = 'Fertig — ' + (p.media_uploaded || 0) + ' Dateien';
    }

    html += '<div class="scraper-platform">';
    html += '<div class="scraper-platform-header">';
    html += '<span class="scraper-platform-icon">' + icon + '</span>';
    html += '<span class="scraper-platform-name">' + label + '</span>';
    html += '<span class="scraper-platform-step">' + step + '</span>';
    html += '</div>';
    html += '<div class="scraper-bar-wrap"><div class="scraper-bar-fill ' + statusClass + '" style="width:' + pct + '%"></div></div>';
    if (pct > 0) html += '<div class="scraper-bar-pct">' + pct + '%</div>';
    html += '</div>';
  });

  // Estimated time remaining
  if (data.instagram && data.instagram.started_at && data.instagram.status === 'running') {
    var total = data.instagram.total_bookmarks || 0;
    var done = (data.instagram.media_uploaded || 0);
    if (done > 0 && total > done) {
      var elapsed = (Date.now() - new Date(data.instagram.started_at).getTime()) / 1000;
      var rate = done / elapsed;
      var remaining = Math.round((total - done) / rate / 86400);
      if (remaining > 0) html += '<div class="scraper-eta">~' + remaining + ' Tag' + (remaining > 1 ? 'e' : '') + ' verbleibend</div>';
    }
  }

  // Last update
  if (data.last_updated) {
    var mins = Math.round((Date.now() - new Date(data.last_updated).getTime()) / 60000);
    html += '<div class="scraper-updated">Aktualisiert vor ' + mins + ' Min.</div>';
  }

  box.innerHTML = html;
}


// ─── SYSTEM TAB ───────────────────────────────────────────────────────────────

var _systemLogCache = null;



// ─── IMPERIALKI ──────────────────────────────────────────────────────────────

var _ikCache = null;

// ── Schema-Migration: Alte Datenformate automatisch upgraden ──
function migrateIKData(ik) {
  if (!ik) return ik;
  var v = ik.version || 1;
  // v1 → v2: Add briefing, coach, drafts
  if (v < 2) {
    if (!ik.briefing) ik.briefing = { date: '', generatedAt: '', cards: { new: { count: 0, items: [] }, done: { count: 0, items: [] }, discussions: { count: 0, items: [] }, deadlines: { count: 0, items: [] } } };
    if (!ik.coach) ik.coach = { currentPhase: 'orientation', weeklyFocus: '', dailyPlan: [], nextMilestone: null, tips: [] };
    if (!ik.drafts) ik.drafts = [];
    ik.version = 2;
  }
  return ik;
}

async function showImperialKITab() {
  var container = document.getElementById('ik-container');
  if (!container) return;
  container.innerHTML = '<div class="empty-state">Wird geladen\u2026</div>';
  var token = getGHToken();
  if (!token) { container.innerHTML = '<div class="empty-state">Bitte Token in Einstellungen eintragen.</div>'; return; }
  try {
    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/imperialki.json',
      { headers: { Authorization: 'token ' + token } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var d = await r.json();
    _ikCache = JSON.parse(decodeBase64Utf8(d.content));
    _ikCache = migrateIKData(_ikCache);
  } catch(e) {
    container.innerHTML = '<div class="empty-state">Fehler: ' + esc(e.message) + '</div>';
    return;
  }
  renderImperialKI(container);
}



// ── ImperialKI: Task Done Tracking ──
var _ikDone = JSON.parse(localStorage.getItem('ikDone') || '{}');
function toggleIkDone(taskKey) {
  if (_ikDone[taskKey]) { delete _ikDone[taskKey]; }
  else { _ikDone[taskKey] = new Date().toISOString(); }
  localStorage.setItem('ikDone', JSON.stringify(_ikDone));
  var container = document.getElementById('ik-container');
  if (container) renderImperialKI(container);
}
function isIkDone(taskKey) { return !!_ikDone[taskKey]; }
function ikDoneTimestamp(taskKey) {
  if (!_ikDone[taskKey]) return '';
  var d = new Date(_ikDone[taskKey]);
  return d.toLocaleDateString('de-CH',{day:'2-digit',month:'2-digit',year:'numeric'}) + ' ' + d.toLocaleTimeString('de-CH',{hour:'2-digit',minute:'2-digit'});
}

function ikCopyDraft(draftId) {
  var ik = _ikCache;
  if (!ik) return;
  var draft = (ik.drafts || []).find(function(d) { return d.id === draftId; });
  if (!draft) return;
  navigator.clipboard.writeText(draft.content).then(function() {
    var btn = document.querySelector('[data-draft-copy="' + draftId + '"]');
    if (btn) { btn.textContent = 'Kopiert!'; setTimeout(function() { btn.textContent = 'Kopieren'; }, 2000); }
  });
}

// ── COCKPIT SHOWCASE 2.0 (nicht-funktional, Mock-Daten, zum Diskutieren) ──
function _csToggle(id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('cs-hidden');
  var btn = document.querySelector('[data-cs-toggle="' + id + '"]');
  if (btn) btn.textContent = el.classList.contains('cs-hidden') ? 'Showcase einblenden' : 'Showcase ausblenden';
  try { localStorage.setItem('cs_hidden_' + id, el.classList.contains('cs-hidden') ? '1' : '0'); } catch(e){}
}
function _csVote(featureId, vote) {
  var key = 'cs_vote_' + featureId;
  try { localStorage.setItem(key, vote); } catch(e){}
  var el = document.querySelector('[data-cs-feature="' + featureId + '"]');
  if (el) {
    el.querySelectorAll('.cs-vote-btn').forEach(function(b){ b.classList.remove('cs-vote-active'); });
    var pick = el.querySelector('[data-cs-vote="' + vote + '"]');
    if (pick) pick.classList.add('cs-vote-active');
  }
}
function _csVoted(featureId) { try { return localStorage.getItem('cs_vote_' + featureId) || ''; } catch(e){ return ''; } }

function renderCockpitShowcase() {
  var hidden = false;
  try { hidden = localStorage.getItem('cs_hidden_cockpit-showcase-root') === '1'; } catch(e){}
  var html = '';

  // ── HEADER ──
  html += '<div class="cs-shell">';
  html += '<div class="cs-banner">';
  html += '<div class="cs-banner-left">';
  html += '<div class="cs-banner-title">ImperialKI Cockpit <span class="cs-tag">Showcase 2.0</span></div>';
  html += '<div class="cs-banner-sub">Prototyp - keine Live-Daten, keine Pipeline. Alles Mockup zum Diskutieren. Sieben wir gemeinsam aus, was real wird.</div>';
  html += '</div>';
  html += '<button class="cs-banner-toggle" data-cs-toggle="cockpit-showcase-root" onclick="_csToggle(\'cockpit-showcase-root\')">' + (hidden ? 'Showcase einblenden' : 'Showcase ausblenden') + '</button>';
  html += '</div>';

  html += '<div id="cockpit-showcase-root" class="cs-root' + (hidden ? ' cs-hidden' : '') + '">';

  // ── 1. MISSION CONTROL ──
  html += '<div class="cs-mc">';
  html += '<div class="cs-mc-cell"><div class="cs-mc-num">12<span class="cs-mc-den">/16</span></div><div class="cs-mc-label">Modul 1 erledigt</div><div class="cs-mc-bar"><div class="cs-mc-bar-fill" style="width:75%"></div></div></div>';
  html += '<div class="cs-mc-cell cs-mc-warn"><div class="cs-mc-num">23<span class="cs-mc-den">h 14m</span></div><div class="cs-mc-label">Bis Assignment 1.1</div><div class="cs-mc-sub">Donnerstag 09.04. 18:29 MESZ</div></div>';
  html += '<div class="cs-mc-cell"><div class="cs-mc-num">3</div><div class="cs-mc-label">Aktionen heute</div><div class="cs-mc-sub">Assignment + 1 Diskussion + Survey</div></div>';
  html += '<div class="cs-mc-cell cs-mc-good"><div class="cs-mc-num">94<span class="cs-mc-den">%</span></div><div class="cs-mc-label">Pass-Wahrscheinlichkeit</div><div class="cs-mc-sub">Modul 1 (Self-Audit, Mock)</div></div>';
  html += '</div>';

  html += '<div class="cs-grid">';

  // ── 2. SPRACH-DNA VAULT ──
  html += '<details open class="cs-card cs-card-voice" data-cs-feature="voice-dna">';
  html += '<summary class="cs-card-head"><span class="cs-icon">DNA</span><span class="cs-card-title">Sprach-DNA Vault</span><span class="cs-card-meta">DE + EN aus Aufgabe 1.1</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-voice-row">';
  html += '<div class="cs-voice-col"><div class="cs-voice-flag">DE</div><blockquote class="cs-voice-quote">Patrick - was ein Zufall, gleiche Klinik. Habe deinen Post zu AI in der Psychotherapie gerade gelesen und dachte direkt: das ist genau die Diskussion die wir vor Ort eigentlich haben sollten. Was mich besonders interessiert: wie siehst Du die Reibung zwischen Ambient Listening und der therapeutischen Beziehung?</blockquote></div>';
  html += '<div class="cs-voice-col"><div class="cs-voice-flag">EN</div><blockquote class="cs-voice-quote">I am a clinical psychologist based in Switzerland, currently working at Klinik Barmelweid - a psychiatric and rehabilitation clinic in the canton of Aargau - where I focus on psychosomatic medicine and trauma-related disorders. I have been fascinated by the intersection of technology and healthcare for as long as I can remember.</blockquote></div>';
  html += '</div>';
  html += '<div class="cs-voice-meta">';
  html += '<div class="cs-voice-pill">Bindestrich-Einschuebe</div>';
  html += '<div class="cs-voice-pill">"ich will" statt "ich moechte"</div>';
  html += '<div class="cs-voice-pill">DE/EN organisch gemischt</div>';
  html += '<div class="cs-voice-pill">":)" als Schluss-Signal</div>';
  html += '<div class="cs-voice-pill">Reflexion + Big Picture</div>';
  html += '<div class="cs-voice-pill cs-voice-pill-bad">kein "leverage"</div>';
  html += '<div class="cs-voice-pill cs-voice-pill-bad">kein "Selbstverstaendlich"</div>';
  html += '<div class="cs-voice-pill cs-voice-pill-bad">keine Em-Dashes</div>';
  html += '</div>';
  html += '<div class="cs-voice-note">Verbunden mit /myhumanvoice Skill in KITT - jeder Forum-Post + Assignment-Draft laeuft durch diese DNA bevor er Dir gezeigt wird.</div>';
  html += '</div>';
  html += '</details>';

  // ── 3. KURS-MIRROR ──
  html += '<details open class="cs-card cs-card-mirror" data-cs-feature="course-mirror">';
  html += '<summary class="cs-card-head"><span class="cs-icon">M1</span><span class="cs-card-title">Kurs-Mirror Modul 1</span><span class="cs-card-meta">12 erledigt / 4 offen</span></summary>';
  html += '<div class="cs-card-body">';
  var done12 = [
    {t:'Module 1: Introduction', h:'Video 1.1 (Brendan, 1:06)', sum:'Kursueberblick: 40 Jahre AI-Historie, Transformer-Aera, ethische Spannungsfelder.'},
    {t:'Foundations of AI in Healthcare', h:'Videos 1.2-1.3 + Poll 1.1', sum:'AI-Evolution, Healthcare-Anwendungen, Admin-Streamlining, Patient-facing Use Cases.'},
    {t:'Mini-Lesson 1.1: Process Mapping', h:'Pflicht', sum:'6-Schritt-Methode zur Visualisierung klinischer Workflows. 4 Symbole: Step, Decision, Problem, Arrow.'},
    {t:'Understanding AI Models', h:'Video 1.4 + Poll 1.2', sum:'Taxonomie: Supervised, Unsupervised, Knowledge-based, Hybrid. Stärken und Limits jeder Klasse.'},
    {t:'Mini-Lesson 1.2: Model Validation', h:'Pflicht', sum:'Sensitivity, Specificity, PPV, NPV, ROC/AUC, F1, Overfitting. Klinisches Verstaendnis.'},
    {t:'Building & Evaluating AI Models', h:'Video 1.5 + Reading 1.1', sum:'Wang 2024 (Lancet): Transformer-basierte Lung-Cancer-Detection aus EHR. Externe Validierung als Knackpunkt.'},
    {t:'Try-It 1.1: Which Model Fits?', h:'Aktivität', sum:'Quiz-aehnliche Selbstpruefung zur Modell-Auswahl. Feedback war positiv.'},
    {t:'Video 1.6: Bias and Ethics', h:'Pflicht', sum:'Datenbias, Algorithmen-Bias, Fairness-Metriken, Black-Box-Problem, Accountability.'},
    {t:'Reflection 1.1: Bias Audit', h:'Reflexion', sum:'Eigene Use Cases gegen Bias-Risiken pruefen.'},
    {t:'Video 1.7: Strategic Recap', h:'Abschluss', sum:'Modul-1-Synthesis: was Leadership ueber AI wissen muss bevor das Adoption-Playbook startet.'},
    {t:'Module 1: Resources', h:'Bibliografie', sum:'Goodfellow, FDA GMLP, FHIR Specs, Lancet Cases, SNOMED CT.'},
    {t:'Module 1: Glossary', h:'28 Begriffe', sum:'AlphaFold, BERT, EHR, FHIR, LLM, ROC, SNOMED CT, Transformer und 20 weitere.'}
  ];
  done12.forEach(function(it){
    html += '<details class="cs-mirror-item cs-mirror-done">';
    html += '<summary><span class="cs-mirror-check">erledigt</span><span class="cs-mirror-title">' + esc(it.t) + '</span><span class="cs-mirror-h">' + esc(it.h) + '</span></summary>';
    html += '<div class="cs-mirror-sum">' + esc(it.sum) + '</div>';
    html += '<div class="cs-mirror-actions"><button class="cs-mini-btn">Audio-Zusammenfassung</button><button class="cs-mini-btn">Karteikarte anlegen</button><button class="cs-mini-btn">Tiefer recherchieren</button></div>';
    html += '</details>';
  });
  var open4 = [
    {t:'Assignment 1.1: Scoping an AI Opportunity', h:'DUE 09.04. 18:29 MESZ', sum:'400-600 Worte, 2 Dokumente (Playbook + Process Map), 5 Bewertungskriterien. Christians Use Case: Behandlungsplanung DPP Barmelweid.', urgent:true},
    {t:'Discussion 1.1: Where could AI help?', h:'Optional, empfohlen', sum:'42 Posts in der Diskussion. Christians Antwort: Voice-DNA-Draft fertig, wartet auf Freigabe.'},
    {t:'Module 1: Feedback Survey', h:'~5 Min', sum:'Standard Emeritus-Umfrage. Pro forma.'},
    {t:'Module 1: Q&A Discussion Board', h:'Optional', sum:'Fragen sammeln + an Luca Parisi richten.'}
  ];
  open4.forEach(function(it){
    html += '<details class="cs-mirror-item cs-mirror-open' + (it.urgent ? ' cs-mirror-urgent' : '') + '">';
    html += '<summary><span class="cs-mirror-check">offen</span><span class="cs-mirror-title">' + esc(it.t) + '</span><span class="cs-mirror-h">' + esc(it.h) + '</span></summary>';
    html += '<div class="cs-mirror-sum">' + esc(it.sum) + '</div>';
    html += '<div class="cs-mirror-actions"><button class="cs-mini-btn">Draft generieren</button><button class="cs-mini-btn">Pre-Grade</button><button class="cs-mini-btn">Kontext laden</button></div>';
    html += '</details>';
  });
  html += '</div>';
  html += '</details>';

  // ── 4. DEUTSCHE LERN-DESTILLATE ──
  html += '<details class="cs-card cs-card-learn" data-cs-feature="learn-distill">';
  html += '<summary class="cs-card-head"><span class="cs-icon">DE</span><span class="cs-card-title">Deutsche Lern-Destillate</span><span class="cs-card-meta">Mini-Lessons + Glossar + Reading auf DE</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<details class="cs-learn"><summary>Mini-Lesson 1.1: Process Mapping (DE-Destillat)</summary><div class="cs-learn-body">Process Mapping ist die strukturierte Visualisierung eines klinischen Workflows. Du brauchst 4 Symbole: Schritt (Rechteck), Entscheidung (Raute), Problem (Stern), Pfeil. Sechs Schritte: 1) Scope festlegen - wo faengt der Prozess an, wo hoert er auf. 2) Stakeholder identifizieren - wer ist beteiligt. 3) Schritte chronologisch sammeln, oft per Interview oder Shadowing. 4) Entscheidungspunkte einzeichnen. 5) Pain Points markieren - wo wartet der Patient, wo gibt es Doppelarbeit. 6) Mit dem Team validieren. Fuer dein Assignment: dokumentiere die Behandlungsplanung in der Psychosomatik und markier die drei Stellen wo AI greifen koennte.</div></details>';
  html += '<details class="cs-learn"><summary>Mini-Lesson 1.2: Model Validation (DE-Destillat)</summary><div class="cs-learn-body">Sensitivity sagt: wie viele tatsaechlich Kranke erkennt das Modell. Specificity sagt: wie viele tatsaechlich Gesunde laesst es korrekt durch. PPV ist die Wahrscheinlichkeit dass ein positives Ergebnis stimmt - haengt von Praevalenz ab. NPV das Gegenstueck. ROC zeigt das Trade-off zwischen Sensitivity und 1-Specificity an verschiedenen Schwellen. AUC fasst das in einer Zahl zusammen - 0.5 ist Zufall, 1.0 ist perfekt. F1 verbindet Precision und Recall. Overfitting passiert wenn das Modell die Trainingsdaten auswendig lernt statt zu generalisieren - Cross-Validation und externe Test-Sets sind die Antwort.</div></details>';
  html += '<details class="cs-learn"><summary>Reading 1.1: Wang 2024 - Lung Cancer Transformer (DE-Zusammenfassung)</summary><div class="cs-learn-body">Wang et al. (2024, Lancet) haben einen Transformer auf Hausarzt-EHR-Daten trainiert um Lungenkrebs frueher zu erkennen als Standard-Triage. Kernbefund: das Modell erkennt subtile Muster im Verlauf der Konsultationen die menschlichen GPs entgehen. Externe Validierung kritisch - das Modell musste auf einem zweiten, unabhaengigen Datensatz funktionieren. Leadership-Lehre: technisch gut heisst nicht klinisch nuetzlich. Equity-Frage: erkennt das Modell Risiken in unterversorgten Populationen genauso? Workflow-Integration und Staff-Akzeptanz waren die echten Bottlenecks, nicht der Algorithmus.</div></details>';
  html += '<details class="cs-learn"><summary>Glossar 28 Begriffe (DE-Erklaerung)</summary><div class="cs-learn-body cs-learn-glossary">';
  var gloss = [
    ['AlphaFold','DeepMinds Modell zur Proteinfaltungs-Vorhersage. Hat ein 50-Jahre-Problem der Strukturbiologie geloest.'],
    ['BERT','Bidirectional Encoder Representations from Transformers. Sprachmodell von Google, oft Basis fuer klinische NLP-Pipelines.'],
    ['Deep Learning','Neuronale Netze mit vielen Schichten. Lernt Repraesentationen aus Rohdaten ohne Feature-Engineering.'],
    ['EHR','Electronic Health Record. Digitale Patientenakte. Hauptquelle fuer Healthcare-AI-Trainingsdaten.'],
    ['Explainability','Faehigkeit eines Modells, seine Entscheidung nachvollziehbar zu machen. In Medizin oft regulatorisch gefordert.'],
    ['FHIR','Fast Healthcare Interoperability Resources. Standard fuer Datenaustausch zwischen Systemen.'],
    ['HL7','Health Level Seven. Aelterer Standard fuer klinische Daten, oft Vorlaeufer von FHIR.'],
    ['LLM','Large Language Model. GPT, Claude, Llama. Generative Sprachmodelle die in Healthcare zunehmend fuer Dokumentation eingesetzt werden.'],
    ['Overfitting','Modell lernt Trainingsdaten auswendig statt zu generalisieren. Symptom: gut auf Training, schlecht auf neuen Daten.'],
    ['ROC Curve','Receiver Operating Characteristic. Trade-off zwischen Sensitivity und 1-Specificity an verschiedenen Cutoffs.'],
    ['SNOMED CT','Klinische Terminologie. Standardvokabular fuer Diagnosen, Symptome, Prozeduren.'],
    ['Transformer','Neuronale Architektur mit Self-Attention. Basis aller modernen LLMs und vieler klinischer NLP-Modelle.'],
    ['MYCIN','Historisches Expertensystem (1970er) fuer Antibiotika-Verschreibung. Wichtiger Vorlaeufer.'],
    ['CDS Hooks','Standard fuer Clinical Decision Support Integration in EHR-Workflows.']
  ];
  gloss.forEach(function(g){ html += '<div class="cs-gloss-item"><strong>' + esc(g[0]) + '</strong> - ' + esc(g[1]) + '</div>'; });
  html += '<div class="cs-gloss-more">14 weitere Begriffe (Autoencoder, Bayesian Systems, Answer Set Programming, FHIR, NPV/PPV, F1, ...) - im echten Cockpit alle anklickbar mit Karteikarte + Audio.</div>';
  html += '</div></details>';
  html += '</div>';
  html += '</details>';

  // ── 5. DISKUSSIONS-RADAR ──
  html += '<details class="cs-card cs-card-radar" data-cs-feature="discussion-radar">';
  html += '<summary class="cs-card-head"><span class="cs-icon">RAD</span><span class="cs-card-title">Diskussions-Radar</span><span class="cs-card-meta">2 aktive Threads, 117 Posts gesamt</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-disc-row">';
  html += '<div class="cs-disc-card">';
  html += '<div class="cs-disc-title">Meet Your Fellow Learners</div>';
  html += '<div class="cs-disc-stats">75 Posts | 23 ungelesen | Christian: <strong>gepostet 30.03.</strong> | 3 Likes auf eigenem Post</div>';
  html += '<div class="cs-disc-bar"><div class="cs-disc-bar-fill" style="width:31%"></div></div>';
  html += '<div class="cs-disc-list">';
  html += '<div class="cs-disc-line"><span class="cs-disc-name">Patrick Koeck</span><span class="cs-disc-role">Psychiater, Klinik Barmelweid</span><span class="cs-disc-action">Reply-Draft fertig</span></div>';
  html += '<div class="cs-disc-line"><span class="cs-disc-name">Owen Roodenburg</span><span class="cs-disc-role">CMO ICU, Melbourne</span><span class="cs-disc-action">Reply-Draft fertig</span></div>';
  html += '<div class="cs-disc-line"><span class="cs-disc-name">Ezani Taib</span><span class="cs-disc-role">CEO IJN Malaysia</span><span class="cs-disc-action">Reply-Draft fertig</span></div>';
  html += '<div class="cs-disc-line"><span class="cs-disc-name">Helgi Sigmundsson</span><span class="cs-disc-role">Gastro, Iowa</span><span class="cs-disc-action">Reply-Vorschlag</span></div>';
  html += '</div>';
  html += '</div>';
  html += '<div class="cs-disc-card">';
  html += '<div class="cs-disc-title">M1: Where Could AI Help in Your Organisation?</div>';
  html += '<div class="cs-disc-stats">42 Posts | 42 ungelesen | Christian: <strong>noch nicht gepostet</strong> | Draft (EN, Voice DNA) ready</div>';
  html += '<div class="cs-disc-bar"><div class="cs-disc-bar-fill cs-disc-bar-warn" style="width:0%"></div></div>';
  html += '<div class="cs-disc-themes"><strong>Use Cases der Cohort:</strong> Ambient AI Scribing, Respiratory Triage NHS, Echocardiography Primary Care, Dermatological Screening, Cardiac Surgery Risk Prediction, Member Contact Center AI</div>';
  html += '<div class="cs-disc-themes"><strong>Christians Position (Draft):</strong> AI scribe fuer Behandlungsplanung in der Psychosomatik. Reflektive Arbeit, aber repetitiv in Struktur. Mensch-im-Loop bleibt zentral.</div>';
  html += '</div>';
  html += '</div>';
  html += '<div class="cs-disc-note">Real wuerde Hermine taeglich um 06:00 alle Discussions scrapen, neue Posts diff-detecten, in RAG indizieren und Reply-Drafts in Christians Voice DNA generieren. Du siehst nur das Ergebnis: 3 fertige Drafts auf dem Smartphone.</div>';
  html += '</div>';
  html += '</details>';

  // ── 6. FORUM-BATTERY ──
  html += '<details class="cs-card cs-card-battery" data-cs-feature="forum-battery">';
  html += '<summary class="cs-card-head"><span class="cs-icon">FB</span><span class="cs-card-title">Forum-Battery (Pre-Drafts)</span><span class="cs-card-meta">4 fertige Replies, durch /myhumanvoice gefiltert</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-draft">';
  html += '<div class="cs-draft-head"><span class="cs-draft-to">An Patrick Koeck (DE)</span><span class="cs-draft-pill">Score 9/10</span></div>';
  html += '<div class="cs-draft-text">Patrick - was ein Zufall, gleiche Klinik. Habe deinen Post zu AI in der Psychotherapie gerade gelesen und dachte direkt: das ist genau die Diskussion die wir vor Ort eigentlich haben sollten. Was mich besonders interessiert: wie siehst Du die Reibung zwischen Ambient Listening und der therapeutischen Beziehung? Das ist bei uns in der Psychosomatik der Hauptknoten. Lass uns das mal vor Ort vertiefen - vielleicht beim Mittagessen?</div>';
  html += '<div class="cs-draft-actions"><button class="cs-mini-btn">Kopieren</button><button class="cs-mini-btn">Auf Emeritus posten</button><button class="cs-mini-btn">Neu generieren</button></div>';
  html += '</div>';
  html += '<div class="cs-draft">';
  html += '<div class="cs-draft-head"><span class="cs-draft-to">An Owen Roodenburg (EN)</span><span class="cs-draft-pill">Score 9/10</span></div>';
  html += '<div class="cs-draft-text">Owen - your shift from ICU to CMO is exactly the move I want to think harder about. From the patient bed to the system level, the AI conversation looks completely different. In psychiatric rehab the bottleneck is rarely the model - it is therapist trust and the time AI gives back to the relationship. Curious how you handle that translation: what convinces a clinician at 3am, vs. what convinces a CMO board.</div>';
  html += '<div class="cs-draft-actions"><button class="cs-mini-btn">Kopieren</button><button class="cs-mini-btn">Auf Emeritus posten</button><button class="cs-mini-btn">Neu generieren</button></div>';
  html += '</div>';
  html += '<div class="cs-draft">';
  html += '<div class="cs-draft-head"><span class="cs-draft-to">An Ezani Taib (EN)</span><span class="cs-draft-pill">Score 8/10</span></div>';
  html += '<div class="cs-draft-text">Ezani - EMRAM Level 7 is impressive context for everything you write. Cardiac surgery and psychiatric rehab look unrelated, but the AI question rhymes: how do you keep the clinical judgment central when the model is faster? At Barmelweid we are early. Would love to hear which step in your AI adoption you would do differently in hindsight - the kind of thing we never read in the case studies.</div>';
  html += '<div class="cs-draft-actions"><button class="cs-mini-btn">Kopieren</button><button class="cs-mini-btn">Auf Emeritus posten</button><button class="cs-mini-btn">Neu generieren</button></div>';
  html += '</div>';
  html += '<div class="cs-draft">';
  html += '<div class="cs-draft-head"><span class="cs-draft-to">M1 Where Could AI Help (EN)</span><span class="cs-draft-pill">Score 9/10</span></div>';
  html += '<div class="cs-draft-text">One specific opening for AI at Klinik Barmelweid - psychosomatic medicine, my department. We currently spend a lot of time on treatment planning documentation: synthesising assessment, history, and treatment phase into a coherent plan. It is reflective work, but also repetitive in structure. An AI scribe that drafts the structural skeleton from the assessment would free clinical time for the therapeutic relationship - which is the actual asset. The risk: losing the reflective layer that planning forces. So the design has to keep the clinician in the loop, not replace the thinking. Curious how others handle this trade-off.</div>';
  html += '<div class="cs-draft-actions"><button class="cs-mini-btn">Kopieren</button><button class="cs-mini-btn">Auf Emeritus posten</button><button class="cs-mini-btn">Neu generieren</button></div>';
  html += '</div>';
  html += '</div>';
  html += '</details>';

  // ── 7. ASSIGNMENT 1.1 STUDIO ──
  html += '<details class="cs-card cs-card-assign" data-cs-feature="assignment-studio">';
  html += '<summary class="cs-card-head"><span class="cs-icon">A1</span><span class="cs-card-title">Assignment 1.1 Studio</span><span class="cs-card-meta">DUE morgen 18:29 - Pre-Grading 38/50</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-assign-row">';
  html += '<div class="cs-assign-col">';
  html += '<div class="cs-assign-h">Use-Case-Vorschlag</div>';
  html += '<div class="cs-assign-text"><strong>Behandlungsplanung DPP Barmelweid</strong> - die strukturierte Synthese aus Erstgespraech, Vorbericht, Diagnostik und Therapieplan. Repetitiv genug fuer AI-Unterstuetzung, sensibel genug um die Reflexionsschicht zu schuetzen.</div>';
  html += '<div class="cs-assign-h">Process Map (Mock-Vorschau)</div>';
  html += '<div class="cs-assign-pmap">';
  html += '<div class="cs-pmap-step">Eintritt + Erstgespraech</div>';
  html += '<div class="cs-pmap-arrow">↓</div>';
  html += '<div class="cs-pmap-step">Diagnostik (3-5 Tage)</div>';
  html += '<div class="cs-pmap-arrow">↓</div>';
  html += '<div class="cs-pmap-decision">Komplexitaet?</div>';
  html += '<div class="cs-pmap-arrow">↓</div>';
  html += '<div class="cs-pmap-step cs-pmap-pain">Behandlungsplanung (~90 min, manuell)</div>';
  html += '<div class="cs-pmap-arrow">↓</div>';
  html += '<div class="cs-pmap-step">Teamkonferenz</div>';
  html += '<div class="cs-pmap-arrow">↓</div>';
  html += '<div class="cs-pmap-step">Patientengespraech + Plan</div>';
  html += '</div>';
  html += '</div>';
  html += '<div class="cs-assign-col">';
  html += '<div class="cs-assign-h">Pre-Grading (Self-Audit gegen Rubrik)</div>';
  html += '<div class="cs-rubric"><div class="cs-rubric-row"><span>Problem Identification</span><div class="cs-rubric-bar"><div style="width:80%"></div></div><span>8/10</span></div>';
  html += '<div class="cs-rubric-row"><span>Process Mapping</span><div class="cs-rubric-bar"><div style="width:60%" class="cs-rubric-warn"></div></div><span>6/10</span></div>';
  html += '<div class="cs-rubric-row"><span>AI Design</span><div class="cs-rubric-bar"><div style="width:90%" class="cs-rubric-good"></div></div><span>9/10</span></div>';
  html += '<div class="cs-rubric-row"><span>Requirements</span><div class="cs-rubric-bar"><div style="width:70%"></div></div><span>7/10</span></div>';
  html += '<div class="cs-rubric-row"><span>Reflection + Leadership</span><div class="cs-rubric-bar"><div style="width:80%"></div></div><span>8/10</span></div>';
  html += '</div>';
  html += '<div class="cs-assign-meta">Wortzahl: <strong>542 / 600</strong> | Abgabe-Format: 2 PDFs (Playbook + Map) | Pass-Threshold: 30/50 (Mock)</div>';
  html += '<div class="cs-assign-h">Verbesserungs-Vorschlaege</div>';
  html += '<ul class="cs-assign-fix"><li>Process Mapping: 3 Decision Points fehlen - im Moment nur lineare Sequenz</li><li>Requirements: Cyber Security explizit erwaehnen (DSGVO + Klinik-IT)</li><li>Stakeholder-Map: Pflege ist im Draft nicht erwaehnt, sollte rein</li></ul>';
  html += '</div>';
  html += '</div>';
  html += '<div class="cs-assign-actions"><button class="cs-mini-btn">Vollen Draft oeffnen</button><button class="cs-mini-btn">Process Map exportieren (PNG)</button><button class="cs-mini-btn">An Hannah/Patrick zur Review</button></div>';
  html += '</div>';
  html += '</details>';

  // ── 8. AUDIO BRIEFING ──
  html += '<details class="cs-card cs-card-audio" data-cs-feature="audio-briefing">';
  html += '<summary class="cs-card-head"><span class="cs-icon">SND</span><span class="cs-card-title">Audio-Briefing</span><span class="cs-card-meta">5 min taeglich, Voice DNA Sprecher</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-audio-row">';
  html += '<div class="cs-audio-card">';
  html += '<div class="cs-audio-date">Heute, 08.04.2026 - 06:30</div>';
  html += '<div class="cs-audio-title">Modul 1 - Was Du heute brauchst</div>';
  html += '<div class="cs-audio-meta">5:12 min | DE | TTS-Mock</div>';
  html += '<div class="cs-audio-player"><div class="cs-audio-btn">▶</div><div class="cs-audio-bar"><div class="cs-audio-bar-fill" style="width:34%"></div></div><span class="cs-audio-time">1:46 / 5:12</span></div>';
  html += '<div class="cs-audio-script">"Guten Morgen Christian. Heute ist Mittwoch der 8. April. Modul 1 ist zu 75 Prozent durch. Drei Sachen: Assignment 1.1 ist morgen um 18 Uhr 29 faellig - der Draft liegt im Studio bereit, Pre-Grading 38 von 50, knapp ueber Pass. Das schwaechste Kriterium ist die Process Map, da fehlen drei Decision Points. Zweitens: Patrick Koeck hat in der Meet-Fellow-Learners-Diskussion einen Post zu AI in der Psychotherapie reingestellt - gleiche Klinik, wert zu antworten. Drittens: das Q-and-A-Board ist immer noch leer auf Deiner Seite. Empfehlung fuer heute: 90 Minuten Assignment finalisieren, dann Patrick antworten, Survey + Q-and-A in 10 Minuten am Abend abhaken. Mehr nicht. Tag wird gut."</div>';
  html += '</div>';
  html += '<div class="cs-audio-card">';
  html += '<div class="cs-audio-date">Gestern, 07.04. - 06:30</div>';
  html += '<div class="cs-audio-title">Modul 1 - Tag 11</div>';
  html += '<div class="cs-audio-meta">4:48 min</div>';
  html += '<div class="cs-audio-player"><div class="cs-audio-btn">▶</div><div class="cs-audio-bar"><div class="cs-audio-bar-fill" style="width:0%"></div></div><span class="cs-audio-time">0:00 / 4:48</span></div>';
  html += '</div>';
  html += '</div>';
  html += '<div class="cs-audio-note">Real-Setup: Hermine generiert das Briefing-Script aus den letzten 24h Diff (Scrape + Voice DNA + Pre-Grading). OpenAI TTS oder ElevenLabs rendert es als MP3, push auf S3 + Telegram + LifeOS. Du hoerst es beim Fruehstueck, machst nichts.</div>';
  html += '</div>';
  html += '</details>';

  // ── 9. UPGRADE BASICS KURS ──
  html += '<details class="cs-card cs-card-upgrade" data-cs-feature="upgrade-basics">';
  html += '<summary class="cs-card-head"><span class="cs-icon">UP</span><span class="cs-card-title">Upgrade Basics - Eigener Mini-Kurs</span><span class="cs-card-meta">14 Lektionen, ~2h gesamt</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-upgrade-intro">Selbstgebauter Foundation-Kurs - die Basics die ImperialKI voraussetzt aber nicht erklaert. In Deiner Sprach-DNA, mit Audio + Karteikarten + Mini-Quiz. Lokal generiert aus den ImperialKI-Materialien, keinen externen Anbieter.</div>';
  var upLessons = [
    {n:'01', t:'Was ist Supervised Learning?', d:'Klassifikation vs Regression, Trainingsdaten, Labels, Verlustfunktion. 8 min Audio + Quiz.'},
    {n:'02', t:'Tokens, Embeddings, Attention', d:'Wie ein LLM Sprache zerlegt und Bedeutung rekonstruiert. 10 min.'},
    {n:'03', t:'ROC, AUC, F1 verstehen', d:'Diagnostik-Metriken intuitiv. Wann ist 90% gut, wann ist 90% gefaehrlich. 9 min.'},
    {n:'04', t:'Bias in klinischen Datensaetzen', d:'Wo Daten luegen. Beispiele aus Dermatologie und Mental Health. 8 min.'},
    {n:'05', t:'Train/Validation/Test Split', d:'Warum dreigeteilt, warum extern. 7 min.'},
    {n:'06', t:'Overfitting + Regularisierung', d:'Wenn das Modell auswendig lernt. Dropout, L1/L2 in einer Minute erklaert. 8 min.'},
    {n:'07', t:'FHIR + EHR Integration', d:'Wie AI ueberhaupt an klinische Daten kommt. 10 min.'},
    {n:'08', t:'Process Mapping in der Praxis', d:'Vertiefung von Mini-Lesson 1.1 mit zwei Klinik-Beispielen. 12 min.'},
    {n:'09', t:'Stakeholder-Mapping fuer Klinikprojekte', d:'Wer muss frueh dabei sein, wer kommt spaeter. 9 min.'},
    {n:'10', t:'EU AI Act Crashkurs', d:'High-Risk-Klassifikation, was das fuer Dich bedeutet. 10 min.'},
    {n:'11', t:'GDPR und klinische AI', d:'DSGVO-Realitaet in CH und EU. 9 min.'},
    {n:'12', t:'Human-in-the-Loop Design', d:'Wann der Mensch entscheidet, wann das Modell. 10 min.'},
    {n:'13', t:'Bewertungsstrategien fuer klinische Modelle', d:'Vor Deployment, waehrend, nach. 11 min.'},
    {n:'14', t:'Change Management bei AI-Adoption', d:'Warum die Haelfte der Pilots scheitert - und wie nicht. 12 min.'}
  ];
  html += '<div class="cs-upgrade-list">';
  upLessons.forEach(function(l){
    html += '<div class="cs-upgrade-item"><span class="cs-upgrade-num">' + l.n + '</span><div class="cs-upgrade-text"><div class="cs-upgrade-t">' + esc(l.t) + '</div><div class="cs-upgrade-d">' + esc(l.d) + '</div></div><button class="cs-mini-btn">Audio starten</button></div>';
  });
  html += '</div>';
  html += '<div class="cs-upgrade-note">Vorschlag: Hermine generiert die Lektionen einmalig auf Lightsail (TTS via OpenAI). Speicherung als MP3 + Markdown + Quiz-JSON in cowork-data. Total ca. 2h Audio, alles offline-faehig im LifeOS.</div>';
  html += '</div>';
  html += '</details>';

  // ── 10. KARTEIKARTEN (Spaced Repetition) ──
  html += '<details class="cs-card cs-card-cards" data-cs-feature="flashcards">';
  html += '<summary class="cs-card-head"><span class="cs-icon">SR</span><span class="cs-card-title">Karteikarten + Spaced Repetition</span><span class="cs-card-meta">28 Glossar + Konzepte aus Modul 1</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-cards-stats">';
  html += '<div class="cs-cards-stat"><div class="cs-cards-num">28</div><div>Aktive Karten</div></div>';
  html += '<div class="cs-cards-stat"><div class="cs-cards-num">7</div><div>Heute faellig (5 min)</div></div>';
  html += '<div class="cs-cards-stat"><div class="cs-cards-num">0</div><div>Streak (Tage)</div></div>';
  html += '<div class="cs-cards-stat"><div class="cs-cards-num">0%</div><div>Mastery</div></div>';
  html += '</div>';
  html += '<div class="cs-cards-preview">';
  html += '<div class="cs-flash"><div class="cs-flash-q">Was misst eine ROC-Kurve?</div><div class="cs-flash-a">Trade-off zwischen Sensitivity (True Positive Rate) und 1-Specificity (False Positive Rate) an verschiedenen Cutoffs. AUC fasst die Kurve in einer Zahl zusammen - 0.5 ist Zufall, 1.0 ist perfekt.</div></div>';
  html += '<div class="cs-flash"><div class="cs-flash-q">Welche 4 Symbole nutzt Process Mapping?</div><div class="cs-flash-a">Schritt (Rechteck), Entscheidung (Raute), Problem (Stern), Pfeil (Verbindung). Mehr braucht es fuer die Mini-Lesson 1.1 nicht.</div></div>';
  html += '<div class="cs-flash"><div class="cs-flash-q">Was unterscheidet FHIR von HL7 v2?</div><div class="cs-flash-a">FHIR ist ressourcenbasiert (REST-API, JSON), modular und web-nativ. HL7 v2 ist nachrichtenbasiert, Pipe-delimited, alt aber noch verbreitet. FHIR ist der Standard fuer moderne Healthcare-AI-Integration.</div></div>';
  html += '</div>';
  html += '<div class="cs-cards-note">Algorithmus: FSRS (modern) oder SM-2 (klassisch). Lokal in localStorage gespeichert. Echte Karten haben Audio + Bild-Optional + Tags pro Modul.</div>';
  html += '</div>';
  html += '</details>';

  // ── 11. RECHERCHE STREAM ──
  html += '<details class="cs-card cs-card-stream" data-cs-feature="research-stream">';
  html += '<summary class="cs-card-head"><span class="cs-icon">RS</span><span class="cs-card-title">Recherche-Stream</span><span class="cs-card-meta">Grok x.com + Google Deep Research</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-stream-section">';
  html += '<div class="cs-stream-h">Heute - Grok x.com Pulse: "AI in Healthcare"</div>';
  html += '<div class="cs-stream-item"><strong>NHS Wales</strong> - 3 Trusts pilot Ambient AI scribe. Kritik: 18% Halluzinationsrate bei Pflegenotizen.</div>';
  html += '<div class="cs-stream-item"><strong>DiGA Update DE</strong> - 12 neue digitale Gesundheitsanwendungen registriert, 4 davon mit AI-Komponente.</div>';
  html += '<div class="cs-stream-item"><strong>FDA</strong> - Neuer Draft Guidance fuer LLMs in Clinical Decision Support, Kommentarphase laeuft.</div>';
  html += '<div class="cs-stream-item"><strong>Lancet</strong> - Kritisches Review zu externen Validierungen klinischer AI-Modelle. Median: nur 17% schaffen es ueber den eigenen Datensatz hinaus.</div>';
  html += '</div>';
  html += '<div class="cs-stream-section">';
  html += '<div class="cs-stream-h">Google Deep Research Brief (verfuegbar)</div>';
  html += '<div class="cs-stream-brief"><strong>Thema:</strong> AI in Psychiatric Rehabilitation Europe 2025-2026<br><strong>Umfang:</strong> 12 Seiten, 47 Quellen, 8 Case Studies<br><strong>Kernbefunde:</strong> Pilot-heavy, konzentriert in UK/DE/FR/NL. Ambient AI scribes sparen 20-35% Doku-Zeit. Multimodales Monitoring AUC 0.79 fuer Rueckfall-Praediktion. EU AI Act hochrisikoklassifiziert. EFQM-/TQM-Frameworks fuer AI Governance werden adoptiert.<br><button class="cs-mini-btn">Vollen Brief lesen</button><button class="cs-mini-btn">Audio-Version</button></div>';
  html += '</div>';
  html += '<div class="cs-stream-section">';
  html += '<div class="cs-stream-h">Vorschlag: Diese Woche tiefer recherchieren</div>';
  html += '<ul class="cs-stream-sugg"><li>Patient-facing AI in stationaerer Psychotherapie (sehr wenig Literatur)</li><li>Liability bei AI-gestuetzten Behandlungsplaenen (CH-Recht)</li><li>Pflegealltag und AI-Akzeptanz - empirische Daten</li></ul>';
  html += '</div>';
  html += '<div class="cs-stream-note">Real: Google Deep Research API + Grok x.com Search API + Perplexity. Hermine triggert taeglich, KITT verarbeitet die Briefs in dein RAG, Cockpit zeigt nur die Kondensate.</div>';
  html += '</div>';
  html += '</details>';

  // ── 12. COHORT MAP ──
  html += '<details class="cs-card cs-card-cohort" data-cs-feature="cohort-map">';
  html += '<summary class="cs-card-head"><span class="cs-icon">58</span><span class="cs-card-title">Cohort Map</span><span class="cs-card-meta">58 Studierende, 14 Laender</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-cohort-grid">';
  var cohortGeo = [['UK',24],['CH',3],['MY',4],['US',5],['DE',6],['NL',2],['IT',3],['IS',2],['AU',2],['FR',2],['ES',2],['JP',1],['SG',1],['Andere',1]];
  cohortGeo.forEach(function(g){
    html += '<div class="cs-cohort-cell"><div class="cs-cohort-flag">' + g[0] + '</div><div class="cs-cohort-num">' + g[1] + '</div></div>';
  });
  html += '</div>';
  html += '<div class="cs-cohort-roles">';
  html += '<div class="cs-cohort-role"><span class="cs-cohort-role-bar" style="width:42%"></span><span>Klinisch (Aerzte, Psychotherapeuten, Pflege)</span><strong>24</strong></div>';
  html += '<div class="cs-cohort-role"><span class="cs-cohort-role-bar" style="width:24%"></span><span>Operations (CMO, COO, Klinikleitung)</span><strong>14</strong></div>';
  html += '<div class="cs-cohort-role"><span class="cs-cohort-role-bar" style="width:17%"></span><span>Tech / Data (CIO, Data Manager, AI Lead)</span><strong>10</strong></div>';
  html += '<div class="cs-cohort-role"><span class="cs-cohort-role-bar" style="width:10%"></span><span>Beratung / Pharma / Startup</span><strong>6</strong></div>';
  html += '<div class="cs-cohort-role"><span class="cs-cohort-role-bar" style="width:7%"></span><span>Akademisch / Forschung</span><strong>4</strong></div>';
  html += '</div>';
  html += '<div class="cs-cohort-note">Echtes Cockpit: Klick auf Land oeffnet die Liste, klick auf Person oeffnet ihren Background + alle Posts + Voice-DNA-Reply-Vorschlag.</div>';
  html += '</div>';
  html += '</details>';

  // ── 13. NETWORKING COMPASS ──
  html += '<details class="cs-card cs-card-net" data-cs-feature="networking">';
  html += '<summary class="cs-card-head"><span class="cs-icon">NC</span><span class="cs-card-title">Networking Compass</span><span class="cs-card-meta">Top 5 Kontakte fuer Christian</span></summary>';
  html += '<div class="cs-card-body">';
  var net = [
    {n:'Patrick Koeck',role:'Psychiater, Klinik Barmelweid',br:'Gleiche Klinik. Gleiche Stadt. Gleiches Departement. Hoechster Hebel fuer lokalen Use Case.',next:'In nachster Woche zum Mittagessen einladen.'},
    {n:'Owen Roodenburg',role:'CMO ICU, Melbourne',br:'Klinik-zu-System Perspektive. Selten in Cohort. Wertvoll fuer Leadership-Reflexion in Modulen 4-6.',next:'Reply auf Meet-Post + 1 Frage zur CMO-Transition.'},
    {n:'Ezani Taib',role:'CEO IJN, Kuala Lumpur',br:'EMRAM Level 7 - eines der digital reifsten Krankenhaeuser weltweit. Lerneffekt fuer Christian sehr hoch.',next:'Spezifische Frage zum AI-Adoption-Stack stellen.'},
    {n:'Iona Macmillan Douglas',role:'IP, Data Privacy, AI Training Rollout',br:'Brueckenfunktion zu DSGVO und EU AI Act. Wichtig fuer Modul 5.',next:'Connection-Request mit Kontext.'},
    {n:'Luca Parisi',role:'Learning Facilitator',br:'Direkter Zugang. Jede gute Frage zaehlt. Office Hours nicht verschenken.',next:'Eine konkrete Frage in Q&A Board posten - erkennt deinen Namen.'}
  ];
  net.forEach(function(p,i){
    html += '<div class="cs-net-card"><div class="cs-net-rank">' + (i+1) + '</div>';
    html += '<div class="cs-net-body"><div class="cs-net-name">' + esc(p.n) + '</div><div class="cs-net-role">' + esc(p.role) + '</div>';
    html += '<div class="cs-net-bridge"><strong>Bruecke:</strong> ' + esc(p.br) + '</div>';
    html += '<div class="cs-net-next"><strong>Naechster Schritt:</strong> ' + esc(p.next) + '</div></div></div>';
  });
  html += '</div>';
  html += '</details>';

  // ── 14. AUTOMATION PIPELINE (Vision) ──
  html += '<details class="cs-card cs-card-pipe" data-cs-feature="automation">';
  html += '<summary class="cs-card-head"><span class="cs-icon">AP</span><span class="cs-card-title">Automation Pipeline (Vision)</span><span class="cs-card-meta">Was Hermine taeglich machen wuerde</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-pipe">';
  var steps = [
    {t:'06:00',a:'Hermine scraped Emeritus via Browser Use',d:'Alle Module + Diskussionen + Announcements + Q&A. Diff zu gestern.'},
    {t:'06:05',a:'Diff Detection',d:'Was ist neu seit letzter Pruefung? Posts, Replies, Likes, neue Module, Survey-Antworten.'},
    {t:'06:08',a:'RAG Index Update',d:'Neue Inhalte ins LanceDB. Alte Versionen versioniert.'},
    {t:'06:12',a:'Voice-DNA Drafts',d:'Fuer jeden neuen Post in einer Discussion: ein Reply-Draft in Christians Stil.'},
    {t:'06:18',a:'Pre-Grading + Updates',d:'Falls Christian an Assignment gearbeitet hat: Self-Audit gegen Rubrik.'},
    {t:'06:22',a:'Recherche-Stream',d:'Grok x.com + Google Deep Research: was war ueber Nacht relevant.'},
    {t:'06:26',a:'Audio-Briefing TTS',d:'Hermine generiert das Briefing-Script, OpenAI TTS rendert MP3.'},
    {t:'06:30',a:'Telegram + LifeOS Push',d:'1-Min Briefing Text + Audio Link. Cockpit aktualisiert.'},
    {t:'18:00',a:'Tages-Recap',d:'Was wurde abgehakt? Was ist offen? Morgen-Vorschau.'},
    {t:'21:00',a:'Karteikarten-Reminder',d:'7 Karten faellig - 5 Min reichen.'}
  ];
  steps.forEach(function(s){
    html += '<div class="cs-pipe-step"><div class="cs-pipe-time">' + s.t + '</div><div class="cs-pipe-body"><div class="cs-pipe-action">' + esc(s.a) + '</div><div class="cs-pipe-desc">' + esc(s.d) + '</div></div></div>';
  });
  html += '</div>';
  html += '<div class="cs-pipe-note">Aktiver Anteil von Christian: 5-15 Min pro Tag - Audio-Briefing hoeren, 1-2 Drafts approven, Karteikarten durchklicken. Pipeline laeuft autonom auf Hermine + Lightsail. Showcase = nicht aktiv.</div>';
  html += '</div>';
  html += '</details>';

  // ── 15. IDEEN-BACKLOG (Was sonst noch machbar ist) ──
  html += '<details open class="cs-card cs-card-ideas" data-cs-feature="ideas">';
  html += '<summary class="cs-card-head"><span class="cs-icon">IB</span><span class="cs-card-title">Ideen-Backlog</span><span class="cs-card-meta">28 Vorschlaege - voten oder verwerfen</span></summary>';
  html += '<div class="cs-card-body">';
  html += '<div class="cs-ideas-intro">Push-the-limits-Liste. Alles realistisch oder fast realistisch mit unserem Setup. Voten: ja / vielleicht / nein. Was Du auswaehlst, baue ich danach echt.</div>';
  var ideas = [
    {tier:'1',id:'i01',t:'Daily Browser-Use Scrape via Hermine',d:'Taeglich 06:00 Emeritus durchsuchen, Diff erkennen, ins RAG.'},
    {tier:'1',id:'i02',t:'Voice-DNA Forum-Drafts pre-generiert',d:'Fuer jeden neuen Post ein Reply in Deinem Stil. Du approvst nur.'},
    {tier:'1',id:'i03',t:'Assignment Pre-Grading',d:'Self-Audit gegen die Rubrik bevor Du abgibst.'},
    {tier:'1',id:'i04',t:'Audio-Briefing 5min taeglich',d:'OpenAI TTS oder ElevenLabs, Telegram Push.'},
    {tier:'1',id:'i05',t:'Karteikarten + Spaced Repetition',d:'FSRS-Algorithmus, lokal in localStorage.'},
    {tier:'1',id:'i06',t:'Deutsche Lern-Destillate aller Mini-Lessons',d:'Eine kompakte DE-Version jeder Mini-Lesson, ca. 200 Worte.'},
    {tier:'1',id:'i07',t:'RAG-Index aller ImperialKI Materialien',d:'PDFs + Transcripts + Discussion-Volltext, durchsuchbar.'},
    {tier:'1',id:'i08',t:'Telegram-Notifications bei Deadlines',d:'Hermine bei -7d, -3d, -24h, -2h.'},
    {tier:'1',id:'i09',t:'Discussion Watch + Reply-Reminder',d:'Wer hat geantwortet? Wer wartet auf eine Antwort?'},
    {tier:'1',id:'i10',t:'Networking Compass',d:'Top 5 Kontakte mit Bruecke + naechstem Schritt.'},
    {tier:'2',id:'i11',t:'Upgrade-Basics-Mini-Kurs (14 Lektionen)',d:'Selbst generiert aus den Materialien. Audio + Quiz.'},
    {tier:'2',id:'i12',t:'Cohort-Pulse Weekly',d:'Was diskutiert die Cohort? Trending topics + Word Cloud.'},
    {tier:'2',id:'i13',t:'Pre-Plagiarism Check',d:'Bevor Submission durch eigenen Filter (lokal, kein externer Service).'},
    {tier:'2',id:'i14',t:'Voice-to-Notes via Telefon',d:'Christian spricht Reflexionen am Telefon ein, Hermine transkribiert + strukturiert.'},
    {tier:'2',id:'i15',t:'AI-Use-Case-Library Klinik Barmelweid',d:'Eigene Klinik-Use-Cases fuer alle 6 Module sammeln, taggen, verbinden.'},
    {tier:'2',id:'i16',t:'Stakeholder-Map als Excalidraw',d:'Klick und ziehen, exportierbar fuer Assignment.'},
    {tier:'2',id:'i17',t:'Process-Map-Generator (Excalidraw)',d:'Aus Klinik-Workflow eine Map bauen, fuer Assignment-Submissions.'},
    {tier:'2',id:'i18',t:'Cross-Course Synthesis',d:'Verbindungen zwischen AIH (jetzt) und DTH (ab 25.06.) automatisch finden.'},
    {tier:'2',id:'i19',t:'Klinik-Doc-Auto-Tagging',d:'Klinik-PDFs nach AI-Adoption-Reife taggen.'},
    {tier:'2',id:'i20',t:'Live Session Calendar Sync',d:'Emeritus Live Sessions automatisch in Google Calendar.'},
    {tier:'3',id:'i21',t:'Eigener AI-Tutor wie Brendan',d:'Voice clone des Brendan-Sprechers (legal heikel - verworfen?).'},
    {tier:'3',id:'i22',t:'AI-Patient-Simulator',d:'Use-Cases mit simulierten Patienten validieren.'},
    {tier:'3',id:'i23',t:'Knowledge Graph Concepts',d:'Visualisierung der Verbindungen zwischen 28 Glossar-Begriffen.'},
    {tier:'3',id:'i24',t:'Real-time Co-Authoring',d:'Cockpit als VS-Code-Plugin, Assignment direkt im Editor.'},
    {tier:'3',id:'i25',t:'Personalisierter Lernplan adaptiv',d:'Algorithmus passt Tagespensum an Christians Tempo an.'},
    {tier:'3',id:'i26',t:'Patent + Paper Watch',d:'Neue Publikationen die zu Christians Use Cases passen.'},
    {tier:'3',id:'i27',t:'Cross-Cohort Compare',d:'Wo steht Christian vs. Mittelwert (Mock-Daten - DSGVO heikel).'},
    {tier:'3',id:'i28',t:'Forum-Sentiment-Analyse',d:'Welche Posts bekommen viel Engagement, was funktioniert.'}
  ];
  ideas.forEach(function(it){
    var voted = _csVoted(it.id);
    html += '<div class="cs-idea cs-tier-' + it.tier + '" data-cs-feature="' + it.id + '">';
    html += '<div class="cs-idea-tier">T' + it.tier + '</div>';
    html += '<div class="cs-idea-body"><div class="cs-idea-t">' + esc(it.t) + '</div><div class="cs-idea-d">' + esc(it.d) + '</div></div>';
    html += '<div class="cs-vote">';
    html += '<button class="cs-vote-btn cs-vote-yes' + (voted==='yes'?' cs-vote-active':'') + '" data-cs-vote="yes" onclick="_csVote(\'' + it.id + '\',\'yes\')">ja</button>';
    html += '<button class="cs-vote-btn cs-vote-maybe' + (voted==='maybe'?' cs-vote-active':'') + '" data-cs-vote="maybe" onclick="_csVote(\'' + it.id + '\',\'maybe\')">vielleicht</button>';
    html += '<button class="cs-vote-btn cs-vote-no' + (voted==='no'?' cs-vote-active':'') + '" data-cs-vote="no" onclick="_csVote(\'' + it.id + '\',\'no\')">nein</button>';
    html += '</div>';
    html += '</div>';
  });
  html += '<div class="cs-ideas-legend"><span><strong>T1</strong> heute machbar mit unserem Setup</span><span><strong>T2</strong> kleine Erweiterungen noetig</span><span><strong>T3</strong> visionaer / Limit-Push</span></div>';
  html += '</div>';
  html += '</details>';

  html += '</div>'; // end cs-grid
  html += '</div>'; // end cs-root
  html += '</div>'; // end cs-shell

  return html;
}


function renderImperialKI(container) {
  var ik = _ikCache;
  if (!ik) { container.innerHTML = '<div class="empty-state">Keine Daten.</div>'; return; }

  var now = new Date();
  var html = '';

  // Cockpit Showcase 2.0 (oben, Mock-Daten, nicht-funktional)
  html += renderCockpitShowcase();

  function countdown(dateStr) {
    var d = new Date(dateStr);
    var diff = d - now;
    if (diff <= 0) return 'vorbei';
    var days = Math.floor(diff / 86400000);
    var hours = Math.floor((diff % 86400000) / 3600000);
    if (days > 0) return 'in ' + days + (days === 1 ? ' Tag' : ' Tagen') + ', ' + hours + ' Std.';
    var mins = Math.floor((diff % 3600000) / 60000);
    return 'in ' + hours + ' Std. ' + mins + ' Min.';
  }
  function fmtDate(dateStr) {
    var d = new Date(dateStr);
    var hasTime = dateStr.indexOf('T') > -1 && dateStr.indexOf('T00:00:00') === -1;
    var datePart = d.toLocaleDateString('de-CH', {weekday:'short', day:'2-digit', month:'2-digit', year:'numeric'});
    if (hasTime) return datePart + ', ' + d.toLocaleTimeString('de-CH', {hour:'2-digit', minute:'2-digit'}) + ' Uhr';
    return datePart;
  }
  function fmtDateShort(dateStr) {
    if (!dateStr) return '';
    var d = new Date(dateStr);
    return d.toLocaleDateString('de-CH', {day:'2-digit', month:'2-digit', year:'numeric'});
  }



  // ── 1. MORGEN-BRIEFING (4 Dashboard-Cards) ──
  var br = ik.briefing || {};
  var cards = br.cards || {};

  html += '<div class="ik-briefing-header">';
  html += '<div class="ik-briefing-title">Briefing vom ' + fmtDateShort(br.date || '') + '</div>';
  if (br.generatedAt) html += '<div class="ik-briefing-meta">Aktualisiert ' + new Date(br.generatedAt).toLocaleTimeString('de-CH', {hour:'2-digit',minute:'2-digit'}) + ' Uhr</div>';
  html += '</div>';

  html += '<div class="ik-briefing-grid">';

  // Card: Neu (blau)
  var newItems = (cards.new || {}).items || [];
  html += '<details class="ik-bcard ik-bcard-new">';
  html += '<summary><span class="ik-bcard-count">' + newItems.length + '</span><span class="ik-bcard-label">Neu</span></summary>';
  if (newItems.length === 0) { html += '<div class="ik-bcard-empty">Nichts Neues seit gestern.</div>'; }
  newItems.forEach(function(item) {
    html += '<div class="ik-bcard-item">';
    if (item.url) html += '<a href="' + esc(item.url) + '" target="_blank">' + esc(item.title) + '</a>';
    else html += '<span>' + esc(item.title) + '</span>';
    if (item.details) html += '<div class="ik-bcard-details">' + esc(item.details) + '</div>';
    html += '</div>';
  });
  html += '</details>';

  // Card: Erledigt (gruen)
  var doneItems = (cards.done || {}).items || [];
  html += '<details class="ik-bcard ik-bcard-done">';
  html += '<summary><span class="ik-bcard-count">' + doneItems.length + '</span><span class="ik-bcard-label">Erledigt</span></summary>';
  if (doneItems.length === 0) { html += '<div class="ik-bcard-empty">Noch nichts abgehakt.</div>'; }
  doneItems.forEach(function(item) {
    html += '<div class="ik-bcard-item"><span>' + esc(item.title) + '</span>';
    if (item.date) html += '<span class="ik-bcard-date">' + fmtDateShort(item.date) + '</span>';
    html += '</div>';
  });
  html += '</details>';

  // Card: Diskussionen (orange)
  var discItems = (cards.discussions || {}).items || [];
  html += '<details class="ik-bcard ik-bcard-disc">';
  html += '<summary><span class="ik-bcard-count">' + discItems.length + '</span><span class="ik-bcard-label">Diskussionen</span></summary>';
  if (discItems.length === 0) { html += '<div class="ik-bcard-empty">Keine offenen Diskussionen.</div>'; }
  discItems.forEach(function(item) {
    html += '<div class="ik-bcard-item">';
    if (item.url) html += '<a href="' + esc(item.url) + '" target="_blank">' + esc(item.title) + '</a>';
    else html += '<span>' + esc(item.title) + '</span>';
    if (item.hint) html += '<div class="ik-bcard-details">' + esc(item.hint) + '</div>';
    if (item.draftId) html += '<a href="#ik-drafts" class="ik-bcard-draft-link">Entwurf lesen</a>';
    html += '</div>';
  });
  html += '</details>';

  // Card: Zu erledigen (rot)
  var dlItems = (cards.deadlines || {}).items || [];
  html += '<details open class="ik-bcard ik-bcard-todo">';
  html += '<summary><span class="ik-bcard-count">' + dlItems.length + '</span><span class="ik-bcard-label">Zu erledigen</span></summary>';
  if (dlItems.length === 0) { html += '<div class="ik-bcard-empty">Alles erledigt!</div>'; }
  dlItems.forEach(function(item) {
    var tKey = 'dl_' + (item.title||'').replace(/\W/g,'_').substring(0,30);
    var tDone = isIkDone(tKey);
    html += '<div class="ik-bcard-item ik-bcard-task' + (tDone ? ' ik-done' : '') + '">';
    html += '<input type="checkbox" class="ik-checkbox" ' + (tDone ? 'checked' : '') + ' onchange="toggleIkDone(\'' + tKey + '\')"/>';
    if (item.url) html += '<a href="' + esc(item.url) + '" target="_blank">' + esc(item.title) + '</a>';
    else html += '<span>' + esc(item.title) + '</span>';
    var meta = [];
    if (item.deadline) meta.push('bis ' + fmtDateShort(item.deadline));
    if (item.estimatedMinutes) meta.push('~' + item.estimatedMinutes + ' min');
    if (meta.length) html += '<span class="ik-bcard-meta' + (item.priority === 'high' ? ' ik-priority-high' : '') + '">' + meta.join(' | ') + '</span>';
    if (tDone) html += '<span class="ik-done-ts">' + ikDoneTimestamp(tKey) + '</span>';
    html += '</div>';
  });
  html += '</details>';

  html += '</div>'; // end briefing-grid

  // ── 2. TAGES-COACH ──
  var coach = ik.coach || {};
  var plan = coach.dailyPlan || [];

  html += '<div class="ik-coach-box">';
  html += '<div class="ik-coach-header">';
  html += '<div class="ik-coach-title">Dein Tagesplan</div>';
  if (coach.currentPhase) html += '<span class="ik-coach-phase">' + esc(coach.currentPhase) + '</span>';
  html += '</div>';

  if (coach.weeklyFocus) {
    html += '<div class="ik-coach-focus">' + esc(coach.weeklyFocus) + '</div>';
  }

  // Progress bar
  if (plan.length > 0) {
    var planDone = plan.filter(function(p) { var k = 'plan_' + (p.title||'').replace(/\W/g,'_').substring(0,30); return isIkDone(k); }).length;
    var pct = Math.round(planDone / plan.length * 100);
    html += '<div class="ik-coach-progress">';
    html += '<div class="ik-coach-progress-bar" style="width:' + pct + '%;"></div>';
    html += '</div>';
    html += '<div class="ik-coach-progress-label">' + planDone + ' von ' + plan.length + ' erledigt</div>';
  }

  var TYPE_ICONS = { admin: '\u{1F4CB}', test: '\u{1F4DD}', networking: '\u{1F91D}', study: '\u{1F4D6}', assignment: '\u{1F4DA}', discussion: '\u{1F4AC}' };
  plan.forEach(function(item) {
    var pKey = 'plan_' + (item.title||'').replace(/\W/g,'_').substring(0,30);
    var pDone = isIkDone(pKey);
    var icon = TYPE_ICONS[item.type] || '\u{2022}';
    html += '<div class="ik-coach-item' + (pDone ? ' ik-done' : '') + '">';
    html += '<input type="checkbox" class="ik-checkbox" ' + (pDone ? 'checked' : '') + ' onchange="toggleIkDone(\'' + pKey + '\')"/>';
    html += '<span class="ik-coach-icon">' + icon + '</span>';
    if (item.url) html += '<a href="' + esc(item.url) + '" target="_blank" class="ik-coach-task-name">' + esc(item.title) + '</a>';
    else html += '<span class="ik-coach-task-name">' + esc(item.title) + '</span>';
    if (item.estimatedMinutes) html += '<span class="ik-coach-time">~' + item.estimatedMinutes + ' min</span>';
    if (pDone) html += '<span class="ik-done-ts">' + ikDoneTimestamp(pKey) + '</span>';
    html += '</div>';
  });

  // Tips
  if (coach.tips && coach.tips.length > 0) {
    html += '<div class="ik-coach-tips">';
    coach.tips.forEach(function(tip) {
      html += '<div class="ik-coach-tip">' + esc(tip) + '</div>';
    });
    html += '</div>';
  }

  // Milestone
  if (coach.nextMilestone) {
    var ms = coach.nextMilestone;
    html += '<div class="ik-coach-milestone">';
    html += '<span class="ik-coach-milestone-label">Naechster Meilenstein:</span> ';
    html += '<strong>' + esc(ms.title) + '</strong>';
    if (ms.target) html += ' <span class="ik-coach-milestone-date">(' + countdown(ms.target + 'T23:59:00Z') + ')</span>';
    html += '</div>';
  }

  html += '</div>'; // end coach-box

  // ── 3. VORBEREITETE ENTWUERFE ──
  var drafts = ik.drafts || [];
  if (drafts.length > 0) {
    html += '<details class="ik-section" id="ik-drafts">';
    html += '<summary class="ik-section-title">Vorbereitete Entwuerfe (' + drafts.length + ')</summary>';
    drafts.forEach(function(draft) {
      var statusClass = draft.status === 'posted' ? 'ik-draft-posted' : draft.status === 'skipped' ? 'ik-draft-skipped' : '';
      html += '<div class="ik-draft-card ' + statusClass + '">';
      html += '<div class="ik-draft-header">';
      html += '<span class="ik-draft-type">' + esc(draft.type || 'Entwurf') + '</span>';
      if (draft.status) html += '<span class="ik-draft-status ik-draft-status-' + draft.status + '">' + esc(draft.status) + '</span>';
      html += '</div>';
      if (draft.context) html += '<div class="ik-draft-context">' + esc(draft.context) + '</div>';
      html += '<div class="ik-draft-content">' + esc(draft.content) + '</div>';
      html += '<div class="ik-draft-actions">';
      html += '<button class="ik-draft-copy" data-draft-copy="' + esc(draft.id) + '" onclick="ikCopyDraft(\'' + esc(draft.id) + '\')">Kopieren</button>';
      if (draft.targetUrl) html += '<a href="' + esc(draft.targetUrl) + '" target="_blank" class="ik-draft-post">Auf Emeritus posten</a>';
      html += '</div>';
      html += '</div>';
    });
    html += '</details>';
  }

  // ── 4. ZEITPLAN (Termine + Deadlines merged) ──
  html += '<details open class="ik-section">';
  html += '<summary class="ik-section-title">Zeitplan</summary>';
  var upcoming = (ik.schedule || []).filter(function(ev) { return new Date(ev.date) > now; }).sort(function(a,b) { return a.date.localeCompare(b.date); });
  if (upcoming.length === 0) {
    html += '<div class="ik-card-sub" style="padding:8px 0;">Keine kommenden Termine.</div>';
  } else {
    upcoming.forEach(function(ev) {
      var color = ev.type === 'live' ? '#3b82f6' : ev.type === 'deadline' ? '#ef4444' : '#f59e0b';
      var label = ev.type === 'live' ? 'Live' : ev.type === 'deadline' ? 'Deadline' : 'Event';
      var courseColor = ik.courses[ev.course] ? ik.courses[ev.course].color : '#6b7280';
      html += '<div class="ik-entry">';
      html += '<span class="ik-time">' + fmtDate(ev.date) + '</span>';
      html += '<span class="ik-badge" style="background:' + color + ';">' + label + '</span>';
      html += '<span class="ik-dot" style="background:' + courseColor + ';"></span>';
      html += '<span class="ik-name">' + esc(ev.title) + '</span>';
      html += '<span class="ik-right">' + countdown(ev.date) + '</span>';
      html += '</div>';
    });
  }
  html += '</details>';

  // ── 5. KURS-DETAILS (Accordions) ──
  Object.keys(ik.courses).forEach(function(ck) {
    var c = ik.courses[ck];
    var isActive = c.status === 'active';
    html += '<details' + (isActive ? ' open' : '') + ' class="ik-section">';
    html += '<summary class="ik-section-title" style="color:' + c.color + ';">' + esc(c.shortName);
    if (c.started) html += ' <span style="font-weight:400;font-size:11px;color:var(--text-muted);">(seit ' + fmtDateShort(c.started) + ')</span>';
    else if (c.starts) html += ' <span style="font-weight:400;font-size:11px;color:var(--text-muted);">(Start: ' + fmtDateShort(c.starts) + ')</span>';
    html += '</summary>';

    // Modules
    if (c.modules && c.modules.length > 0) {
      html += '<div style="margin-bottom:12px;">';
      html += '<div class="sl-section-title">Module</div>';
      c.modules.forEach(function(mod) {
        var statusBadge = mod.status === 'locked' ? '\uD83D\uDD12' : mod.status === 'open' ? '\uD83D\uDCD6' : '\u2705';
        html += '<div class="ik-module-card">';
        html += '<span class="ik-module-icon">' + statusBadge + '</span>';
        html += '<div style="flex:1;">';
        html += '<div class="ik-module-title">' + esc(mod.id + ': ' + mod.title) + '</div>';
        html += '<div class="ik-module-desc">' + esc(mod.description) + '</div>';
        html += '<div class="ik-module-desc">~' + mod.hours + ' Stunden</div>';
        html += '</div></div>';
      });
      html += '</div>';
    }

    // Discussions
    if (c.discussions && c.discussions.length > 0) {
      html += '<div style="margin-bottom:8px;">';
      html += '<div class="sl-section-title">Diskussionen</div>';
      c.discussions.forEach(function(disc) {
        var icon = disc.status === 'posted' ? '\u2705' : '\u270F\uFE0F';
        html += '<div class="ik-entry" style="padding:6px 16px;">';
        html += '<span>' + icon + '</span>';
        html += '<a href="' + esc(disc.url) + '" target="_blank" style="color:' + c.color + ';" class="ik-name">' + esc(disc.title) + '</a>';
        html += '<span class="ik-right">' + (disc.status === 'posted' ? 'gepostet ' + fmtDateShort(disc.postedDate) : 'offen') + '</span>';
        html += '</div>';
      });
      html += '</div>';
    }

    if (!isActive && c.starts) {
      html += '<div class="ik-card-sub" style="padding:8px 14px;">Kurs startet am ' + fmtDateShort(c.starts) + '.</div>';
    }
    html += '</details>';
  });

  // ── 6. WISSENSDATENBANK + TRIP REPORT + LOGBUCH ──
  // Trip Report
  html += '<details class="ik-section">';
  html += '<summary class="ik-section-title">Trip Report / Blog</summary>';
  var tr = ik.tripReport || {};
  html += '<div class="ik-info-card">';
  html += '<div class="ik-info-title">Reflective Journal Anfrage</div>';
  html += 'Email gesendet: ' + fmtDateShort(tr.emailSent || '') + '<br>';
  html += 'Status: <span style="color:#f59e0b;font-weight:600;">' + (tr.status === 'awaiting_response' ? 'Warte auf Antwort' : tr.status || '?') + '</span><br>';
  if (tr.followUpDate) html += 'Follow-up geplant: ' + fmtDateShort(tr.followUpDate);
  html += '</div>';
  html += '</details>';

  // Wissensdatenbank
  html += '<details class="ik-section">';
  html += '<summary class="ik-section-title">Wissensdatenbank</summary>';
  var kb = ik.knowledgeBase || {};
  html += '<div class="ik-info-card">';
  html += '<strong>Klinik-Dokumente:</strong> ' + ((kb.clinicDocs || []).join(', ') || 'Keine') + '<br>';
  html += '<strong>Transkripte:</strong> ' + ((kb.transcripts || []).length || 0) + ' Dateien<br>';
  html += '<strong>NotebookLM:</strong> ' + (kb.notebookLM || 'nicht konfiguriert');
  html += '</div>';

  if (kb.grokResearch) {

    html += '<div class="ik-info-card" style="margin-top:8px;">';

    html += '<div class="ik-info-title" style="font-size:11px;">Grok-Recherche: AI in Psychiatric Rehab Europe</div>';

    html += '<div style="font-size:11px;">' + esc(kb.grokResearch) + '</div>';

    html += '</div>';

  }

  html += '</details>';



  // ── PROFIL ──

  html += '<details class="ik-section">';

  html += '<summary class="ik-section-title">Mein Profil</summary>';

  var pr = ik.profile || {};

  html += '<div class="ik-info-card">';

  html += '<strong>' + esc(pr.name || '') + '</strong> \u2014 ' + esc(pr.role || '') + '<br>';

  html += esc(pr.clinic || '') + ', ' + esc(pr.department || '') + '<br>';

  html += 'Arbeitstage: ' + esc(pr.workDays || '') + '<br>';

  html += 'Fokus: ' + esc(pr.focus || '') + '<br>';

  html += 'Hintergrund: ' + esc(pr.background || '');

  html += '</div>';

  html += '</details>';



  container.innerHTML = html;

}



// ─── SYSTEM-UEBERSICHT (Mermaid lazy-load) ──────────────────────────────────

var _mermaidLoaded = false;
function initUebersichtMermaid() {
  var container = document.getElementById('ub-mermaid');
  if (!container) return;
  var isDark = document.documentElement.classList.contains('dark-theme');
  var graphDef = [
    'graph LR',
    '  subgraph User[" "]',
    '    Browser["Browser / PWA"]',
    '    TG["Telegram / WhatsApp"]',
    '    CLI["Terminal / Claude Code"]',
    '  end',
    '  subgraph Agents["CoworkOS"]',
    '    LifeOS["LifeOS\\nDashboard"]',
    '    Hermine["Hermine\\n24/7 Bot"]',
    '    KITT["KITT\\nDev Agent"]',
    '  end',
    '  subgraph Data["GitHub"]',
    '    CK["CoworkKanban\\nCode"]',
    '    CD["cowork-data\\nDaten"]',
    '    DM["dispatch-memory\\nDocs"]',
    '  end',
    '  Browser --> LifeOS',
    '  TG --> Hermine',
    '  CLI --> KITT',
    '  LifeOS -- "R/W" --> CD',
    '  Hermine -- "R/W" --> CD',
    '  Hermine -- "R" --> DM',
    '  KITT -- "R/W" --> CK',
    '  KITT -- "R/W" --> DM',
    '  KITT -. "deploy" .-> LifeOS',
    '  Hermine -. "eskaliert" .-> KITT'
  ].join('\n');

  function renderDiagram() {
    var theme = isDark ? 'dark' : 'default';
    var vars = isDark ? {
      primaryColor: '#3d352a', primaryTextColor: '#e8e0d4', primaryBorderColor: '#c47a2a',
      lineColor: '#9a8e7d', secondaryColor: '#2e2820', background: '#252019',
      mainBkg: '#2e2820', nodeBorder: '#c47a2a', clusterBkg: '#1a1714', clusterBorder: '#3d352a'
    } : {
      primaryColor: '#fff7ed', primaryTextColor: '#1a1815', primaryBorderColor: '#c47a2a',
      lineColor: '#6b6560', secondaryColor: '#f5f0ea', background: '#ffffff',
      mainBkg: '#fff7ed', nodeBorder: '#c47a2a', clusterBkg: '#f5f0ea', clusterBorder: '#e8e3dc'
    };
    mermaid.initialize({ startOnLoad: false, theme: theme, themeVariables: vars, securityLevel: 'loose' });
    mermaid.render('ub-mermaid-svg', graphDef).then(function(result) {
      container.innerHTML = result.svg;
    }).catch(function() {
      container.innerHTML = '<div class="empty-state">Diagramm konnte nicht gerendert werden.</div>';
    });
  }

  if (_mermaidLoaded) { renderDiagram(); return; }
  container.innerHTML = '<div class="empty-state">Lade Diagramm...</div>';
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js';
  s.onload = function() { _mermaidLoaded = true; renderDiagram(); };
  s.onerror = function() { container.innerHTML = '<div class="empty-state">Mermaid konnte nicht geladen werden (offline?).</div>'; };
  document.head.appendChild(s);
}

(function() {
  var dd = document.getElementById('uebersicht-dropdown');
  if (dd) dd.addEventListener('toggle', function() { if (dd.open) initUebersichtMermaid(); });
})();

// ─── SYSTEM LOG ─────────────────────────────────────────────────────────────

async function showSystemTab() {

  var container = document.getElementById('system-log-container');

  if (!container) return;

  container.innerHTML = '<div class="empty-state">Wird geladen\u2026</div>';

  var token = getGHToken();

  if (!token) {

    container.innerHTML = '<div class="empty-state">Bitte Token in Einstellungen eintragen.</div>';

    return;

  }

  try {

    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/system-log.json',

      { headers: { Authorization: 'token ' + token } });

    if (!r.ok) throw new Error('HTTP ' + r.status);

    var d = await r.json();

    _systemLogCache = JSON.parse(decodeBase64Utf8(d.content));

  } catch(e) {

    container.innerHTML = '<div class="empty-state">Fehler beim Laden: ' + esc(e.message) + '</div>';

    return;

  }

  renderSystemLog(container);

}



function renderSystemLog(container) {

  var entries = (_systemLogCache && _systemLogCache.entries) || [];

  if (entries.length === 0) {

    container.innerHTML = '<div class="empty-state">Keine Eintr\u00e4ge.</div>';

    return;

  }



  var TYPE_COLORS = {

    deploy:  { bg: '#c47a2a', label: 'Deploy' },

    fix:     { bg: '#b45309', label: 'Fix' },

    success: { bg: '#15803d', label: 'Erfolg' },

    error:   { bg: '#b91c1c', label: 'Fehler' },

    info:    { bg: '#6b7280', label: 'Info' }

  };



  var now = new Date();

  var yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);



  // Sort newest first

  var sorted = entries.slice().sort(function(a, b) { return b.ts.localeCompare(a.ts); });



  // Split into last 24h vs older

  var recent = sorted.filter(function(e) { return new Date(e.ts) >= yesterday; });

  var older  = sorted.filter(function(e) { return new Date(e.ts) < yesterday; });



  // Group older by KW

  var byKW = {};

  older.forEach(function(e) {

    var d = new Date(e.ts);

    var startOfYear = new Date(d.getFullYear(), 0, 1);

    var dayOfYear = Math.ceil((d - startOfYear) / 86400000);

    var kw = Math.ceil((dayOfYear + startOfYear.getDay()) / 7);

    var kwKey = 'KW\u00a0' + String(kw).padStart(2, '0') + '\u00a0(' + d.getFullYear() + ')';

    if (!byKW[kwKey]) byKW[kwKey] = [];

    byKW[kwKey].push(e);

  });



  function entryHtml(e) {

    var tc = TYPE_COLORS[e.type] || TYPE_COLORS.info;

    var d = new Date(e.ts);

    var timeStr = d.toLocaleDateString('de-CH', {day:'2-digit',month:'2-digit'}) + ' '

      + d.toLocaleTimeString('de-CH', {hour:'2-digit', minute:'2-digit'});

    var detailId = 'syslog-detail-' + Math.random().toString(36).slice(2);

    return '<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);">'

      + '<span style="font-size:11px;color:var(--text-muted);min-width:80px;padding-top:2px;">' + timeStr + '</span>'

      + '<span style="background:' + tc.bg + ';color:#fff;font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;min-width:52px;text-align:center;flex-shrink:0;">' + tc.label + '</span>'

      + '<div style="flex:1;min-width:0;">'

      + '<div style="font-weight:600;font-size:13px;color:var(--text);">' + esc(e.title) + '</div>'

      + (e.details ? '<div style="font-size:12px;color:var(--text-muted);margin-top:3px;">' + esc(e.details) + '</div>' : '')

      + '</div></div>';

  }



  var html = '';



  // Letzte 24h section

  html += '<div style="margin-bottom:20px;">';

  html += '<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--accent);margin-bottom:8px;">Letzte 24h</div>';

  if (recent.length === 0) {

    html += '<div class="empty-state" style="padding:16px 0;">Keine Aktivit\u00e4t in den letzten 24 Stunden.</div>';

  } else {

    recent.forEach(function(e) { html += entryHtml(e); });

  }

  html += '</div>';



  // Older grouped by KW

  Object.keys(byKW).sort().reverse().forEach(function(kw) {

    var kwId = 'kw-' + kw.replace(/\s/g, '');

    html += '<details style="margin-bottom:12px;" open>'

      + '<summary style="cursor:pointer;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);padding:6px 0;list-style:none;display:flex;align-items:center;gap:8px;">'

      + '<span style="color:var(--accent);">&#9660;</span>' + esc(kw)

      + '<span style="font-weight:400;color:var(--text-muted);">(' + byKW[kw].length + ' Eintr\u00e4ge)</span>'

      + '</summary>';

    byKW[kw].forEach(function(e) { html += entryHtml(e); });

    html += '</details>';

  });



  container.innerHTML = html;

}



// ─── COLLECT TAB ──────────────────────────────────────────────────────────────

function getCollect() { return ls('cowork_collect', null); }

function saveCollect(c) { lsSet('cowork_collect', c); }

function initCollect() { if (!getCollect()) { saveCollect({categories:['KI','Tools','Gesundheit','Finanzen','Lernen','Sonstiges'],items:[]}); } }



function renderCollect() {

  var data = getCollect() || {categories:[], items:[]};

  var toc = document.getElementById('collect-toc');

  var list = document.getElementById('collect-list');

  if (!toc || !list) return;



  if (data.items.length === 0) {

    toc.innerHTML = '';

    list.innerHTML = '<div class="empty-state">Keine Links gesammelt.</div>';

    return;

  }



  var cats = data.categories || [];

  toc.innerHTML = '<div class="collect-toc-bar">' + cats.map(function(cat) {

    var count = data.items.filter(function(i){return i.category===cat;}).length;

    if (count === 0) return '';

    return '<a class="collect-toc-link" href="#collect-cat-'+esc(cat)+'" onclick="event.preventDefault();document.getElementById(\'collect-cat-'+esc(cat)+'\').scrollIntoView({behavior:\'smooth\'})">'+esc(cat)+' ('+count+')</a>';

  }).join('') + '</div>';



  var html = '';

  cats.forEach(function(cat) {

    var items = data.items.filter(function(i){return i.category===cat;}).sort(function(a,b){return (b.createdAt||'').localeCompare(a.createdAt||'');});

    if (items.length === 0) return;

    html += '<div class="collect-cat-section" id="collect-cat-'+esc(cat)+'">';

    html += '<h3 class="collect-cat-title">'+esc(cat)+'</h3>';

    items.forEach(function(item) {

      var date = new Date(item.createdAt).toLocaleDateString('de-CH');

      html += '<div class="collect-card" onclick="openCollectModal(\''+esc(item.id)+'\')">';

      html += '<div class="collect-card-header">';

      html += '<span class="collect-card-title">'+esc(item.title || item.url)+'</span>';

      html += '<span class="collect-card-date">'+date+'</span>';

      html += '</div>';

      if (item.url) html += '<div class="collect-card-url">'+esc(item.url)+'</div>';

      if (item.description) html += '<div class="collect-card-desc">'+esc(item.description)+'</div>';

      if (item.screenshot) html += '<div class="collect-card-img"><img src="https://raw.githubusercontent.com/ctmos/cowork-data/main/data/collect-images/'+esc(item.screenshot)+'" alt="Screenshot" loading="lazy"></div>';

      html += '<div class="collect-card-meta"><span class="collect-card-by">'+esc(item.createdBy||'')+'</span></div>';

      html += '</div>';

    });

    html += '</div>';

  });

  list.innerHTML = html;

}



var collectEntryId = null;

function openCollectModal(entryId) {

  collectEntryId = entryId;

  var data = getCollect() || {categories:[],items:[]};

  var entry = entryId ? data.items.find(function(e){return e.id===entryId;}) : null;

  var isNew = !entry;

  document.getElementById('collect-modal-title').textContent = isNew ? 'Link sammeln' : 'Eintrag bearbeiten';

  document.getElementById('colm-url').value = (entry&&entry.url)||'';

  document.getElementById('colm-title').value = (entry&&entry.title)||'';

  document.getElementById('colm-desc').value = (entry&&entry.description)||'';

  document.getElementById('colm-cat').value = (entry&&entry.category)||data.categories[0]||'Sonstiges';

  document.getElementById('colm-delete').style.display = isNew ? 'none' : '';

  document.getElementById('colm-screenshot').value = '';

  var dl = document.getElementById('collect-cats');

  dl.innerHTML = data.categories.map(function(c){return '<option value="'+esc(c)+'">';}).join('');

  document.getElementById('collect-modal-overlay').classList.add('open');

}

function closeCollectModal() {

  document.getElementById('collect-modal-overlay').classList.remove('open');

  collectEntryId = null;

}



document.getElementById('btn-collect-add').addEventListener('click', function(){ openCollectModal(null); });



document.getElementById('colm-save').addEventListener('click', function() {

  var url = document.getElementById('colm-url').value.trim();

  var title = document.getElementById('colm-title').value.trim();

  var desc = document.getElementById('colm-desc').value.trim();

  var cat = document.getElementById('colm-cat').value;

  if (!url && !title) { document.getElementById('colm-url').focus(); return; }

  if (!title) title = url;

  var data = getCollect() || {categories:[],items:[]};



  var fileInput = document.getElementById('colm-screenshot');

  var file = fileInput.files && fileInput.files[0];



  if (collectEntryId) {

    var idx = data.items.findIndex(function(e){return e.id===collectEntryId;});

    if (idx !== -1) data.items[idx] = Object.assign({}, data.items[idx], {url:url, title:title, description:desc, category:cat});

  } else {

    var newId = 'col_' + Date.now();

    var item = {id:newId, url:url, title:title, description:desc, category:cat, screenshot:null, createdAt:new Date().toISOString(), createdBy:'User'};

    data.items.push(item);



    if (file) {

      item.screenshot = newId + '.png';

      var reader = new FileReader();

      reader.onload = function(ev) {

        var b64 = ev.target.result.split(',')[1];

        safeWriteToGitHub('data/collect-images/' + item.screenshot, b64, 'upload: screenshot ' + item.screenshot);

      };

      reader.readAsDataURL(file);

    }

  }



  if (cat && data.categories.indexOf(cat) === -1) data.categories.push(cat);



  saveCollect(data);

  closeCollectModal();

  renderCollect();

  fileInput.value = '';

});



document.getElementById('colm-delete').addEventListener('click', function() {

  confirmAction('Link löschen?', 'Dieser Eintrag wird gelöscht.', function() {

    var data = getCollect() || {categories:[],items:[]};

    data.items = data.items.filter(function(e){return e.id !== collectEntryId;});

    saveCollect(data);

    closeCollectModal();

    renderCollect();

  });

});



document.getElementById('colm-cancel').addEventListener('click', closeCollectModal);

document.getElementById('collect-modal-overlay').addEventListener('click', function(e) {

  if (e.target === e.currentTarget) closeCollectModal();

});



// ─── SERVICE WORKER: Auto-Update ─────────────────────────────────────────────

if ('serviceWorker' in navigator) {

  var swPath = location.hostname === 'lifeos.moser.ai' ? '/sw.js' : '/CoworkKanban/sw.js';
  navigator.serviceWorker.register(swPath, { updateViaCache: 'none' }).then(function(reg) {

    // Check for updates on every page load

    reg.update();

    // When new SW is found and installed, auto-reload

    reg.addEventListener('updatefound', function() {

      var newWorker = reg.installing;

      newWorker.addEventListener('statechange', function() {

        if (newWorker.state === 'activated') {

          console.log('[SW] New version activated — reloading');

          window.location.reload();

        }

      });

    });

  }).catch(function(err) { console.warn('[SW] Registration failed:', err); });

}



// ─── BOOT ─────────────────────────────────────────────────────────────────────

// Skip PIN screen if session is still valid (hard reload)
if (sessionStorage.getItem('cowork_pin_set') === 'true') {
  var savedPin = sessionStorage.getItem('cowork_pin_val');
  if (savedPin) {
    // Derive patient encryption key from PIN, then restore token
    deriveKeyFromPin(savedPin, 'lifeos-patient-enc').then(function(k) {
      _encKey = k;
      return unlockSecureVault(savedPin);
    }).then(function(ok) {
      if (!ok && !_appState.gh_token) {
        var saved = localStorage.getItem('cowork_gh_token');
        if (saved) _appState.gh_token = saved;
      }
      unlockApp();
    });
  } else {
    // PIN val lost but session flag set — fallback to login
    initPinScreen();
  }
} else {
  initPinScreen();
}





// ─── KEYBOARD SHORTCUTS ──────────────────────────────────────────────────────

document.addEventListener('keydown', function(e) {

  // Ctrl+S or Cmd+S: Force sync

  if ((e.ctrlKey || e.metaKey) && e.key === 's') {

    e.preventDefault();

    if (getGHToken()) {

      showToast('Synchronisiere...', 'info');

      scheduleSyncToGitHub();

    }

  }

  // Escape: Close any open modal

  if (e.key === 'Escape') {

    closeCardModal();

    closePatModal();

  }

});



// ─── OFFLINE WRITE QUEUE ─────────────────────────────────────────────────────

window._pendingWrites = JSON.parse(localStorage.getItem('cowork_pending_writes') || '[]');



function queueOfflineWrite(key, data, msg) {

  window._pendingWrites.push({key: key, data: data, msg: msg, ts: Date.now()});

  localStorage.setItem('cowork_pending_writes', JSON.stringify(window._pendingWrites));

  showToast('Offline gespeichert \u2014 wird synchronisiert wenn online', 'info');

}



async function flushOfflineQueue() {

  if (window._pendingWrites.length === 0) return;

  var queue = window._pendingWrites.slice();

  window._pendingWrites = [];

  localStorage.removeItem('cowork_pending_writes');

  for (var i = 0; i < queue.length; i++) {

    try {

      await safeWriteToGitHub(queue[i].key, JSON.stringify(queue[i].data, null, 2), queue[i].msg);

    } catch (err) {

      console.error('[OFFLINE-QUEUE] Write failed:', err);

      window._pendingWrites.push(queue[i]);

    }

  }

  if (window._pendingWrites.length > 0) {

    localStorage.setItem('cowork_pending_writes', JSON.stringify(window._pendingWrites));

  }

}



// Flush queue when coming back online

window.addEventListener('online', function() { setTimeout(flushOfflineQueue, 2000); });





// Auto-refresh calendar every 30 min

setInterval(function() {

  if (navigator.onLine && typeof loadCalendarEvents === 'function') {

    loadCalendarEvents().then(function() {

      if (currentTab === 'heute') renderHeute();

      console.log('[CAL] Auto-refreshed');

    }).catch(function() {});

  }

  if (navigator.onLine && typeof loadHannahSummary === 'function') {

    loadHannahSummary().then(function() {

      if (currentTab === 'kanban') renderHannahSummary();

    }).catch(function() {});

  }

}, 30 * 60 * 1000);



// ─── TOUCH DRAG & DROP ───────────────────────────────────────────────────────────────────

(function() {

  var dragCard = null;

  var dragCardId = null;

  var touchStartY = 0;

  var isDragging = false;



  document.addEventListener('touchstart', function(e) {

    var card = e.target.closest('.card-item');

    if (!card || !card.dataset.id) return;

    dragCard = card;

    dragCardId = card.dataset.id;

    touchStartY = e.touches[0].clientY;

    isDragging = false;

  }, {passive: true});



  document.addEventListener('touchmove', function(e) {

    if (!dragCard) return;

    var dy = Math.abs(e.touches[0].clientY - touchStartY);

    if (dy > 20 && !isDragging) {

      isDragging = true;

      dragCard.classList.add('dragging-touch');

    }

    if (isDragging) {

      // Highlight lane under finger

      var el = document.elementFromPoint(e.touches[0].clientX, e.touches[0].clientY);

      document.querySelectorAll('.lane.drag-over-touch').forEach(function(l) { l.classList.remove('drag-over-touch'); });

      var lane = el ? el.closest('.lane') : null;

      if (lane) lane.classList.add('drag-over-touch');

    }

  }, {passive: true});



  document.addEventListener('touchend', function(e) {

    if (!dragCard || !isDragging || !dragCardId) { dragCard = null; return; }

    dragCard.classList.remove('dragging-touch');

    document.querySelectorAll('.lane.drag-over-touch').forEach(function(l) { l.classList.remove('drag-over-touch'); });



    // Find which lane the finger ended on

    var touch = e.changedTouches[0];

    var el = document.elementFromPoint(touch.clientX, touch.clientY);

    var lane = el ? el.closest('.lane') : null;

    if (lane && lane.dataset.lane) {

      var targetLane = lane.dataset.lane || (lane.id ? lane.id.replace('lane-','') : null);

      var cards = getCards();

      if (cards[dragCardId] && cards[dragCardId].lane !== targetLane) {

        var oldLane = cards[dragCardId].lane;

        cards[dragCardId].lane = targetLane;

        saveCards(cards);

        showToast(dragCardId + ' → ' + targetLane);

        renderKanban();

      }

    }

    dragCard = null;

    dragCardId = null;

    isDragging = false;

  });

})();



// ─── DESKTOP DRAG & DROP between lanes ──────────────────────────────────────

(function() {

  // Make cards draggable

  document.addEventListener('dragstart', function(e) {

    // Lane-Drag via drag-handle
    var handle = e.target.closest('.lane-drag-handle');
    if (handle) {
      var hLane = handle.closest('.lane');
      if (!hLane) return;
      var laneId = hLane.dataset.lane || hLane.id.replace('lane-','');
      e.dataTransfer.setData('text/plain', 'lane:' + laneId);
      e.dataTransfer.effectAllowed = 'move';
      hLane.classList.add('lane-dragging');
      return;
    }

    var card = e.target.closest('.card-item');

    if (!card) return;

    var cardId = card.dataset.id;

    if (!cardId) return;

    e.dataTransfer.setData('text/plain', cardId);

    e.dataTransfer.effectAllowed = 'move';

    card.style.opacity = '0.5';

    setTimeout(function() {

      document.querySelectorAll('.lane').forEach(function(l) {

        l.classList.add('drop-target-hint');

      });

    }, 0);

  });



  document.addEventListener('dragend', function(e) {

    var card = e.target.closest('.card-item');

    if (card) card.style.opacity = '1';

    document.querySelectorAll('.lane').forEach(function(l) {

      l.classList.remove('drop-target-hint', 'drag-over', 'lane-dragging', 'lane-drop-before', 'lane-drop-after');

    });

  });



  document.addEventListener('dragover', function(e) {

    var lane = e.target.closest('.lane');

    if (!lane) return;

    e.preventDefault();

    e.dataTransfer.dropEffect = 'move';

    document.querySelectorAll('.lane.drag-over').forEach(function(l) { l.classList.remove('drag-over'); });

    lane.classList.add('drag-over');

  });



  document.addEventListener('dragleave', function(e) {

    var lane = e.target.closest('.lane');

    if (lane) lane.classList.remove('drag-over');

  });



  document.addEventListener('drop', function(e) {

    e.preventDefault();

    var lane = e.target.closest('.lane');

    if (!lane) return;

    lane.classList.remove('drag-over', 'lane-drop-before', 'lane-drop-after');

    document.querySelectorAll('.drop-target-hint,.lane-dragging,.lane-drop-before,.lane-drop-after').forEach(function(l) { l.classList.remove('drop-target-hint','lane-dragging','lane-drop-before','lane-drop-after'); });



    var raw = e.dataTransfer.getData('text/plain');

    // LANE REORDER
    if (raw && raw.indexOf('lane:') === 0) {
      var sourceLaneId = raw.slice(5);
      var targetLaneId = lane.dataset.lane || lane.id.replace('lane-','');
      if (sourceLaneId === targetLaneId) return;
      var order = getLaneOrder() || LANES.map(function(l) { return l.id; });
      // Remove source from current position
      order = order.filter(function(id) { return id !== sourceLaneId; });
      // Determine insertion index based on cursor position relative to target lane
      var laneRect = lane.getBoundingClientRect();
      var midY = laneRect.top + laneRect.height / 2;
      var targetIdx = order.indexOf(targetLaneId);
      if (targetIdx === -1) targetIdx = order.length;
      if (e.clientY >= midY) targetIdx += 1;
      order.splice(targetIdx, 0, sourceLaneId);
      saveLaneOrder(order);
      showToast('Lane ' + sourceLaneId + ' verschoben');
      renderKanban();
      return;
    }

    var cardId = raw;

    var targetLane = lane.dataset.lane || (lane.id ? lane.id.replace('lane-','') : null);

    if (!cardId || !targetLane) return;



    var cards = getCards();

    var card = cards[cardId];

    if (!card) return;

    // Determine insertion index: find target card under cursor (if any)
    var overCard = e.target.closest('.card-item');
    var insertBeforeId = null;
    if (overCard && overCard.dataset.id && overCard.dataset.id !== cardId) {
      var rect = overCard.getBoundingClientRect();
      var midY = rect.top + rect.height / 2;
      if (e.clientY < midY) {
        insertBeforeId = overCard.dataset.id;
      } else {
        // Insert after overCard: find next sibling card
        var next = overCard.nextElementSibling;
        while (next && !next.classList.contains('card-item')) next = next.nextElementSibling;
        insertBeforeId = next ? next.dataset.id : null;
      }
    }

    // Same-lane reorder
    if (card.lane === targetLane) {
      var laneCards = Object.values(cards)
        .filter(function(c) { return !c.archived && c.lane === targetLane && c.status !== 'erledigt'; })
        .sort(function(a,b) { return (a.order||0) - (b.order||0) || a.id.localeCompare(b.id); });
      // Remove dragged card from list
      laneCards = laneCards.filter(function(c) { return c.id !== cardId; });
      // Find insertion index
      var idx = laneCards.length;
      if (insertBeforeId) {
        var foundIdx = laneCards.findIndex(function(c) { return c.id === insertBeforeId; });
        if (foundIdx !== -1) idx = foundIdx;
      }
      laneCards.splice(idx, 0, card);
      // Reassign order values
      laneCards.forEach(function(c, i) { cards[c.id].order = (i + 1) * 1000; });
      saveCards(cards);
      showToast(cardId + ' neu sortiert');
      renderKanban();
      if (currentTab === 'heute') renderHeute();
      return;
    }

    // Cross-lane move
    var oldLane = card.lane;

    var oldId = card.id;



    // Generate new ID for target lane

    var newId = nextCardId(targetLane);



    // Move card: delete old, create new with new ID

    delete cards[oldId];

    card.id = newId;

    card.lane = targetLane;

    // Clear todayFlag when moving OUT of today-group lanes

    var todayGroup = ['HE','HB','HD','JZ'];

    if (todayGroup.indexOf(targetLane) === -1) {

      card.todayFlag = false;

      delete card.originalLane;

    }

    cards[newId] = card;

    // Reorder target lane with insertion point
    var tLaneCards = Object.values(cards)
      .filter(function(c) { return !c.archived && c.lane === targetLane && c.status !== 'erledigt'; })
      .sort(function(a,b) { return (a.order||0) - (b.order||0) || a.id.localeCompare(b.id); });
    // Remove the moved card from its position (it's currently at the end with old order)
    tLaneCards = tLaneCards.filter(function(c) { return c.id !== newId; });
    var insIdx = tLaneCards.length;
    if (insertBeforeId) {
      var fi = tLaneCards.findIndex(function(c) { return c.id === insertBeforeId; });
      if (fi !== -1) insIdx = fi;
    }
    tLaneCards.splice(insIdx, 0, cards[newId]);
    tLaneCards.forEach(function(c, i) { cards[c.id].order = (i + 1) * 1000; });



    saveCards(cards);

    showToast(oldId + ' → ' + newId + ' (' + targetLane + ')');

    renderKanban();

    if (currentTab === 'heute') renderHeute();

  });

})();





// ─── BURGER MENU TOGGLE ─────────────────────────────────────────────────────

(function() {

  var burger = document.getElementById('burger-btn');

  var navTabs = document.getElementById('nav-tabs');

  if (burger && navTabs) {

    burger.addEventListener('click', function(e) {

      e.stopPropagation();

      navTabs.classList.toggle('open');

    });

    // Close when clicking a tab

    navTabs.querySelectorAll('.tab-btn').forEach(function(btn) {

      btn.addEventListener('click', function() {

        navTabs.classList.remove('open');

      });

    });

    // Close when clicking outside

    document.addEventListener('click', function(e) {

      if (!burger.contains(e.target) && !navTabs.contains(e.target)) {

        navTabs.classList.remove('open');

      }

    });

  }

})();





// ─── DELEGATED CLICK: Status cards open card modal ──────────────────────────

document.addEventListener('click', function(e) {

  var card = e.target.closest('.status-card');

  if (!card) return;

  if (e.target.closest('.today-btn')) return;

  var prefix = card.querySelector('.card-prefix');

  if (prefix) {

    var cardId = prefix.textContent.trim();

    if (cardId && typeof openCardModal === 'function') {

      openCardModal(cardId);

    }

  }

});







// PATIENT BLOG

var _currentPatId=null;var _blogExpanded={};var _entryExpanded={};

function openPatDetail(patId){_currentPatId=patId;var patients=getPatients();var pat=patients.find(function(p){return p.id===patId;});if(!pat)return;document.getElementById('pat-list').style.display='none';document.querySelector('.pat-header').style.display='none';var d=document.getElementById('pat-detail-view');d.classList.add('active');document.getElementById('pat-detail-title').textContent=pat.code;var s=document.getElementById('pat-detail-status');s.textContent=pat.status||'aktiv';s.className='pat-status-badge pat-status-'+(pat.status||'aktiv');renderPatAmpel(pat);renderPatBlog(pat);}

function closePatDetail(){_currentPatId=null;document.getElementById('pat-detail-view').classList.remove('active');document.getElementById('pat-list').style.display='';document.querySelector('.pat-header').style.display='';}

function renderPatAmpel(pat){var a=pat.ampel||{};var fields=['austritt','ambulant','tagesstruktur','wiedereingliederung'];var labels={austritt:'Austrittsplanung',ambulant:'Ambulante Weiterbehandlung',tagesstruktur:'Tagesstruktur',wiedereingliederung:'Wiedereingliederung'};var c=document.getElementById('pat-detail-ampel');c.innerHTML=fields.map(function(f){var st=(a[f]&&a[f].status)||'offen';var tx=(a[f]&&a[f].text)||'';return '<div class="pat-ampel-chip" data-status="'+st+'" onclick="cycleAmpel(\''+f+'\')" title="'+esc(labels[f]+(tx?' \u2014 '+tx:''))+'"><span class="pat-ampel-dot" data-status="'+st+'"></span>'+esc(labels[f])+'</div>';}).join('');}

function cycleAmpel(field){var patients=getPatients();var pat=patients.find(function(p){return p.id===_currentPatId;});if(!pat)return;if(!pat.ampel)pat.ampel={};if(!pat.ampel[field])pat.ampel[field]={status:'offen',text:''};var order=['offen','gruen','gelb','rot'];var idx=order.indexOf(pat.ampel[field].status);pat.ampel[field].status=order[(idx+1)%4];savePatients(patients);renderPatAmpel(pat);}

function renderPatBlog(pat){var entries=(pat.entries||[]).concat(pat.blog||[]);var seen={};entries=entries.filter(function(e){if(!e.id)return true;if(seen[e.id])return false;seen[e.id]=true;return true;});entries.sort(function(a,b){var da=new Date(a.date||a.ts||0);var db=new Date(b.date||b.ts||0);return db-da;});var c=document.getElementById('pat-blog-list');if(entries.length===0){c.innerHTML='<div class="empty-state">Noch keine Verlaufseintr\u00e4ge.</div>';return;}c.innerHTML=entries.map(function(e){var text=e.content||e.text||'';var lines=text.split('\n');var isLong=lines.length>5||text.length>400;var exp=_blogExpanded[e.id];var cls=isLong&&!exp?'pat-blog-entry-text collapsed':'pat-blog-entry-text';var btn=isLong?'<button class="pat-blog-expand" onclick="toggleBlogExpand(\''+e.id+'\')">'+(exp?'Weniger':'Mehr anzeigen...')+'</button>':'';var dateStr=e.date||e.ts?new Date(e.date||e.ts).toLocaleString('de-CH'):'';var titleStr=e.title?'<span class="pat-blog-entry-title">'+esc(e.title)+'</span>':'';var typeStr=e.type?'<span class="pat-blog-entry-type">'+esc(e.type)+'</span>':'';var syncBadge=e.status_sync==='synced'?'<span class="pat-sync-badge">\u2714 synced</span>':'';var copyBtn='<button class="pat-blog-entry-copy" onclick="copyBlogEntry(this,\''+e.id+'\')" title="Inhalt kopieren">\u2398 Copy</button>';return '<div class="pat-blog-entry"><div class="pat-blog-entry-header"><span class="pat-blog-entry-date">'+dateStr+'</span>'+typeStr+syncBadge+'<div class="pat-blog-entry-actions">'+copyBtn+'<button class="pat-blog-entry-delete" onclick="deleteEntry(\''+e.id+'\')">L\u00f6schen</button></div></div>'+titleStr+'<div class="'+cls+'" data-entry-id="'+e.id+'">'+esc(text)+'</div>'+btn+'</div>';}).join('');}

function addBlogEntry(){var t=document.getElementById('pat-blog-text').value.trim();if(!t)return;var patients=getPatients();var pat=patients.find(function(p){return p.id===_currentPatId;});if(!pat)return;if(!pat.entries)pat.entries=[];pat.entries.unshift({id:'entry'+Date.now(),date:new Date().toISOString(),content:t,type:'notiz',source:'manual'});savePatients(patients);document.getElementById('pat-blog-text').value='';renderPatBlog(pat);}

function deleteEntry(entryId){confirmAction('Eintrag l\u00f6schen?','Dieser Verlaufseintrag wird gel\u00f6scht.',function(){var patients=getPatients();var pat=patients.find(function(p){return p.id===_currentPatId;});if(!pat)return;if(pat.entries)pat.entries=pat.entries.filter(function(e){return e.id!==entryId;});if(pat.blog)pat.blog=pat.blog.filter(function(e){return e.id!==entryId;});savePatients(patients);renderPatBlog(pat);});}

function toggleBlogExpand(blogId){_blogExpanded[blogId]=!_blogExpanded[blogId];var patients=getPatients();var pat=patients.find(function(p){return p.id===_currentPatId;});if(pat)renderPatBlog(pat);}
function toggleEntryExpand(entryId){_entryExpanded[entryId]=!_entryExpanded[entryId];showPatientDetail(_patCurrentId);}

function copyBlogEntry(btn,entryId){var el=document.querySelector('[data-entry-id="'+entryId+'"]');if(!el)return;var text=el.textContent||el.innerText;navigator.clipboard.writeText(text).then(function(){btn.textContent='\u2714 Kopiert';btn.classList.add('copied');setTimeout(function(){btn.textContent='\u2398 Copy';btn.classList.remove('copied');},1500);}).catch(function(){var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);btn.textContent='\u2714 Kopiert';btn.classList.add('copied');setTimeout(function(){btn.textContent='\u2398 Copy';btn.classList.remove('copied');},1500);});}



// Import function for audiorec pipeline transcripts

function importAnonEntry(patientId, entry) {

  var patients = getPatients();

  var pat = patients.find(function(p) { return p.id === patientId || p.code === patientId; });

  if (!pat) return 'Patient ' + patientId + ' nicht gefunden';

  if (!pat.entries) pat.entries = [];

  // Prevent duplicate import

  var exists = pat.entries.find(function(e) { return e.id === entry.id; });

  if (exists) return 'Entry ' + entry.id + ' existiert bereits';

  pat.entries.unshift(entry);

  savePatients(patients);

  return 'OK: Entry importiert fuer ' + patientId;

}



// Sync PA-lane cards to patient entries (cards starting with patient code)

function syncPACardsToPatients() {

  var cards = getCards();

  var patients = getPatients();

  if (!patients || patients.length === 0) return;

  var patCodes = {};

  patients.forEach(function(p) { patCodes[p.id] = p; if(p.code) patCodes[p.code] = p; });

  var changed = false;

  Object.values(cards).forEach(function(c) {

    if (c.archived) return;

    var title = (c.title || '').trim();

    if (!title) return;

    // Check if title starts with a patient code

    var firstWord = title.split(/\s+/)[0];

    var pat = patCodes[firstWord];

    if (!pat) return;

    if (!pat.entries) pat.entries = [];

    var syncId = 'kanban_' + c.id;

    var existing = pat.entries.find(function(e) { return e.id === syncId; });

    var entryContent = title.replace(firstWord, '').trim();

    if (!entryContent) entryContent = title;

    if (existing) {

      // Update if content changed

      if (existing.content !== entryContent || existing.title !== c.id) {

        existing.content = entryContent;

        existing.title = c.id;

        existing.status_sync = 'synced';

        changed = true;

      }

    } else {

      // Create new synced entry

      pat.entries.unshift({

        id: syncId,

        date: c.createdAt || new Date().toISOString(),

        title: c.id,

        content: entryContent,

        type: 'kanban',

        source: 'kanban',

        status_sync: 'synced'

      });

      changed = true;

    }

  });

  if (changed) savePatients(patients);

}







// BB-112: MULTI-DEVICE SYNC (Smart Polling)

// Ctrl+Enter save shortcut for all input areas

document.addEventListener('keydown', function(e) {

  if (e.ctrlKey && e.key === 'Enter') {

    e.preventDefault();

    // Card modal

    var cardModal = document.getElementById('card-modal-overlay');

    if (cardModal && cardModal.classList.contains('open')) {

      document.getElementById('cm-save').click(); return;

    }

    // Patient entry modal

    var peModal = document.getElementById('pat-entry-modal-overlay');

    if (peModal && peModal.classList.contains('open')) {

      document.getElementById('pe-save').click(); return;

    }

    // Patient blog text

    var blogText = document.getElementById('pat-blog-text');

    if (blogText && document.activeElement === blogText) {

      addBlogEntry(); return;

    }

    // Settings modal

    var settingsModal = document.getElementById('settings-modal-overlay');

    if (settingsModal && settingsModal.classList.contains('open')) {

      var saveBtn = settingsModal.querySelector('.btn-primary');

      if (saveBtn) { saveBtn.click(); return; }

    }

  }

});



var _lastKnownSHA = null;

var _syncInterval = null;



async function checkForRemoteChanges() {

  var token = getGHToken();

  if (!token) return;

  try {

    var result = await fetchFromGitHub('data/tasks.json', { conditional: true });

    if (!result) return;

    if (result.notModified) return;

    var remoteSHA = result.sha;



    if (_lastKnownSHA && remoteSHA !== _lastKnownSHA) {

      console.log('[sync] Remote change detected:', _lastKnownSHA, '->', remoteSHA);

      showToast('Neue Daten erkannt \u2014 lade...', false);

      _dataLoaded = false;

      await loadFromGitHub();



      // Also force-reload patients (workaround for proxy issue)

      try {

        var pr = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/patients.json', {

          headers: { Authorization: 'token ' + token }, cache: 'no-store'

        });

        if (pr.ok) {

          var pd = await pr.json();

          var rawText = decodeBase64Utf8(pd.content);

          var decText = await decryptJSON(rawText);

          var raw = JSON.parse(decText);

          _appState.patients = Array.isArray(raw) ? raw : (raw.patients || []);

        }

      } catch(e) {}



      // Re-render current tab

      if (currentTab === 'heute') renderHeute();

      if (currentTab === 'kanban') renderKanban();

      if (currentTab === 'kba') renderPatients();

      if (currentTab === 'autonomy') renderAL();



      showToast('\u2705 Daten synchronisiert', false);

    }

    _lastKnownSHA = remoteSHA;

  } catch(e) {

    console.warn('[sync] check failed:', e);

  }

}



function startSyncPolling() {

  if (_syncInterval) clearInterval(_syncInterval);

  // Initial SHA capture

  checkForRemoteChanges();

  // Poll every 60 seconds

  _syncInterval = setInterval(checkForRemoteChanges, 60000);

  console.log('[sync] Polling started (60s interval)');

}



// Also sync on tab focus (user switches back to this tab)

document.addEventListener('visibilitychange', function() {

  if (!document.hidden) {

    checkForRemoteChanges();

  }

});



// Start polling after boot

setTimeout(startSyncPolling, 5000);


// ─── RAG TAB (Upload + Knowledge Base + Index + GDrive) ─────────────────────

var _ragUploadQueue = [];
var _ragUploading = false;
var _ragIndex = null;
var _ragIndexSearchTimer = null;
var RAG_SPLIT_MAX = 700 * 1024; // 700KB max per chunk (GitHub API limit ~1MB base64)
var RAG_TEXT_EXTS = ['.txt', '.md', '.json', '.csv', '.log'];

function showRAGTab() {
  renderCollect();
  loadRAGStats();
  loadRAGInbox();
  loadRAGIndex();
  loadGDrivePending();
  if (!showRAGTab._initialized) {
    showRAGTab._initialized = true;
    var dropZone = document.getElementById('rag-drop-zone');
    var fileInput = document.getElementById('rag-file-input');
    if (dropZone && fileInput) {
      dropZone.addEventListener('click', function() { fileInput.click(); });
      dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('drag-over'); });
      dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('drag-over'); });
      dropZone.addEventListener('drop', function(e) {
        e.preventDefault(); dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) handleRAGUpload(e.dataTransfer.files);
      });
      fileInput.addEventListener('change', function() {
        if (fileInput.files.length > 0) handleRAGUpload(fileInput.files);
        fileInput.value = '';
      });
    }
    var gdriveBtn = document.getElementById('btn-gdrive-import');
    if (gdriveBtn) gdriveBtn.addEventListener('click', submitGDriveImport);
    var idxSearch = document.getElementById('rag-index-search');
    var idxFilter = document.getElementById('rag-index-filter');
    if (idxSearch) idxSearch.addEventListener('input', function() {
      clearTimeout(_ragIndexSearchTimer);
      _ragIndexSearchTimer = setTimeout(function() { renderRAGIndex(); }, 300);
    });
    if (idxFilter) idxFilter.addEventListener('change', function() { renderRAGIndex(); });
  }
}

// ── File Splitting for Large Files ──

function isTextFile(name) {
  var lower = name.toLowerCase();
  for (var i = 0; i < RAG_TEXT_EXTS.length; i++) {
    if (lower.endsWith(RAG_TEXT_EXTS[i])) return true;
  }
  return false;
}

function splitTextFileSync(text, maxBytes, baseName) {
  var lines = text.split('\n');
  var parts = [];
  var current = '';
  var currentSize = 0;
  var partNum = 1;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i] + (i < lines.length - 1 ? '\n' : '');
    var lineSize = new Blob([line]).size;
    if (currentSize + lineSize > maxBytes && current.length > 0) {
      var padded = partNum < 10 ? '00' + partNum : partNum < 100 ? '0' + partNum : '' + partNum;
      parts.push({ name: baseName + '_part' + padded + '.txt', text: current, partNum: partNum });
      partNum++;
      current = line;
      currentSize = lineSize;
    } else {
      current += line;
      currentSize += lineSize;
    }
  }
  if (current.length > 0) {
    var padded = partNum < 10 ? '00' + partNum : partNum < 100 ? '0' + partNum : '' + partNum;
    parts.push({ name: baseName + '_part' + padded + '.txt', text: current, partNum: partNum });
  }
  return parts;
}

// ── Upload Handling ──

function handleRAGUpload(files) {
  var queueEl = document.getElementById('rag-upload-queue');
  if (!queueEl) return;
  queueEl.style.display = 'flex';

  var contextInput = document.getElementById('rag-context-input');
  var context = contextInput ? contextInput.value.trim() : '';

  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    if (f.size > RAG_SPLIT_MAX && !isTextFile(f.name)) {
      showToast(f.name + ': Zu gross (' + (f.size / 1024 / 1024).toFixed(1) + ' MB). Nur Text-Dateien werden automatisch aufgeteilt.', true);
      continue;
    }
    var item = { file: f, name: f.name, size: f.size, status: 'pending', context: context, needsSplit: f.size > RAG_SPLIT_MAX && isTextFile(f.name) };
    _ragUploadQueue.push(item);
    var sizeStr = f.size < 1024 ? f.size + ' B' : f.size < 1048576 ? (f.size / 1024).toFixed(1) + ' KB' : (f.size / 1048576).toFixed(1) + ' MB';
    var splitHint = item.needsSplit ? ' (wird aufgeteilt)' : '';
    var div = document.createElement('div');
    div.className = 'rag-queue-item';
    div.id = 'rag-q-' + _ragUploadQueue.length;
    div.innerHTML = '<span class="rag-queue-name">' + esc(f.name) + splitHint + '</span>' +
      '<span class="rag-queue-size">' + sizeStr + '</span>' +
      '<span class="rag-queue-status pending">Wartend</span>';
    queueEl.appendChild(div);
  }

  if (!_ragUploading) processRAGQueue();
}

function updateRAGProgress(filename, current, total, status) {
  var container = document.getElementById('rag-upload-progress');
  var fnEl = document.getElementById('rag-progress-filename');
  var pctEl = document.getElementById('rag-progress-pct');
  var fillEl = document.getElementById('rag-progress-fill');
  var statusEl = document.getElementById('rag-progress-status');
  if (!container) return;
  container.style.display = 'block';
  if (fnEl) fnEl.textContent = filename;
  var pct = total > 0 ? Math.round((current / total) * 100) : 0;
  if (pctEl) pctEl.textContent = pct + '%';
  if (fillEl) fillEl.style.width = pct + '%';
  if (statusEl) statusEl.textContent = status || ('Teil ' + current + ' / ' + total);
}

function hideRAGProgress() {
  var container = document.getElementById('rag-upload-progress');
  if (container) container.style.display = 'none';
}

async function uploadSingleToGitHub(token, path, b64, message) {
  var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/' + path, {
    method: 'PUT',
    headers: { Authorization: 'token ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: message, content: b64 })
  });
  if (r.status === 422) {
    var existing = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/' + path, {
      headers: { Authorization: 'token ' + token }
    });
    if (existing.ok) {
      var ed = await existing.json();
      r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/' + path, {
        method: 'PUT',
        headers: { Authorization: 'token ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message, content: b64, sha: ed.sha })
      });
    }
  }
  return r;
}

async function processRAGQueue() {
  _ragUploading = true;
  var token = getGHToken();
  if (!token) { showToast('Kein GitHub-Token gesetzt', true); _ragUploading = false; return; }

  var uploadedNames = [];

  for (var i = 0; i < _ragUploadQueue.length; i++) {
    var item = _ragUploadQueue[i];
    if (item.status !== 'pending') continue;

    item.status = 'uploading';
    var statusEl = document.querySelector('#rag-q-' + (i + 1) + ' .rag-queue-status');
    if (statusEl) { statusEl.textContent = 'Hochladen...'; statusEl.className = 'rag-queue-status uploading'; }

    try {
      if (item.needsSplit) {
        // Read as text and split
        var text = await new Promise(function(resolve, reject) {
          var reader = new FileReader();
          reader.onload = function(ev) { resolve(ev.target.result); };
          reader.onerror = reject;
          reader.readAsText(item.file);
        });
        var baseName = item.name.replace(/\.[^.]+$/, '');
        var parts = splitTextFileSync(text, RAG_SPLIT_MAX, baseName);
        var totalParts = parts.length;

        updateRAGProgress(item.name, 0, totalParts, 'Teile ' + totalParts + ' Teile auf...');

        // Upload each part
        var partNames = [];
        for (var p = 0; p < parts.length; p++) {
          updateRAGProgress(item.name, p + 1, totalParts + 1, 'Teil ' + (p + 1) + ' / ' + totalParts);
          var partB64 = encodeUtf8Base64(parts[p].text);
          var partPath = 'data/rag-inbox/' + parts[p].name;
          var pr = await uploadSingleToGitHub(token, partPath, partB64, 'rag-part: ' + parts[p].name);
          if (!pr.ok && pr.status !== 200 && pr.status !== 201) throw new Error('Part upload failed: HTTP ' + pr.status);
          partNames.push(parts[p].name);
          uploadedNames.push(parts[p].name);
        }

        // Upload manifest
        updateRAGProgress(item.name, totalParts, totalParts + 1, 'Manifest hochladen...');
        var manifest = JSON.stringify({
          original_name: item.name, total_parts: totalParts,
          parts: partNames, context: item.context || '',
          uploaded_at: new Date().toISOString()
        });
        var manifestB64 = encodeUtf8Base64(manifest);
        var manifestPath = 'data/rag-inbox/' + baseName + '.manifest.json';
        await uploadSingleToGitHub(token, manifestPath, manifestB64, 'rag-manifest: ' + baseName);
        uploadedNames.push(baseName + '.manifest.json');

        updateRAGProgress(item.name, totalParts + 1, totalParts + 1, 'Fertig');
        item.status = 'done';
        if (statusEl) { statusEl.textContent = totalParts + ' Teile hochgeladen'; statusEl.className = 'rag-queue-status done'; }

      } else {
        // Normal single-file upload
        var reader = new FileReader();
        var b64 = await new Promise(function(resolve, reject) {
          reader.onload = function(ev) { resolve(ev.target.result.split(',')[1]); };
          reader.onerror = reject;
          reader.readAsDataURL(item.file);
        });

        updateRAGProgress(item.name, 1, 1, 'Hochladen...');
        var path = 'data/rag-inbox/' + item.name;
        var r = await uploadSingleToGitHub(token, path, b64, 'rag-upload: ' + item.name);

        if (r.ok || r.status === 200 || r.status === 201) {
          item.status = 'done';
          if (statusEl) { statusEl.textContent = 'Hochgeladen'; statusEl.className = 'rag-queue-status done'; }
          uploadedNames.push(item.name);
          if (item.context) {
            var metaContent = encodeUtf8Base64('Kontext: ' + item.context + '\nDatei: ' + item.name + '\nUpload: ' + new Date().toISOString());
            await uploadSingleToGitHub(token, path + '.meta.txt', metaContent, 'rag-meta: ' + item.name).catch(function() {});
          }
        } else {
          throw new Error('HTTP ' + r.status);
        }
        updateRAGProgress(item.name, 1, 1, 'Fertig');
      }
    } catch(e) {
      item.status = 'error';
      if (statusEl) { statusEl.textContent = 'Fehler: ' + e.message; statusEl.className = 'rag-queue-status error'; }
    }
  }

  hideRAGProgress();
  _ragUploading = false;
  _ragUploadQueue = [];
  var ctxInput = document.getElementById('rag-context-input');
  if (ctxInput) ctxInput.value = '';

  if (uploadedNames.length > 0) {
    showToast(uploadedNames.length + ' Datei(en) hochgeladen');
    pollInboxUntilClear(uploadedNames);
  }
  loadRAGInbox();
}

// ── Inbox Polling (wait for server processing) ──

function pollInboxUntilClear(filenames) {
  var indicator = document.getElementById('rag-processing-indicator');
  if (indicator) indicator.style.display = 'block';
  var ticks = 0;
  var maxTicks = 40; // 40 x 15s = 10min
  var interval = setInterval(async function() {
    ticks++;
    if (ticks >= maxTicks) {
      clearInterval(interval);
      if (indicator) indicator.style.display = 'none';
      showToast('Server-Verarbeitung dauert laenger als erwartet', true);
      return;
    }
    try {
      var token = getGHToken();
      if (!token) return;
      var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/rag-inbox', {
        headers: { Authorization: 'token ' + token }
      });
      if (r.status === 404) {
        clearInterval(interval);
        if (indicator) indicator.style.display = 'none';
        showToast('Alle Dateien verarbeitet');
        loadRAGIndex();
        loadRAGStats();
        loadRAGInbox();
        return;
      }
      if (r.ok) {
        var files = await r.json();
        var remaining = files.filter(function(f) {
          return filenames.indexOf(f.name) >= 0;
        });
        if (remaining.length === 0) {
          clearInterval(interval);
          if (indicator) indicator.style.display = 'none';
          showToast('Alle Dateien verarbeitet');
          loadRAGIndex();
          loadRAGStats();
          loadRAGInbox();
        }
      }
    } catch(e) { /* ignore polling errors */ }
  }, 15000);
}

// ── RAG Stats ──

async function loadRAGStats() {
  var bar = document.getElementById('rag-stats-bar');
  if (!bar) return;
  var hb = null;
  try {
    var r = await fetchFromGitHub('data/fleet-heartbeat.json');
    if (r && r.content) hb = JSON.parse(r.content);
  } catch(e) {}

  if (hb && hb.rag) {
    bar.innerHTML = '<span class="rag-stat"><span class="on-dot ' + (hb.rag.status === 'healthy' ? 'on-dot--healthy' : 'on-dot--down') + '"></span> RAG ' + esc(hb.rag.status) + '</span>' +
      '<span class="rag-stat">Dokumente: <span class="rag-stat-value">' + (hb.rag.documents_indexed || 0) + '</span></span>' +
      '<span class="rag-stat">Update: <span class="rag-stat-value">' + (hb.updated_at ? fmtTimestampDE(hb.updated_at) : '-') + '</span></span>';
  } else {
    bar.innerHTML = '<span class="rag-stat"><span class="on-dot on-dot--unknown"></span> RAG Status unbekannt</span>';
  }
}

// ── RAG Inbox ──

async function loadRAGInbox() {
  var list = document.getElementById('rag-inbox-list');
  if (!list) return;
  var token = getGHToken();
  if (!token) { list.innerHTML = '<div class="on-no-data">Kein Token</div>'; return; }

  try {
    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/rag-inbox', {
      headers: { Authorization: 'token ' + token }
    });
    if (r.status === 404) { list.innerHTML = '<div class="on-no-data">Inbox leer</div>'; return; }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var files = await r.json();
    if (!Array.isArray(files) || files.length === 0) { list.innerHTML = '<div class="on-no-data">Inbox leer</div>'; return; }
    var html = '';
    files.forEach(function(f) {
      if (f.name.endsWith('.meta.txt') || f.name.endsWith('.sha')) return;
      var sizeStr = f.size < 1024 ? f.size + ' B' : f.size < 1048576 ? (f.size / 1024).toFixed(1) + ' KB' : (f.size / 1048576).toFixed(1) + ' MB';
      html += '<div class="rag-inbox-item"><span class="rag-inbox-name">' + esc(f.name) + '</span><span class="rag-inbox-date">' + sizeStr + '</span></div>';
    });
    list.innerHTML = html || '<div class="on-no-data">Inbox leer</div>';
  } catch(e) {
    list.innerHTML = '<div class="on-no-data">Fehler: ' + esc(e.message) + '</div>';
  }
}

// ── RAG Index / Catalog ──

async function loadRAGIndex() {
  try {
    var r = await fetchFromGitHub('data/rag-index.json');
    if (r && r.content) {
      _ragIndex = JSON.parse(r.content);
      renderRAGIndex();
    }
  } catch(e) { /* index not yet published */ }
}

function renderRAGIndex() {
  var listEl = document.getElementById('rag-index-list');
  var countEl = document.getElementById('rag-index-count');
  if (!listEl) return;
  if (!_ragIndex || !_ragIndex.files) { listEl.innerHTML = '<div class="on-no-data">Index leer</div>'; return; }

  var searchEl = document.getElementById('rag-index-search');
  var filterEl = document.getElementById('rag-index-filter');
  var search = searchEl ? searchEl.value.trim().toLowerCase() : '';
  var filter = filterEl ? filterEl.value : '';

  var entries = [];
  var files = _ragIndex.files;
  for (var fname in files) {
    if (!files.hasOwnProperty(fname)) continue;
    var meta = files[fname];
    if (filter && meta.source !== filter) continue;
    if (search && fname.toLowerCase().indexOf(search) < 0 && (meta.context || '').toLowerCase().indexOf(search) < 0 && (meta.domain || '').toLowerCase().indexOf(search) < 0) continue;
    entries.push({ name: fname, meta: meta });
  }

  entries.sort(function(a, b) {
    return (b.meta.ingested_at || '').localeCompare(a.meta.ingested_at || '');
  });

  var totalChunks = 0;
  for (var k in files) { if (files.hasOwnProperty(k)) totalChunks += (files[k].chunk_count || 0); }
  if (countEl) countEl.textContent = entries.length + ' / ' + Object.keys(files).length + ' Dateien, ' + (_ragIndex.total_chunks || totalChunks) + ' Chunks';

  if (entries.length === 0) { listEl.innerHTML = '<div class="on-no-data">Keine Treffer</div>'; return; }

  var html = '';
  var shown = Math.min(entries.length, 100);
  for (var i = 0; i < shown; i++) {
    var e = entries[i];
    var m = e.meta;
    var date = m.ingested_at ? new Date(m.ingested_at).toLocaleDateString('de-CH', { day: '2-digit', month: '2-digit', year: '2-digit' }) : '-';
    var sizeStr = m.size_bytes ? (m.size_bytes < 1024 ? m.size_bytes + ' B' : (m.size_bytes / 1024).toFixed(0) + ' KB') : '';
    var srcClass = 'rag-index-badge rag-badge--' + (m.source || 'upload');
    var domClass = 'rag-index-badge rag-badge--' + (m.domain || 'general');
    html += '<div class="rag-index-item">';
    html += '<div class="rag-index-item-header"><span class="rag-index-item-name">' + esc(e.name) + '</span><span class="rag-index-item-date">' + date + '</span></div>';
    html += '<div class="rag-index-item-meta"><span class="' + srcClass + '">' + esc(m.source || 'upload') + '</span>';
    html += '<span class="' + domClass + '">' + esc(m.domain || 'general') + '</span>';
    if (m.chunk_count) html += '<span class="rag-index-item-chunks">' + m.chunk_count + ' Chunks</span>';
    if (sizeStr) html += '<span class="rag-index-item-chunks">' + sizeStr + '</span>';
    if (m.context) html += '<span class="rag-index-item-context">' + esc(m.context) + '</span>';
    html += '</div></div>';
  }
  if (entries.length > shown) html += '<div class="on-no-data">... und ' + (entries.length - shown) + ' weitere</div>';
  listEl.innerHTML = html;
}

// ── Google Drive Import ──

function extractGDriveFileId(input) {
  if (!input) return null;
  var m = input.match(/\/d\/([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  m = input.match(/[?&]id=([a-zA-Z0-9_-]+)/);
  if (m) return m[1];
  if (/^[a-zA-Z0-9_-]{20,}$/.test(input.trim())) return input.trim();
  return null;
}

async function submitGDriveImport() {
  var inputEl = document.getElementById('gdrive-input');
  var ctxEl = document.getElementById('gdrive-context-input');
  var statusEl = document.getElementById('gdrive-status');
  if (!inputEl) return;

  var fileId = extractGDriveFileId(inputEl.value);
  if (!fileId) { if (statusEl) statusEl.textContent = 'Ungueltige Google Drive URL oder ID'; return; }

  var context = ctxEl ? ctxEl.value.trim() : '';
  var token = getGHToken();
  if (!token) { showToast('Kein GitHub-Token', true); return; }

  var request = JSON.stringify({
    file_id: fileId, context: context,
    requested_at: new Date().toISOString(), status: 'pending'
  });
  var b64 = encodeUtf8Base64(request);
  var path = 'data/rag-gdrive-requests/' + fileId.substring(0, 16) + '.json';

  try {
    await uploadSingleToGitHub(token, path, b64, 'gdrive-request: ' + fileId.substring(0, 16));
    if (statusEl) statusEl.textContent = 'Anfrage gesendet — Server verarbeitet in Kuerze...';
    if (inputEl) inputEl.value = '';
    if (ctxEl) ctxEl.value = '';
    loadGDrivePending();
  } catch(e) {
    if (statusEl) statusEl.textContent = 'Fehler: ' + e.message;
  }
}

async function loadGDrivePending() {
  var list = document.getElementById('gdrive-pending-list');
  if (!list) return;
  var token = getGHToken();
  if (!token) return;
  try {
    var r = await fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/rag-gdrive-requests', {
      headers: { Authorization: 'token ' + token }
    });
    if (r.status === 404 || !r.ok) { list.innerHTML = ''; return; }
    var files = await r.json();
    if (!Array.isArray(files) || files.length === 0) { list.innerHTML = ''; return; }
    var html = '';
    files.forEach(function(f) {
      html += '<div class="rag-inbox-item"><span class="rag-inbox-name">' + esc(f.name) + '</span><span class="rag-inbox-date">Wartend</span></div>';
    });
    list.innerHTML = html;
  } catch(e) { list.innerHTML = ''; }
}


// ─── WIKI BROWSER + QUERY UI (Compiler-Augmented RAG) ─────────────────────────

var _wikiIndex = null;
var _wikiSearchTimer = null;
var _wikiQueryPending = false;

// Tailscale Funnel URL for direct RAG API access
var RAG_API_BASE = 'https://hermine-lightsail.tail40eaf3.ts.net';

function initWikiUI() {
  if (initWikiUI._done) return;
  initWikiUI._done = true;

  var queryBtn = document.getElementById('btn-wiki-query');
  var queryInput = document.getElementById('wiki-query-input');
  if (queryBtn) queryBtn.addEventListener('click', submitWikiQuery);
  if (queryInput) queryInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') submitWikiQuery();
  });

  var compileBtn = document.getElementById('btn-wiki-compile');
  if (compileBtn) compileBtn.addEventListener('click', triggerWikiCompile);

  var wikiSearch = document.getElementById('wiki-search-input');
  var wikiFilter = document.getElementById('wiki-category-filter');
  if (wikiSearch) wikiSearch.addEventListener('input', function() {
    clearTimeout(_wikiSearchTimer);
    _wikiSearchTimer = setTimeout(renderWikiArticles, 300);
  });
  if (wikiFilter) wikiFilter.addEventListener('change', renderWikiArticles);
}

function loadWikiStatus() {
  var statsBar = document.getElementById('wiki-stats-bar');
  var compileStatus = document.getElementById('wiki-compile-status');
  var token = getGHToken();
  if (!token) return;
  fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/wiki-status.json', {
    headers: { Authorization: 'token ' + token }
  }).then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (!data || !data.content) return;
      var status = JSON.parse(decodeBase64Utf8(data.content));
      if (statsBar) {
        var wikiChunks = status.wiki_chunks_in_lancedb || 0;
        var pending = status.pending_files || 0;
        var lastCompile = status.last_compile_at ? fmtTimestampDE(status.last_compile_at) : 'Nie';
        var stats = status.stats || {};
        statsBar.innerHTML =
          '<div class="rag-stat"><strong>' + (stats.total_summaries || 0) + '</strong> Summaries</div>' +
          '<div class="rag-stat"><strong>' + (stats.total_concepts || 0) + '</strong> Concepts</div>' +
          '<div class="rag-stat"><strong>' + wikiChunks + '</strong> Chunks</div>' +
          '<div class="rag-stat"><strong>' + pending + '</strong> Ausstehend</div>' +
          '<div class="rag-stat">Kompiliert: ' + lastCompile + '</div>';
      }
      if (compileStatus) {
        compileStatus.innerHTML =
          '<div><strong>Summaries:</strong> ' + (stats.total_summaries || 0) + '</div>' +
          '<div><strong>Concepts:</strong> ' + (stats.total_concepts || 0) + '</div>' +
          '<div><strong>Wiki-Chunks:</strong> ' + (status.wiki_chunks_in_lancedb || 0) + '</div>' +
          '<div><strong>Ausstehend:</strong> ' + (status.pending_files || 0) + '</div>' +
          '<div><strong>Letzte Kompilierung:</strong> ' + (status.last_compile_at ? fmtTimestampDE(status.last_compile_at) : 'Nie') + '</div>' +
          '<div><strong>Modell:</strong> ' + (status.compile_model || 'DeepSeek V3.2') + '</div>';
      }
    }).catch(function() {});
}

function loadWikiIndex() {
  var token = getGHToken();
  if (!token) return;
  fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/wiki-index.json', {
    headers: { Authorization: 'token ' + token }
  }).then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (!data || !data.content) {
        _wikiIndex = { articles: [] };
        renderWikiArticles();
        return;
      }
      _wikiIndex = JSON.parse(decodeBase64Utf8(data.content));
      renderWikiArticles();
    }).catch(function() {
      _wikiIndex = { articles: [] };
      renderWikiArticles();
    });
}

function renderWikiArticles() {
  var list = document.getElementById('wiki-article-list');
  var countEl = document.getElementById('wiki-article-count');
  if (!list) return;
  if (!_wikiIndex || !_wikiIndex.articles || _wikiIndex.articles.length === 0) {
    list.innerHTML = '<div class="on-no-data">Noch keine Wiki-Artikel kompiliert.</div>';
    if (countEl) countEl.textContent = '0 Artikel';
    return;
  }

  var searchVal = (document.getElementById('wiki-search-input') || {}).value || '';
  var filterVal = (document.getElementById('wiki-category-filter') || {}).value || '';
  var search = searchVal.toLowerCase();

  var filtered = _wikiIndex.articles.filter(function(a) {
    if (filterVal && a.category !== filterVal) return false;
    if (search && a.path.toLowerCase().indexOf(search) < 0) return false;
    return true;
  });

  filtered.sort(function(a, b) {
    return (b.compiled_at || '').localeCompare(a.compiled_at || '');
  });

  if (countEl) countEl.textContent = filtered.length + ' / ' + _wikiIndex.articles.length + ' Artikel';

  var html = '';
  var limit = Math.min(filtered.length, 100);
  for (var i = 0; i < limit; i++) {
    var a = filtered[i];
    var name = a.path.replace('summaries/', '').replace('concepts/', '').replace('queries/', '').replace('.md', '');
    var catClass = 'rag-badge--' + (a.category || 'summary');
    var domClass = 'rag-badge--' + (a.domain || 'general');
    var date = a.compiled_at ? a.compiled_at.substring(0, 10) : '';
    html += '<div class="rag-index-item">' +
      '<span class="rag-index-name">' + esc(name) + '</span>' +
      '<span class="rag-badge ' + catClass + '">' + esc(a.category || '?') + '</span>' +
      '<span class="rag-badge ' + domClass + '">' + esc(a.domain || '') + '</span>' +
      '<span class="rag-index-date">' + date + '</span>' +
      '</div>';
  }
  list.innerHTML = html || '<div class="on-no-data">Keine Treffer.</div>';
}

function triggerWikiCompile() {
  var btn = document.getElementById('btn-wiki-compile');
  if (btn) btn.disabled = true;
  var status = document.getElementById('wiki-compile-status');
  if (status) status.innerHTML += '<div style="margin-top:8px;color:var(--accent)">Kompilierung gestartet...</div>';

  // Push compile request via GitHub (PWA can't reach Lightsail directly without Funnel)
  var token = getGHToken();
  if (!token) return;
  var req = { trigger: 'compile', requested_at: new Date().toISOString(), max_files: 10 };
  var content = encodeUtf8Base64(JSON.stringify(req));
  fetch('https://api.github.com/repos/ctmos/cowork-data/contents/data/wiki-compile-request.json', {
    method: 'PUT',
    headers: { Authorization: 'token ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: 'wiki: compile request from PWA',
      content: content
    })
  }).then(function(r) {
    if (btn) btn.disabled = false;
    if (r.ok && status) {
      status.innerHTML += '<div style="color:var(--success)">Anfrage gesendet. Cron triggert Kompilierung.</div>';
    }
  }).catch(function() {
    if (btn) btn.disabled = false;
  });
}

function submitWikiQuery() {
  var input = document.getElementById('wiki-query-input');
  var resultDiv = document.getElementById('wiki-query-result');
  if (!input || !resultDiv || !input.value.trim()) return;
  if (_wikiQueryPending) return;

  var query = input.value.trim();
  _wikiQueryPending = true;
  resultDiv.style.display = 'block';
  resultDiv.innerHTML = '<div class="on-no-data">Suche laeuft...</div>';

  // Try Tailscale Funnel first, fallback to status message
  if (RAG_API_BASE) {
    fetch(RAG_API_BASE + '/query?q=' + encodeURIComponent(query) + '&top_k=5')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        _wikiQueryPending = false;
        renderWikiQueryResult(data, query);
      })
      .catch(function() {
        _wikiQueryPending = false;
        resultDiv.innerHTML = '<div class="on-no-data">RAG-Service nicht erreichbar. Frage Hermine per Telegram.</div>';
      });
  } else {
    _wikiQueryPending = false;
    resultDiv.innerHTML = '<div class="on-no-data">Direkter RAG-Zugang nicht konfiguriert. Frage Hermine per Telegram: "Was weiss das RAG ueber ' + esc(query) + '?"</div>';
  }
}

function renderWikiQueryResult(data, query) {
  var div = document.getElementById('wiki-query-result');
  if (!div) return;
  var sources = data.sources || [];
  var tier = data.source_tier || 'unknown';
  var tierLabel = tier === 'wiki' ? 'Wiki' : tier === 'raw' ? 'Raw' : 'Hybrid';
  var tierClass = tier === 'wiki' ? 'rag-badge--concept' : tier === 'raw' ? 'rag-badge--upload' : 'rag-badge--url';

  if (sources.length === 0) {
    div.innerHTML = '<div class="on-no-data">Keine Ergebnisse fuer "' + esc(query) + '"</div>';
    return;
  }

  var html = '<div class="wiki-query-header">' +
    '<strong>Ergebnisse</strong> <span class="rag-badge ' + tierClass + '">' + tierLabel + '</span>' +
    ' <span class="wiki-query-confidence">Konfidenz: ' + ((sources[0].relevance_score || 0) * 100).toFixed(0) + '%</span>' +
    '</div>';
  for (var i = 0; i < sources.length; i++) {
    var s = sources[i];
    var meta = s.metadata || {};
    var file = meta.source_file || meta.wiki_path || '?';
    html += '<div class="wiki-query-source">' +
      '<div class="wiki-query-source-header">' +
        '<span class="rag-badge ' + (s.source_tier === 'wiki' ? 'rag-badge--concept' : 'rag-badge--upload') + '">' + (s.source_tier || tier) + '</span> ' +
        '<strong>' + esc(file) + '</strong>' +
        '<span class="wiki-query-score">' + ((s.relevance_score || 0) * 100).toFixed(0) + '%</span>' +
      '</div>' +
      '<div class="wiki-query-text">' + esc(s.text || '') + '</div>' +
      '</div>';
  }
  div.innerHTML = html;
}

// Hook into showRAGTab
var _origShowRAGTab = showRAGTab;
showRAGTab = function() {
  _origShowRAGTab();
  initWikiUI();
  loadWikiStatus();
  loadWikiIndex();
};


// ─── ON TAB (Operations / Monitoring) ────────────────────────────────────────

var _onTabInterval = null;

function fmtDurationDE(startIso, endIso) {
  try {
    var start = new Date(startIso).getTime();
    var end = endIso ? new Date(endIso).getTime() : Date.now();
    var diff = Math.max(0, end - start);
    var mins = Math.floor(diff / 60000);
    if (mins < 60) return mins + ' Min.';
    var hrs = Math.floor(mins / 60);
    var rem = mins % 60;
    return hrs + ' Std. ' + (rem > 0 ? rem + ' Min.' : '');
  } catch(e) { return '?'; }
}

async function showONTab() {
  var container = document.getElementById('on-container');
  if (!container) return;
  container.innerHTML = '<div class="empty-state">Wird geladen\u2026</div>';

  var results = await Promise.all([
    fetchFromGitHub('data/fleet-heartbeat.json'),
    fetchFromGitHub('data/session-bus.json')
  ]);

  var hb = null;
  var sb = null;
  try { if (results[0] && results[0].content) hb = JSON.parse(results[0].content); } catch(e) {}
  try { if (results[1] && results[1].content) sb = JSON.parse(results[1].content); } catch(e) {}

  renderONTab(container, hb, sb);
  startONPolling();
}

function startONPolling() {
  if (_onTabInterval) clearInterval(_onTabInterval);
  _onTabInterval = setInterval(async function() {
    // ON ist jetzt ein Dropdown im System-Tab; Polling nur weiter wenn System aktiv
    if (currentTab !== 'system') {
      clearInterval(_onTabInterval);
      _onTabInterval = null;
      return;
    }
    var results = await Promise.all([
      fetchFromGitHub('data/fleet-heartbeat.json', { conditional: true }),
      fetchFromGitHub('data/session-bus.json', { conditional: true })
    ]);
    var changed = false;
    var hb = null;
    var sb = null;
    if (results[0] && !results[0].notModified) {
      try { hb = JSON.parse(results[0].content); changed = true; } catch(e) {}
    }
    if (results[1] && !results[1].notModified) {
      try { sb = JSON.parse(results[1].content); changed = true; } catch(e) {}
    }
    if (changed) {
      var container = document.getElementById('on-container');
      if (container) renderONTab(container, hb, sb);
    }
  }, 30000);
}

function renderONTab(container, hb, sb) {
  var html = '';
  html += renderONFleet(hb);
  html += renderONHermine(hb);
  html += renderONSessionBus(sb);
  html += renderONRag(hb);
  html += renderONScheduled(hb);
  container.innerHTML = html;
}

function renderONFleet(hb) {
  var html = '<details class="sys-dropdown"><summary class="sys-dropdown-header">Fleet</summary>';
  html += '<div class="sys-dropdown-body">';
  if (!hb || !hb.fleet) {
    html += '<div class="on-no-data">Kein Heartbeat \u2014 fleet-heartbeat.json nicht gefunden</div>';
  } else {
    html += '<div class="on-fleet-grid">';
    var devices = ['cloudypc', 'cloudynb', 'lightsail'];
    for (var i = 0; i < devices.length; i++) {
      var key = devices[i];
      var d = hb.fleet[key];
      if (!d) continue;
      var dotClass = d.status === 'online' ? 'on-dot--online' : d.status === 'offline' ? 'on-dot--offline' : 'on-dot--unknown';
      var lastSeen = d.last_seen ? fmtTimestampDE(d.last_seen) : 'Nie gesehen';
      html += '<div class="on-card">';
      html += '<div class="on-card-header"><span class="on-dot ' + dotClass + '"></span>';
      html += '<span class="on-card-title">' + esc(d.name || key) + '</span>';
      html += '<span class="on-card-ip">' + esc(d.ip || '') + '</span></div>';
      html += '<div class="on-card-meta">Zuletzt: ' + esc(lastSeen) + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }
  html += '</div></details>';
  return html;
}

function renderONHermine(hb) {
  var html = '<details class="sys-dropdown"><summary class="sys-dropdown-header">Hermine</summary>';
  html += '<div class="sys-dropdown-body">';
  if (!hb || !hb.hermine) {
    html += '<div class="on-no-data">Kein Heartbeat</div>';
  } else {
    var h = hb.hermine;
    var dotClass = h.last_heartbeat ? 'on-dot--online' : 'on-dot--unknown';
    html += '<div class="on-card">';
    html += '<div class="on-card-header"><span class="on-dot ' + dotClass + '"></span>';
    html += '<span class="on-card-title">Hermine</span></div>';
    html += '<div class="on-card-meta">Modell: ' + esc(h.model || 'Unbekannt') + '</div>';
    html += '<div class="on-card-meta">Heartbeat: ' + (h.last_heartbeat ? esc(fmtTimestampDE(h.last_heartbeat)) : 'Nie') + '</div>';
    if (h.last_action) html += '<div class="on-card-meta">Letzte Aktion: ' + esc(h.last_action) + '</div>';
    html += '</div>';
  }
  html += '</div></details>';
  return html;
}

function renderONSessionBus(sb) {
  var html = '<details class="sys-dropdown"><summary class="sys-dropdown-header">Session Bus</summary>';
  html += '<div class="sys-dropdown-body">';
  if (!sb) {
    html += '<div class="on-no-data">session-bus.json nicht gefunden</div>';
    html += '</div></details>';
    return html;
  }

  // Active sessions
  var active = sb.active_sessions || [];
  html += '<div class="on-section-title">Aktiv (' + active.length + ')</div>';
  if (active.length === 0) {
    html += '<div class="on-no-data">Keine aktiven Sessions</div>';
  } else {
    html += '<table class="on-sessions-table"><thead><tr>';
    html += '<th>ID</th><th>Device</th><th>Task</th><th>Dauer</th>';
    html += '</tr></thead><tbody>';
    for (var i = 0; i < active.length; i++) {
      var s = active[i];
      var task = (s.task || '').substring(0, 60);
      html += '<tr><td><strong>' + esc(s.id || '') + '</strong></td>';
      html += '<td>' + esc(s.device || '') + '</td>';
      html += '<td><span class="on-task-truncated">' + esc(task) + '</span></td>';
      html += '<td>' + fmtDurationDE(s.started_at) + '</td></tr>';
    }
    html += '</tbody></table>';
  }

  // Completed sessions (last 5)
  var completed = (sb.completed_sessions || []).slice(-5).reverse();
  html += '<div class="on-section-title">Abgeschlossen (letzte 5)</div>';
  if (completed.length === 0) {
    html += '<div class="on-no-data">Keine abgeschlossenen Sessions</div>';
  } else {
    html += '<table class="on-sessions-table"><thead><tr>';
    html += '<th>ID</th><th>Device</th><th>Ergebnis</th><th>Dauer</th>';
    html += '</tr></thead><tbody>';
    for (var j = 0; j < completed.length; j++) {
      var c = completed[j];
      var summary = (c.result_summary || 'Kein Summary').substring(0, 80);
      html += '<tr><td><strong>' + esc(c.id || '') + '</strong></td>';
      html += '<td>' + esc(c.device || '') + '</td>';
      html += '<td><span class="on-task-truncated">' + esc(summary) + '</span></td>';
      html += '<td>' + fmtDurationDE(c.started_at, c.finished_at) + '</td></tr>';
    }
    html += '</tbody></table>';
  }

  if (sb.shared_context) {
    html += '<div class="on-card-meta" style="margin-top:8px">Kontext: ' + esc(sb.shared_context) + '</div>';
  }

  html += '</div></details>';
  return html;
}

function renderONRag(hb) {
  var html = '<details class="sys-dropdown"><summary class="sys-dropdown-header">RAG</summary>';
  html += '<div class="sys-dropdown-body">';
  if (!hb || !hb.rag) {
    html += '<div class="on-no-data">Kein Heartbeat</div>';
  } else {
    var r = hb.rag;
    var dotClass = r.status === 'healthy' ? 'on-dot--healthy' : r.status === 'down' ? 'on-dot--down' : 'on-dot--unknown';
    html += '<div class="on-card">';
    html += '<div class="on-card-header"><span class="on-dot ' + dotClass + '"></span>';
    html += '<span class="on-card-title">RAG Service</span></div>';
    html += '<div class="on-card-meta">Dokumente indexiert: ' + (r.documents_indexed || 0) + '</div>';
    html += '<div class="on-card-meta">Letzte Abfrage: ' + (r.last_query ? esc(fmtTimestampDE(r.last_query)) : 'Nie') + '</div>';
    html += '</div>';
  }
  html += '</div></details>';
  return html;
}

function renderONScheduled(hb) {
  var html = '<details class="sys-dropdown"><summary class="sys-dropdown-header">Geplante Tasks</summary>';
  html += '<div class="sys-dropdown-body">';
  if (!hb || !hb.scheduled_tasks || hb.scheduled_tasks.length === 0) {
    html += '<div class="on-no-data">Keine geplanten Tasks konfiguriert</div>';
  } else {
    for (var i = 0; i < hb.scheduled_tasks.length; i++) {
      var t = hb.scheduled_tasks[i];
      var dotClass = t.status === 'ok' ? 'on-dot--ok' : t.status === 'error' ? 'on-dot--error' : t.status === 'running' ? 'on-dot--running' : 'on-dot--unknown';
      html += '<div class="on-sched-row">';
      html += '<span class="on-dot ' + dotClass + '"></span>';
      html += '<span class="on-sched-name">' + esc(t.name || t.id) + '</span>';
      html += '<span class="on-sched-time">Letzter: ' + (t.last_run ? esc(fmtTimestampDE(t.last_run)) : '-') + '</span>';
      html += '</div>';
    }
  }
  html += '</div></details>';
  return html;
}


// ─── $$$ FINANZEN TAB ──────────────────────────────────────────────────────────

function renderMoneyTab() {
  var c = document.getElementById('money-container');
  if (!c) return;

  var h = '';

  // --- KONTOST&Auml;NDE ---
  h += '<div class="money-section">';
  h += '<h3>Kontost\u00e4nde (Stand 02.04.2026)</h3>';
  h += '<div class="money-grid">';
  h += moneyCard('Hauptkonto', '6.944 EUR', 'Sparkasse Hochrhein');
  h += moneyCard('Tagesgeld', '8.600 EUR', 'davon ~5.600 gebunden (PSP + Elisa)');
  h += moneyCard('Schweizer CHF', '196 CHF', 'Lohnkonto Klinik Barmelweid');
  h += moneyCard('Frei verf\u00fcgbar', '~10.000 EUR', 'Puffer');
  h += '</div></div>';

  // --- EINKOMMEN HAUSHALT ---
  h += '<div class="money-section">';
  h += '<h3>Einkommen Haushalt</h3>';
  h += '<h4>Christian</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>Betrag</th><th>Info</th></tr>';
  h += mRow('Lohn Klinik (80%)', '5.709 CHF/Mon', 'Netto nach Quellensteuer, = ~5.300 EUR');
  h += mRow('Aufstockung 90% (Apr-Jul 26)', '+~600 CHF/Mon', 'Tempor\u00e4r, endet August');
  h += mRow('13. Monatslohn', '~5.700 CHF', 'Aufgeteilt Jul (~3.200) + Dez (~5.800)');
  h += mRow('HanseMerkur Erstattungen', '~390 EUR/Mon', 'Katheter + Elvanse (durchlaufend)');
  h += '</table>';
  h += '<h4>Hannah</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>Betrag</th><th>Info</th></tr>';
  h += mRow('Lohn Klinik (Grenzg\u00e4nger)', '2.400-2.800 CHF/Mon', 'Netto VOR KK + Steuer');
  h += mRow('13. Monatslohn', 'Dezember', 'Komplett im Dezember');
  h += mRow('Hebamme (selbstst\u00e4ndig)', '~400 EUR/Mon', 'Brutto, starke Schwankungen, keine USt');
  h += '</table>';
  h += '<p style="color:var(--text-muted);font-size:12px">Noch offen: Hannahs Pensum, KK-Beitrag, Auto-Kosten</p>';
  h += '</div>';

  // --- WAS CHRISTIANS 3.070 ABDECKEN ---
  h += '<div class="money-section">';
  h += '<h3>Christians 3.070 EUR an Hannah — Aufschl\u00fcsselung</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>EUR</th><th>Info</th></tr>';
  h += mRow('Steuer-Vorauszahlung (sparen)', '1.350', 'Hannah zahlt 4.134/Quartal davon');
  h += mRow('Miete (kalt)', '1.300', 'Kaltmiete 1.340, 40 EUR Differenz von Hannah');
  h += mRow('Strom', '221', 'Separater Anbieter');
  h += mRow('Kindergarten Sophie', '111', '');
  h += mRow('Gesamttopf (Rest)', '88', 'F\u00fcr was es braucht');
  h += '<tr class="money-subtotal"><td>Summe</td><td>3.070</td><td></td></tr>';
  h += '</table></div>';

  // --- WOHNEN & KINDER (Hannah zahlt) ---
  h += '<div class="money-section">';
  h += '<h3>Wohnen &amp; Kinder (zahlt Hannah)</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>EUR/Mon</th><th>Info</th></tr>';
  h += mRow('Miete kalt (Differenz)', '40', 'Kaltmiete 1.340 - 1.300 von Christian');
  h += mRow('Gas/Heizung', '217', 'Separater Anbieter');
  h += mRow('M\u00fcll', '26', '310 EUR/Jahr');
  h += mRow('Reiten Annabell', '100', '');
  h += mRow('Klettern Sophie', '37', '');
  h += mRow('Verlaessl. Grundschule', '35', '');
  h += mRow('Turnen Annabell', '30', '');
  h += mRow('Sparen Kinder (2x25)', '50', 'Annabell + Sophie');
  h += mRow('Wocheneinkauf, Drogerie, Kleidung', '?', 'Von Hannahs eigenem Geld');
  h += mRow('Hannahs Krankenkasse', '?', 'Noch offen');
  h += mRow('Hannahs Auto', '?', 'Noch offen');
  h += '<tr class="money-subtotal"><td>Summe bekannt</td><td>535+</td><td>+ KK + Auto + Einkauf</td></tr>';
  h += '</table></div>';

  // --- CHRISTIANS FIXKOSTEN ---
  h += '<div class="money-section">';
  h += '<h3>Christians Fixkosten (monatlich)</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>EUR/Mon</th><th>Status</th></tr>';
  h += mRow('Hannah (inkl. Steuer+Miete+Strom)', '3.070', 'Fix, zweckgebunden');
  h += mRow('HanseMerkur PKV (3 Pers.)', '820', 'Christian + 2 Kinder');
  h += mRow('FINN Auto-Abo', '547', 'Via Klarna, endet Mai 2026');
  h += mRow('Telekom Mobilfunk (2 Handys)', '90', 'Inkl. Handy-Raten');
  h += mRow('Vodafone Kabel-Internet', '44', '');
  h += mRow('Sparkasse Kontogeb\u00fchren', '12', '');
  h += '<tr class="money-subtotal"><td>Summe Fixkosten</td><td>4.583</td><td></td></tr>';
  h += '</table>';
  h += '<p style="font-size:13px;color:var(--text-muted)">Einnahme ~5.300 - Fix 4.583 = <strong>~717 EUR frei</strong> f\u00fcr Abos, Essen, Tanken, Amazon, Kleidung</p>';
  h += '</div>';

  // --- ABOS & SUBSCRIPTIONS ---
  h += '<div class="money-section">';
  h += '<h3>Abos &amp; Subscriptions</h3>';

  // AI & Tech
  h += '<h4>KI &amp; Tech</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Service</th><th>EUR/Mon</th><th>Status</th></tr>';
  h += mRowStatus('Claude.ai Max 20', '180', 'keep', 'Runterstufen geplant');
  h += mRowStatus('AWS (Lightsail + Bedrock)', '50', 'keep', 'Server + API');
  h += mRowStatus('Google Cloud', '25', 'check', 'Brauchen wir das neben AWS?');
  h += mRowStatus('OpenAI / ChatGPT', '23', 'cut', 'Claude reicht');
  h += mRowStatus('Google One 2TB', '22', 'keep', 'Cloud-Speicher');
  h += mRowStatus('OpenRouter', '20', 'keep', 'Hermine LLM');
  h += mRowStatus('Replit Core', '20', 'cut', 'Noch aktiv?');
  h += mRowStatus('xAI / Grok', '19', 'cut', 'Hermine nutzt DeepSeek');
  h += mRowStatus('Wispr Flow Pro', '15', 'cut', 'Sprachsteuerung aktiv?');
  h += mRowStatus('Anthropic API', '10', 'keep', 'Hermine');
  h += mRowStatus('Notion', '5', 'keep', 'LifeOS');
  h += '<tr class="money-subtotal"><td>Summe KI &amp; Tech</td><td>389</td><td>K\u00fcndigbar: ~77/Mon</td></tr>';
  h += '</table>';

  // Hosting
  h += '<h4>Hosting</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Service</th><th>EUR/Mon</th><th>Status</th></tr>';
  h += mRowStatus('Variomedia (moser.ai)', '37', 'check', '222/Halbjahr — g\u00fcnstigerer Anbieter?');
  h += mRowStatus('Strato', '0?', 'check', 'Gek\u00fcndigt Nov 2024 — pr\u00fcfen');
  h += '</table>';

  // Entertainment
  h += '<h4>Entertainment</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Service</th><th>EUR/Mon</th><th>Status</th></tr>';
  h += mRowStatus('Spotify', '22', 'keep', 'Musik');
  h += mRowStatus('Amazon Prime', '9', 'keep', 'Versand + Video');
  h += mRowStatus('Audible', '0?', 'check', 'Vermutlich inaktiv seit Jan 2025');
  h += '</table>';

  // Telekom/Versicherung (already in Fixkosten)
  h += '</div>';

  // --- VARIABLE AUSGABEN ---
  h += '<div class="money-section">';
  h += '<h3>Variable Ausgaben (Durchschnitt/Monat)</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Kategorie</th><th>Aktuell</th><th>Budget-Ziel</th></tr>';
  h += mRowBudget('Amazon', '510', '150', 'Hartes Limit. 24h-Regel.');
  h += mRowBudget('Kleidung (Best Secret etc.)', '465', '100', 'App l\u00f6schen. 1x/Monat max.');
  h += mRowBudget('Swiss Bankers Prepaid (CH)', '280', '250', 'Mittagessen etc. in CH');
  h += mRowBudget('Lebensmittel', '175', '175', '');
  h += mRowBudget('Essen gehen', '165', '100', 'Chinatown, McDonalds etc.');
  h += mRowBudget('Bargeld', '107', '80', 'Geldautomat Kadelburg');
  h += mRowBudget('Tanken', '80', '80', 'Shell, Esso');
  h += mRowBudget('Gesundheit (nach Erstattung)', '75', '75', 'Zuzahlungen');
  h += '<tr class="money-subtotal"><td>Summe variabel</td><td>1.857</td><td>1.010</td></tr>';
  h += '</table></div>';

  // --- TEMPORAERE KOSTEN ---
  h += '<div class="money-section">';
  h += '<h3>Tempor\u00e4re Kosten (enden bald)</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>EUR/Mon</th><th>Endet</th></tr>';
  h += mRow('PSP Weiterbildung', '~560', '2026 (genaues Datum kl\u00e4ren)');
  h += mRow('FINN Auto-Abo (Elroq)', '608', 'Mai 2027');
  h += mRow('Claude Max 20 (wenn runtergestuft)', '~90-160', 'Wenn bereit');
  h += mRow('K\u00fcndigbare KI-Abos', '~77', 'Sofort m\u00f6glich');
  h += '<tr class="money-subtotal"><td>M\u00f6gliche Entlastung</td><td>~1.335-1.405</td><td></td></tr>';
  h += '</table></div>';

  // --- STEUERN ---
  h += '<div class="money-section">';
  h += '<h3>Steuern 2026</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Posten</th><th>Betrag</th><th>Info</th></tr>';
  h += mRow('Einkommensteuer Vorauszahlung', '4.035/Quartal', '10. M\u00e4rz / Juni / Sep / Dez');
  h += mRow('Kirchensteuer (Hannah)', '99/Quartal', 'Evangelisch');
  h += mRow('Solidarit\u00e4tszuschlag', '0', '');
  h += mRow('Gesamt pro Quartal', '4.134', '');
  h += mRow('Gesamt pro Jahr', '16.536', '');
  h += mRow('CH-Quellensteuer (Christian)', '~320/Mon', 'Wird direkt vom Lohn abgezogen');
  h += '</table>';
  h += '<p style="color:var(--text-muted);font-size:13px">Steuerberater: Vereinigte Lohnsteuerhilfe e.V. (Diana Gatti, Grafenhausen)</p>';
  h += '</div>';

  // --- LOHN-DETAILS ---
  h += '<div class="money-section">';
  h += '<h3>Lohnabrechnung Christian (Jan 2026)</h3>';
  h += '<table class="money-table">';
  h += '<tr><th>Position</th><th>CHF</th></tr>';
  h += mRow2('Monatslohn (80%)', '6.658,40');
  h += mRow2('Kinderzulage 2x', '+450,00');
  h += mRow2('BRUTTO', '7.108,40');
  h += mRow2('Abz\u00fcge (AHV, ALV, Unfall, KTG, PK)', '-999,25');
  h += mRow2('NETTO', '6.109,15');
  h += mRow2('Quellensteuer 4,5%', '-319,90');
  h += mRow2('Parkplatz', '-80,00');
  h += '<tr class="money-subtotal"><td>Auszahlung</td><td>5.709,25</td></tr>';
  h += '</table>';
  h += '<p style="color:var(--text-muted);font-size:13px">Ab April 2026: 90% Pensum (7.490,70 brutto) bis Juli, dann zur\u00fcck auf 80%</p>';
  h += '</div>';

  // --- STRATEGIE ---
  h += '<div class="money-section">';
  h += '<h3>Strategie: Stabilisierung in 3 Phasen</h3>';

  h += '<h4>Phase 1: Sofort (April 2026)</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Aktion</th><th>Ersparnis/Mon</th><th>Aufwand</th></tr>';
  h += mRow('KI-Abos k\u00fcndigen (OpenAI, xAI, Replit, Wispr)', '+77', '4x k\u00fcndigen');
  h += mRow('Claude Max 20 \u2192 Pro', '+160', '1 Klick');
  h += mRow('Best Secret App l\u00f6schen', '+300-500', 'App deinstallieren');
  h += mRow('Amazon Budget 150 EUR/Mon', '+350', '24h-Regel einf\u00fchren');
  h += '<tr class="money-subtotal"><td>Phase 1 Total</td><td>+887-1.087</td><td></td></tr>';
  h += '</table>';

  h += '<h4>Phase 2: Mai-Juli 2026</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Aktion</th><th>Ersparnis/Mon</th><th>Info</th></tr>';
  h += mRow('FINN endet Mai \u2192 Entscheidung treffen', '+547', 'Ohne Auto? G\u00fcnstigeres Auto?');
  h += mRow('90% Pensum (Apr-Jul)', '+500-600', 'Tempor\u00e4r mehr Lohn');
  h += mRow('PSP endet 2026', '+560', 'Genaues Datum kl\u00e4ren');
  h += '<tr class="money-subtotal"><td>Phase 2 Total</td><td>+1.607-1.707</td><td></td></tr>';
  h += '</table>';

  h += '<h4>Phase 3: Ab August 2026</h4>';
  h += '<table class="money-table">';
  h += '<tr><th>Ziel</th><th>Betrag</th><th>Info</th></tr>';
  h += mRow('Zur\u00fcck auf 80% Pensum', '-600', 'F\u00e4llt weg');
  h += mRow('Aber: PSP + FINN weg', '+1.107', 'Dauerhaft');
  h += mRow('Netto-Verbesserung', '+507', 'Gegenueber heute');
  h += mRow('Notgroschen-Ziel', '15.000 EUR', '3 Monatsausgaben als Puffer');
  h += mRow('Variomedia \u2192 g\u00fcnstigerer Anbieter', '+30', 'Domain-Transfer');
  h += mRow('Google Cloud konsolidieren', '+25', 'Wenn m\u00f6glich');
  h += '</table>';
  h += '</div>';

  // --- OFFENE PUNKTE ---
  h += '<div class="money-section">';
  h += '<h3>Offene Punkte</h3>';
  h += '<ul style="list-style:none;padding:0">';
  h += '<li>&#9745; Hannahs Einkommen \u2014 2.400-2.800 CHF + Hebamme ~400</li>';
  h += '<li>&#9745; Miete \u2014 1.340 kalt + 221 Strom + 217 Gas + 26 M\u00fcll = 1.804/Mon</li>';
  h += '<li>&#9745; Steuer-Aufteilung \u2014 1.350/Mon von Christians 3.070, Rest von Hannah</li>';
  h += '<li>&#9745; Kinder-Kosten \u2014 KiGa 111 + Reiten 100 + Klettern 37 + Turnen 30 + Grundschule 35 + Sparen 50</li>';
  h += '<li>&#9744; Hannahs Pensum (Klinik) \u2014 noch offen</li>';
  h += '<li>&#9744; Hannahs Krankenkasse \u2014 Betrag noch offen</li>';
  h += '<li>&#9744; Hannahs Auto-Kosten \u2014 noch offen</li>';
  h += '<li>&#9744; PSP Ende-Datum \u2014 2026, aber wann genau?</li>';
  h += '<li>&#9744; FINN-Entscheidung \u2014 Mai 2026</li>';
  h += '<li>&#9744; Abo-Durchgang mit Christian \u2014 22 Abos durchgehen</li>';
  h += '<li>&#9744; Best Secret App l\u00f6schen</li>';
  h += '<li>&#9744; Amazon Budget 150 EUR einrichten</li>';
  h += '<li>&#9744; Neuer Steuerberater f\u00fcr Hebamme (Diana Gatti kann das nicht)</li>';
  h += '<li>&#9744; Lohnsteuerhilfe-Kosten: 350 EUR/Jahr</li>';
  h += '</ul></div>';

  c.innerHTML = h;
}

function moneyCard(title, value, sub) {
  return '<div class="money-card"><div class="money-card-value">' + esc(value) + '</div><div class="money-card-title">' + esc(title) + '</div><div class="money-card-sub">' + esc(sub) + '</div></div>';
}

function mRow(a, b, c) {
  return '<tr><td>' + esc(a) + '</td><td>' + esc(b) + '</td><td>' + esc(c) + '</td></tr>';
}

function mRow2(a, b) {
  return '<tr><td>' + esc(a) + '</td><td>' + esc(b) + '</td></tr>';
}

function mRowStatus(name, amount, status, note) {
  var cls = status === 'keep' ? 'money-keep' : status === 'cut' ? 'money-cut' : 'money-check';
  var icon = status === 'keep' ? '&#9989;' : status === 'cut' ? '&#10060;' : '&#10067;';
  return '<tr class="' + cls + '"><td>' + icon + ' ' + esc(name) + '</td><td>' + esc(amount) + '</td><td>' + esc(note) + '</td></tr>';
}

function mRowBudget(name, current, target, note) {
  var cls = parseInt(current) > parseInt(target) ? 'money-over' : '';
  return '<tr class="' + cls + '"><td>' + esc(name) + '</td><td>' + esc(current) + '</td><td><strong>' + esc(target) + '</strong> ' + esc(note) + '</td></tr>';
}


