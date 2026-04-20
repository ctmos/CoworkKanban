// LifeOS Service Worker
const CACHE_NAME = 'lifeos-v7.16';
const isCustomDomain = self.location.hostname === 'lifeos.moser.ai' || self.location.hostname === 'app.moser.ai';
const BASE = isCustomDomain ? '/' : '/CoworkKanban/';
const APP_SHELL = [
  BASE,
  BASE + 'index.html',
  BASE + 'src/data-layer.js',
  BASE + 'app.js',
  BASE + 'style.css',
  BASE + 'manifest.json',
  BASE + 'icon-192.png',
  BASE + 'icon-512.png'
];

// Install: pre-cache app shell — KEIN skipWaiting() um Force-Reload zu verhindern
// Neuer SW wird erst aktiv wenn ALLE Tabs geschlossen werden (sicher für Daten)
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
  );
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(names =>
      Promise.all(
        names.filter(n => n !== CACHE_NAME).map(n => caches.delete(n))
      )
    ).then(() => self.clients.claim())
  );
});

// Fetch: different strategies per request type
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // GitHub API: Network-first with cache fallback (for offline, GET only)
  if (url.hostname === 'api.github.com') {
    if (event.request.method !== 'GET') return;
    event.respondWith(
      fetch(event.request.clone())
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // App shell: Network-first (always get latest, fallback to cache if offline)
  if (url.hostname === self.location.hostname) {
    event.respondWith(
      fetch(event.request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => caches.match(event.request))
    );
    return;
  }

  // Everything else: cache-first
  event.respondWith(
    caches.match(event.request).then(cached => cached || fetch(event.request))
  );
});

// Background Sync: process offline writes when back online
self.addEventListener('sync', event => {
  if (event.tag === 'cowork-sync') {
    event.waitUntil(syncPendingWrites());
  }
});

async function syncPendingWrites() {
  // Read pending writes from clients
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({ type: 'SYNC_REQUESTED' });
  });
}

// Listen for messages from main thread
// SKIP_WAITING ENTFERNT — SW-Updates dürfen NIEMALS laufende Tabs killen
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'CACHE_VERSION') {
    event.source.postMessage({ type: 'CACHE_VERSION_RESPONSE', version: CACHE_NAME });
  }
});
