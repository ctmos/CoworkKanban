// LifeOS Service Worker v4.7
const CACHE_NAME = 'lifeos-v5.12';
const APP_SHELL = [
  '/CoworkKanban/',
  '/CoworkKanban/index.html',
  '/CoworkKanban/style.css',
  '/CoworkKanban/manifest.json',
  '/CoworkKanban/icon-192.png',
  '/CoworkKanban/icon-512.png'
];

// Install: pre-cache app shell
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
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
  if (url.pathname.startsWith('/CoworkKanban/')) {
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
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data && event.data.type === 'CACHE_VERSION') {
    event.source.postMessage({ type: 'CACHE_VERSION_RESPONSE', version: CACHE_NAME });
  }
});
