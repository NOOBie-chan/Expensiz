// Expensiz service worker: keeps the app opening offline. Change V when you upload a new version.
const V = "expensiz-v1", LIBS = "expensiz-libs", SHELL = ["./", "index.html", "manifest.webmanifest", "icon-192.png", "icon-512.png"];
self.addEventListener("install", (e) => e.waitUntil(caches.open(V).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener("activate", (e) => e.waitUntil(caches.keys().then((k) => Promise.all(k.filter((x) => x !== V && x !== LIBS).map((x) => caches.delete(x)))).then(() => self.clients.claim())));
self.addEventListener("fetch", (e) => {
  const r = e.request; if (r.method !== "GET") return;
  const u = new URL(r.url);
  if (u.origin === location.origin) { // the app itself: newest copy when online, saved copy when offline
    e.respondWith(fetch(r).then((res) => { const cp = res.clone(); caches.open(V).then((c) => c.put(r, cp)); return res; })
      .catch(() => caches.match(r).then((m) => m || caches.match("index.html"))));
  } else if (/^(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net)$/.test(u.host)) { // Excel, PDF and MEGA libraries, kept after first use
    e.respondWith(caches.match(r).then((m) => m || fetch(r).then((res) => { const cp = res.clone(); caches.open(LIBS).then((c) => c.put(r, cp)); return res; })));
  } // everything else (your server, exchange rates) always goes straight to the network
});
