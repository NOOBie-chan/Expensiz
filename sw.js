// Expensiz service worker: keeps the app working offline.
const CACHE = "expensiz-v1";
const FILES = ["./", "index.html", "manifest.webmanifest", "icon-192.png", "icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => Promise.all(FILES.map((f) => c.add(f).catch(() => {}))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (e) => {
  const r = e.request, u = new URL(r.url);
  // Only handle this app's own files. Server calls and MEGA go straight to the network.
  if (r.method !== "GET" || u.origin !== location.origin) return;
  e.respondWith(
    fetch(r)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(r, copy));
        return res;
      })
      .catch(() => caches.match(r).then((m) => m || caches.match("index.html"))),
  );
});
