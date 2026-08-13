var CACHE_NAME = 'ff-admin-v1';
var urlsToCache = [
    '/',
    '/admin/login.html',
    '/admin/index.html',
    '/uid-checker.html',
    '/video-lock.html',
    '/user-dashboard.html',
    '/manifest.json'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) { return cache.addAll(urlsToCache); })
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) { return response || fetch(event.request); })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.filter(function(name) { return name !== CACHE_NAME; })
                    .map(function(name) { return caches.delete(name); })
            );
        })
    );
});