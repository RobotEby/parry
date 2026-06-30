# Store Contract

Stores keep rate limit, temporary ban, and suspicious activity state for Parry.
Methods may return values directly or return Promises.

```js
store.incrementRateLimit(key, windowMs);
// -> { key, count, resetAt, ttlMs }

store.getRateLimit(key);
// -> { key, count, resetAt, ttlMs }

store.resetRateLimit(key);
store.ban(key, ttlMs, metadata);
store.isBanned(key);
// -> { key, banned, banExpiresAt, metadata }

store.unban(key);
store.recordSuspicious(key, ttlMs, metadata);
// -> { key, count, resetAt, ttlMs }

store.incrementCounter(key, ttlMs, metadata);
// -> { key, count, resetAt, ttlMs }

store.getCounter(key);
// -> { key, count, resetAt, ttlMs }

store.resetCounter(key);
store.blockKey(key, ttlMs, metadata);
store.isBlocked(key);
// -> { key, blocked, blockExpiresAt, metadata }

store.unblockKey(key);

store.listBans?.({ limit, offset });
// -> [{ key, createdAt, banExpiresAt, ttlMs, metadata }]

store.listBlocks?.({ limit, offset });
// -> [{ key, createdAt, blockExpiresAt, ttlMs, metadata }]

store.getStoreInfo?.();
// -> { type, supportsAdminListing, ...metadata }

store.close?.();
```

`key` is produced by the rate limiter, route policy, or brute force key builder.
Stores are responsible for TTL handling, cleanup, and any backend-specific
namespacing. Custom stores should avoid persisting sensitive request data.
Administrative listing methods are optional, but stores that implement them must
return only sanitized metadata suitable for a read-only operations dashboard.
