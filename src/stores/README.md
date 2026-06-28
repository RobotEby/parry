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

store.close?.();
```

`key` is produced by the rate limiter. Stores are responsible for TTL handling,
cleanup, and any backend-specific namespacing. Custom stores should avoid
persisting sensitive request data.
