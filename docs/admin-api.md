# Parry Admin API

The Parry Admin API is an optional, read-only Express router for operational dashboards such as `parry-security-console`. It exposes health, metrics, recent security events, active MemoryStore bans, and normalized route policies.

The router is never mounted automatically:

```js
const { createParry, createParryAdminRouter } = require('@roboteby/parry');

const parry = createParry({ admin: { enabled: true } });

app.use(parry.middleware());
app.use(
  '/_parry',
  createParryAdminRouter(parry, {
    auth: (req) => req.headers['x-parry-admin-token'] === process.env.PARRY_ADMIN_TOKEN,
  })
);
```

## Security

- Never expose `/_parry` publicly without authentication and network restrictions.
- Parry does not enable CORS automatically. If `parry-security-console` runs on a separate origin, configure CORS explicitly in the host application.
- A token stored directly in a browser frontend is suitable only for demos or local development. Production deployments should put the Admin API behind a backend-for-frontend, VPN, private network, identity-aware proxy, or equivalent control.
- Do not forward cookies, Authorization headers, application secrets, or raw request bodies into events or Admin API metadata.
- The examples use `x-parry-admin-token` as the recommended admin header, but authentication is controlled by your own middleware or the router `auth(req)` callback.

## Common Response Shapes

List endpoints use:

```json
{
  "data": [],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 0
  }
}
```

Errors use:

```json
{
  "error": "Unauthorized",
  "code": "ADMIN_UNAUTHORIZED",
  "message": "Unauthorized"
}
```

The `message` field is retained for compatibility. New consumers should key on `error` and `code`.

## Authentication Header

Recommended header:

| Header                | Required    | Notes                                                                                     |
| --------------------- | ----------- | ----------------------------------------------------------------------------------------- |
| `x-parry-admin-token` | Recommended | Validate this header in external middleware or `createParryAdminRouter(parry, { auth })`. |

If no auth middleware and no `auth` callback are configured, the router is open. That is acceptable only for local tests.

## GET /\_parry/health

Returns basic Admin API status.

### Query Params

None.

### Example Response

```json
{
  "ok": true,
  "name": "parry",
  "version": "1.0.0",
  "uptimeMs": 124532,
  "store": "memory"
}
```

### Status Codes

| Status | Meaning                                                                  |
| ------ | ------------------------------------------------------------------------ |
| `200`  | Health status returned.                                                  |
| `401`  | Admin auth failed or `requireAuth` was enabled without a valid callback. |

### Security Notes

This endpoint does not include secrets, runtime environment variables, Redis URLs, or internal credentials.

## GET /\_parry/metrics

Returns an in-process metrics snapshot.

### Query Params

None.

### Example Response

```json
{
  "startedAt": "2026-06-29T12:00:00.000Z",
  "uptimeMs": 124532,
  "totalRequests": 1284,
  "allowedRequests": 1190,
  "blockedRequests": 94,
  "rateLimitedRequests": 21,
  "bruteForceBlocks": 4,
  "activeBans": 2,
  "eventsByType": {
    "SQL_INJECTION_BLOCKED": 12,
    "RATE_LIMIT_EXCEEDED": 21
  },
  "eventsBySeverity": {
    "medium": 40,
    "high": 54
  },
  "eventsByDetector": {
    "SQL_INJECTION": 12,
    "XSS": 8
  },
  "eventsByAction": {
    "blocked": 94
  }
}
```

### Status Codes

| Status | Meaning            |
| ------ | ------------------ |
| `200`  | Metrics returned.  |
| `401`  | Admin auth failed. |

### Security Notes

Metrics are process-local and lightweight. They are useful for dashboards, but they do not replace CloudWatch, SIEM, WAF logs, Prometheus, OpenTelemetry, or provider-level observability.

## GET /\_parry/events

Returns recent sanitized threat events.

### Query Params

| Param        | Type    | Notes                                                            |
| ------------ | ------- | ---------------------------------------------------------------- |
| `limit`      | integer | Default `50`, min `1`, max depends on event store configuration. |
| `offset`     | integer | Default `0`.                                                     |
| `type`       | string  | Example: `SQL_INJECTION_BLOCKED`.                                |
| `severity`   | string  | `low`, `medium`, `high`, or `critical`.                          |
| `action`     | string  | Example: `blocked`, `observed`, `error`.                         |
| `detector`   | string  | Internal detector value, for example `SQL_INJECTION`.            |
| `ip`         | string  | Exact IP filter.                                                 |
| `path`       | string  | Exact path filter, for example `/login`.                         |
| `policyName` | string  | Exact policy name filter.                                        |

### Example Response

```json
{
  "data": [
    {
      "id": "evt_lx9a1b_1",
      "type": "SQL_INJECTION_BLOCKED",
      "module": "detector",
      "detector": "SQL_INJECTION",
      "detectorSlug": "sql",
      "severity": "high",
      "action": "blocked",
      "reason": "SQL injection pattern detected",
      "ip": "203.0.113.10",
      "method": "POST",
      "path": "/login",
      "statusCode": 400,
      "requestId": "req_demo_001",
      "userAgent": "Mozilla/5.0 dashboard demo",
      "timestamp": "2026-06-29T12:01:04.000Z",
      "metadata": {
        "target": "body.username"
      }
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### Status Codes

| Status | Meaning              |
| ------ | -------------------- |
| `200`  | Event list returned. |
| `401`  | Admin auth failed.   |

### Security Notes

Events are sanitized before storage and before callback delivery. Do not add raw request bodies, credentials, cookies, Authorization headers, or application secrets to custom metadata.

## GET /\_parry/events/:id

Returns one sanitized threat event by id.

### Path Params

| Param | Type   | Notes                                 |
| ----- | ------ | ------------------------------------- |
| `id`  | string | Event id, for example `evt_lx9a1b_1`. |

### Example Response

```json
{
  "id": "evt_lx9a1b_1",
  "type": "SQL_INJECTION_BLOCKED",
  "module": "detector",
  "detector": "SQL_INJECTION",
  "detectorSlug": "sql",
  "severity": "high",
  "action": "blocked",
  "reason": "SQL injection pattern detected",
  "ip": "203.0.113.10",
  "method": "POST",
  "path": "/login",
  "statusCode": 400,
  "requestId": "req_demo_001",
  "timestamp": "2026-06-29T12:01:04.000Z",
  "metadata": {
    "target": "body.username"
  }
}
```

### Status Codes

| Status | Meaning                 |
| ------ | ----------------------- |
| `200`  | Event returned.         |
| `401`  | Admin auth failed.      |
| `404`  | Event id was not found. |

## GET /\_parry/bans

Returns active bans when the configured store exposes a safe ban snapshot. MemoryStore supports this. Stores without a snapshot return an empty list.

### Query Params

| Param    | Type    | Notes                             |
| -------- | ------- | --------------------------------- |
| `limit`  | integer | Default `50`, min `1`, max `500`. |
| `offset` | integer | Default `0`.                      |

### Example Response

```json
{
  "data": [
    {
      "key": "203.0.113.25",
      "banExpiresAt": 1782734520000,
      "metadata": {
        "reason": "temporary application-layer ban"
      }
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### Status Codes

| Status | Meaning            |
| ------ | ------------------ |
| `200`  | Ban list returned. |
| `401`  | Admin auth failed. |

### Security Notes

Ban keys may identify IPs or internal store keys. Treat this endpoint as operational data and protect it like other admin telemetry.

## GET /\_parry/policies

Returns normalized route policies without functions or raw request data.

### Query Params

| Param    | Type    | Notes                             |
| -------- | ------- | --------------------------------- |
| `limit`  | integer | Default `50`, min `1`, max `500`. |
| `offset` | integer | Default `0`.                      |

### Example Response

```json
{
  "data": [
    {
      "name": "auth-login",
      "match": {
        "method": "POST",
        "path": "/login"
      },
      "inheritGlobalRateLimit": true,
      "rateLimit": {
        "enabled": true,
        "max": 20,
        "windowMs": 60000,
        "key": "ip"
      },
      "bruteForce": {
        "enabled": true,
        "maxAttempts": 5,
        "windowMs": 900000,
        "blockDurationMs": 600000,
        "keyTypes": ["ip", "body.email", "ip+body.email"],
        "resetOnSuccess": true
      }
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### Status Codes

| Status | Meaning               |
| ------ | --------------------- |
| `200`  | Policy list returned. |
| `401`  | Admin auth failed.    |

### Security Notes

Policies should describe matching and limits only. Do not encode secrets, credentials, or sensitive tenant identifiers into policy names or custom key labels.
