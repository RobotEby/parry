# Docker Demo API

The Docker demo runs a local Express API protected by Parry and backed by RedisStore. It is intended for local development and for connecting the read-only `parry-security-console`.

This demo does not make Parry a volumetric DDoS protection product. Use CloudFront, AWS WAF, Shield, ALB, CDN, or equivalent edge and infrastructure controls for volumetric attacks.

## Start

```bash
docker compose up --build
```

Services:

- `redis`: `redis:7-alpine`, local demo only.
- `demo-api`: Express API on `http://localhost:3000`.

The demo token is:

```text
change-me
```

Use it only for local development.

The compose file uses token auth explicitly:

```env
PARRY_ADMIN_ENABLED=true
PARRY_ADMIN_AUTH_MODE=token
PARRY_ADMIN_TOKEN=change-me
```

Other local auth modes such as IP allowlist and trusted proxy are documented in [Admin API Authentication](./admin-api-auth.md).

## Smoke Tests

```bash
curl http://localhost:3000/health

curl http://localhost:3000/_parry/health \
  -H "x-parry-admin-token: change-me"

curl http://localhost:3000/_parry/metrics \
  -H "x-parry-admin-token: change-me"

curl -X POST http://localhost:3000/echo \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'
```

Generate a local defensive block event:

```bash
curl -X POST http://localhost:3000/echo \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR '\''1'\''='\''1"}'
```

Inspect events and bans:

```bash
curl http://localhost:3000/_parry/events \
  -H "x-parry-admin-token: change-me"

curl http://localhost:3000/_parry/bans \
  -H "x-parry-admin-token: change-me"
```

## Frontend Integration

For Vite proxy development in `parry-security-console`:

```env
VITE_PARRY_API_URL=/api/parry
VITE_PARRY_ADMIN_TOKEN=change-me
```

If you call the demo API directly from a browser origin, set a specific CORS origin:

```bash
PARRY_ADMIN_CORS_ORIGIN=http://localhost:5173 docker compose up --build
```

Parry does not allow `*` automatically. The demo CORS middleware only allows the configured origin and only the headers needed for JSON requests and `x-parry-admin-token`.

## Safety

- Use the included payload examples only against your local demo.
- Do not run payloads against third-party systems.
- `/echo` returns JSON only; it does not execute payloads, query a database, or make outbound requests.
- The Admin API is read-only and must not be exposed publicly without authentication and network controls.
