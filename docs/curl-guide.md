# cURL Guide

This guide provides local `curl` commands for validating the Parry Docker demo API, the read-only Parry Admin API, Threat Events, bans/blocks, brute-force protection, rate limiting, CORS behavior, request IDs, and frontend Vite proxy integration.

> These commands are intended for local/demo environments only. Do not run security payloads against systems you do not own or have explicit permission to test.

Parry is application-layer security middleware for Express.js. It does not replace CloudFront, AWS WAF, Shield, Cloudflare, a CDN, an ALB, or other edge-layer controls for volumetric DDoS protection.

## Prerequisites

Start the local demo API and Redis:

```bash
docker compose up --build
```

The demo API listens on `http://localhost:3000` and uses the local demo Admin API token `change-me`.

## Environment variables

Set these variables in your shell:

```bash
API="http://localhost:3000"
ADMIN="$API/_parry"
TOKEN="change-me"
```

## Public demo API

```bash
curl -i "$API/health"
```

## Admin API authentication

Without a token:

```bash
curl -i "$ADMIN/health"
```

With the wrong token:

```bash
curl -i "$ADMIN/health" \
  -H "x-parry-admin-token: wrong-token"
```

With the local demo token:

```bash
curl -i "$ADMIN/health" \
  -H "x-parry-admin-token: $TOKEN"
```

The `change-me` token is for local demos only. Do not expose the Admin API publicly without authentication and network controls.

## Admin API endpoints

```bash
curl "$ADMIN/health" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/metrics" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?limit=10&offset=0" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/bans" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/policies" \
  -H "x-parry-admin-token: $TOKEN"
```

Filter recent events:

```bash
curl "$ADMIN/events?detector=sql" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?detector=xss" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?detector=brute-force" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?action=blocked" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?severity=high" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?path=/echo" \
  -H "x-parry-admin-token: $TOKEN"
```

Fetch a specific event after copying an event ID from `/events`:

```bash
curl "$ADMIN/events/<EVENT_ID>" \
  -H "x-parry-admin-token: $TOKEN"
```

## Normal demo requests

```bash
curl "$API/search?q=nodejs"

curl -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'

curl -i -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"password123"}'

curl -i -X POST "$API/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"wrong"}'
```

## SQL Injection test payloads

These are local defensive validation payloads for the demo API.

```bash
curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR '\''1'\''='\''1"}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' --","password":"x"}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"query":"1 UNION SELECT username,password FROM users"}'

curl -i "$API/search?q=%27%20OR%20%271%27%3D%271"

curl "$ADMIN/events?detector=sql" \
  -H "x-parry-admin-token: $TOKEN"
```

## XSS test payloads

These payload strings are sent only to the local demo API.

```bash
curl -i "$API/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"comment":"<script>alert(1)</script>"}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"comment":"<img src=x onerror=alert(1)>"}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"comment":"<svg onload=alert(1)>"}'

curl "$ADMIN/events?detector=xss" \
  -H "x-parry-admin-token: $TOKEN"
```

## NoSQL Injection test payloads

The demo API does not query a database. These payloads are submitted only to validate detector behavior locally.

```bash
curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"email":{"$ne":null}}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"role":{"$in":["admin","root"]}}'

curl "$ADMIN/events?detector=nosql" \
  -H "x-parry-admin-token: $TOKEN"
```

## Prototype Pollution test payloads

```bash
curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"polluted":true}}}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"prototype":{"isAdmin":true}}'

curl "$ADMIN/events?detector=prototype-pollution" \
  -H "x-parry-admin-token: $TOKEN"
```

## Path Traversal test payloads

```bash
curl -i "$API/search?q=../../../../etc/passwd"

curl -i "$API/search?q=..%2F..%2F..%2F..%2Fetc%2Fpasswd"

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"file":"../../../../etc/passwd"}'

curl "$ADMIN/events?detector=path-traversal" \
  -H "x-parry-admin-token: $TOKEN"
```

## HTTP Parameter Pollution checks

```bash
curl -i "$API/search?q=normal&q=admin"

curl -i "$API/search?role=user&role=admin"

curl "$ADMIN/events?detector=hpp" \
  -H "x-parry-admin-token: $TOKEN"
```

HTTP Parameter Pollution checks may depend on the active preset/configuration used by the demo API. The Docker demo enables `PARRY_HPP_ENABLED` only when configured explicitly.

## Brute-force protection

Submit repeated failed local login attempts:

```bash
for i in {1..12}; do
  curl -s -X POST "$API/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"demo@example.com","password":"wrong"}'
  echo
done
```

Inspect active bans/blocks and brute-force events:

```bash
curl "$ADMIN/bans" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?detector=brute-force" \
  -H "x-parry-admin-token: $TOKEN"
```

The BruteForceGuard may block by IP, identity, or composite keys such as IP + email. If an IP-level block is active, other login identities from the same source may also be blocked until the TTL expires.

## Rate limit checks

```bash
for i in {1..150}; do
  curl -s -o /dev/null -w "%{http_code}\n" "$API/health"
done

for i in {1..150}; do
  curl -s -o /dev/null -w "%{http_code}\n" "$API/search?q=test-$i"
done

curl "$ADMIN/metrics" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/events?detector=rate-limit" \
  -H "x-parry-admin-token: $TOKEN"
```

Rate-limit thresholds depend on the demo environment variables and active route policies. The default Docker demo uses `PARRY_RATE_LIMIT_MAX=120` unless overridden.

## CORS checks

CORS is not opened by default. Start the demo with an explicit local frontend origin before running these checks:

```bash
PARRY_ADMIN_CORS_ORIGIN=http://localhost:5173 docker compose up --build
```

Then test preflight and allowed origin behavior:

```bash
curl -i -X OPTIONS "$ADMIN/health" \
  -H "Origin: http://localhost:5173" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: x-parry-admin-token,content-type"

curl -i "$ADMIN/health" \
  -H "Origin: http://localhost:5173" \
  -H "x-parry-admin-token: $TOKEN"

curl -i "$ADMIN/health" \
  -H "Origin: http://evil.localhost" \
  -H "x-parry-admin-token: $TOKEN"
```

The demo does not configure wildcard CORS. Production deployments should configure CORS deliberately for the frontend deployment model.

## Frontend Vite proxy checks

These commands require the Parry Security Console dev server to be running with `VITE_PARRY_API_URL=/api/parry`.

```bash
curl -i "http://localhost:5173/api/parry/health" \
  -H "x-parry-admin-token: $TOKEN"

curl "http://localhost:5173/api/parry/events" \
  -H "x-parry-admin-token: $TOKEN"

curl "http://localhost:5173/api/parry/bans" \
  -H "x-parry-admin-token: $TOKEN"
```

## Request ID checks

```bash
curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-manual-001" \
  -d '{"message":"hello with request id"}'

curl -i -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -H "x-request-id: req-sqli-001" \
  -d '{"username":"'\'' OR '\''1'\''='\''1"}'

curl "$ADMIN/events" \
  -H "x-parry-admin-token: $TOKEN"
```

## Advanced Admin API auth modes

These modes depend on environment variables when starting the demo. Stop the current compose stack before switching modes:

```bash
docker compose down
```

### IP allowlist

```bash
PARRY_ADMIN_AUTH_MODE=ip-allowlist \
PARRY_ADMIN_ALLOWED_IPS=127.0.0.1,::1,172.16.0.0/12 \
docker compose up --build
```

Test:

```bash
curl -i "$ADMIN/health"
```

### Trusted proxy

```bash
PARRY_ADMIN_AUTH_MODE=trusted-proxy \
PARRY_ADMIN_TRUST_PROXY_HEADERS=true \
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12 \
PARRY_ADMIN_REQUIRED_HEADER=x-parry-admin-authenticated:true \
PARRY_PROXY_SHARED_SECRET=dev-secret \
docker compose up --build
```

Test:

```bash
curl -i "$ADMIN/health"

curl -i "$ADMIN/health" \
  -H "x-parry-admin-authenticated: true" \
  -H "x-parry-proxy-secret: dev-secret" \
  -H "x-parry-admin-user: local-admin" \
  -H "x-parry-admin-email: admin@example.com"
```

### Cloudflare Access simulated mode

```bash
PARRY_ADMIN_AUTH_MODE=cloudflare-access \
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12 \
PARRY_ADMIN_ALLOWED_DOMAINS=example.com \
docker compose up --build
```

Test:

```bash
curl -i "$ADMIN/health" \
  -H "cf-access-authenticated-user-email: admin@example.com"
```

### ALB/Cognito simulated mode

```bash
PARRY_ADMIN_AUTH_MODE=cognito-alb \
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1,172.16.0.0/12 \
PARRY_ADMIN_ALLOWED_SUBJECTS=local-subject \
docker compose up --build
```

Test:

```bash
curl -i "$ADMIN/health" \
  -H "x-amzn-oidc-identity: local-subject"
```

Cloudflare Access and ALB/Cognito commands are local simulations. Real deployments should validate identity at the edge or load balancer and only trust identity headers from trusted proxies or private networks.

## Resetting local Redis state

Reset the Docker volume and restart:

```bash
docker compose down -v
docker compose up --build
```

Flush Redis manually:

```bash
docker ps
docker exec -it <redis-container-name> redis-cli FLUSHALL
```

## Full local validation sequence

```bash
API="http://localhost:3000"
ADMIN="$API/_parry"
TOKEN="change-me"

curl "$API/health"

curl "$ADMIN/health" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/metrics" \
  -H "x-parry-admin-token: $TOKEN"

curl -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'

curl -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"username":"'\'' OR '\''1'\''='\''1"}'

curl -X POST "$API/echo" \
  -H "Content-Type: application/json" \
  -d '{"comment":"<script>alert(1)</script>"}'

for i in {1..12}; do
  curl -s -X POST "$API/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"demo@example.com","password":"wrong"}'
  echo
done

curl "$ADMIN/events" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/bans" \
  -H "x-parry-admin-token: $TOKEN"

curl "$ADMIN/policies" \
  -H "x-parry-admin-token: $TOKEN"
```
