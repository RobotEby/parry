# Admin API

The optional Admin API is read-only and exposes health, process metrics, recent
sanitized events, active bans, and normalized policies. It is never mounted
automatically.

## Fail-closed construction

```js
const { createParry, createParryAdminRouter } = require('@roboteby/parry');

const parry = createParry({ admin: { enabled: true } });
app.use(
  '/_parry',
  createParryAdminRouter(parry, {
    auth: { mode: 'token', token: process.env.PARRY_ADMIN_TOKEN },
  })
);
```

Construction throws when no authentication strategy exists. A token must be a
non-empty string. The legacy callback remains supported:

```js
createParryAdminRouter(parry, {
  auth: async (req) => authorizeAdmin(req),
});
```

For local development only, one of these explicit forms enables anonymous
access and emits a warning:

```js
{
  allowInsecureAdminApi: true;
}
{
  auth: {
    mode: 'none';
  }
}
{
  requireAuth: false;
} // deprecated alias
```

All three throw under `NODE_ENV=production`, even when combined with an override.

## Built-in modes

- `token`: constant-time comparison of `x-parry-admin-token` or a configured header.
- `ip-allowlist`: exact IPv4/IPv6 or CIDR rules.
- `trusted-proxy`: accepts identity headers only from a trusted direct proxy and
  can require fixed headers or a shared proxy secret.
- `cloudflare-access`: applies trusted-proxy/shared-secret boundaries plus email
  or domain policy to Cloudflare Access headers.
- `alb-auth` / `cognito-alb`: applies the same boundary model to AWS ALB identity
  headers and optional subject/email/domain policy.
- `combined`: evaluates either `allowAny` or `requireAll`; nested combined modes
  are rejected.

External identity headers are assertions from the configured boundary. In 1.x,
Parry does not perform JWKS signature verification. `verifyJwt: true` throws an
explicit configuration error; decoding claims is never presented as verification.

## Trusted boundary example

```js
createParryAdminRouter(parry, {
  auth: {
    mode: 'cloudflare-access',
    trustedProxies: ['10.0.0.0/8'],
    allowedDomains: ['example.com'],
  },
});
```

Prefer private networking, VPN, an identity-aware proxy, or ALB/Cognito for
production. Browser-visible shared tokens are suitable only for local demos.

## Endpoints

| Method | Path          | Purpose                                               |
| ------ | ------------- | ----------------------------------------------------- |
| `GET`  | `/health`     | Version, uptime, and store type                       |
| `GET`  | `/metrics`    | Per-process counters and active ban count             |
| `GET`  | `/events`     | Paginated sanitized event buffer                      |
| `GET`  | `/events/:id` | One event by ID                                       |
| `GET`  | `/bans`       | Active rate/brute-force blocks supported by the store |
| `GET`  | `/policies`   | Sanitized normalized policies                         |

List endpoints accept `limit` and `offset`. Events additionally accept `type`,
`severity`, `action`, `detector`, `ip`, `path`, and `policyName`.

The machine-readable contract is [OpenAPI](./openapi/parry-admin-api.yaml).
