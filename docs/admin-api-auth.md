# Admin API Authentication

The Parry Admin API is read-only, but it still exposes operational security data. Do not expose it publicly without authentication, network restrictions, or both.

Browser-visible tokens are acceptable only for local demos and development. Production deployments should prefer a private network, VPN, reverse proxy, IP allowlist, identity-aware proxy, or equivalent external control. Parry does not implement users, passwords, OAuth, Cognito, Cloudflare Access, or an auth database.

## Local Token Mode

The Docker demo defaults to token mode:

```env
PARRY_ADMIN_ENABLED=true
PARRY_ADMIN_AUTH_MODE=token
PARRY_ADMIN_TOKEN=change-me
```

Requests must send:

```http
x-parry-admin-token: change-me
```

Missing credentials return `401`. Wrong credentials return `403`. Tokens are compared in constant time and are never returned in responses.

Programmatic configuration:

```js
const parry = createParry({
  admin: {
    enabled: true,
    path: '/_parry',
    auth: {
      mode: 'token',
      token: process.env.PARRY_ADMIN_TOKEN,
    },
  },
});

app.use(parry.middleware());
app.use('/_parry', createParryAdminRouter(parry));
```

## IP Allowlist Mode

IP allowlists support IPv4, IPv6, IPv4-mapped IPv6, exact IPs, and CIDR ranges.

```env
PARRY_ADMIN_AUTH_MODE=ip-allowlist
PARRY_ADMIN_ALLOWED_IPS=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

By default Parry ignores `x-forwarded-for`. If the app is behind a trusted proxy and you need to allowlist the original client IP, configure trusted proxy handling:

```env
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
```

Only direct peers listed in `trustedProxies` may provide forwarded client IP headers.

## Trusted Proxy Mode

Trusted proxy mode is for Nginx, Traefik, Caddy, Cloudflare Tunnel, VPN gateways, or a private reverse proxy that authenticates the user before forwarding traffic to the app.

```env
PARRY_ADMIN_AUTH_MODE=trusted-proxy
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
PARRY_ADMIN_REQUIRED_HEADER=x-parry-admin-authenticated:true
PARRY_PROXY_SHARED_SECRET=replace-with-secret
PARRY_PROXY_SHARED_SECRET_HEADER=x-parry-proxy-secret
```

The app accepts administrative identity headers only when the direct peer is trusted. Public clients cannot grant themselves access by sending `x-parry-admin-authenticated`.

Optional identity headers:

- `x-parry-admin-user`
- `x-parry-admin-email`
- `x-parry-admin-roles`

Shared proxy secrets are compared in constant time and are never logged or returned.

## Nginx Example

```nginx
location /_parry/ {
  proxy_pass http://parry-demo-api:3000/_parry/;

  proxy_set_header X-Parry-Admin-Authenticated "true";
  proxy_set_header X-Parry-Admin-User $remote_user;
  proxy_set_header X-Parry-Proxy-Secret "<shared-secret>";

  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Real-IP $remote_addr;
}
```

When using this mode, block direct public access to the Node.js app with firewall rules, security groups, private networking, or equivalent controls.

## Combined Mode

`combined` supports simple `allowAny` or `requireAll` policy composition:

```js
createParry({
  admin: {
    enabled: true,
    auth: {
      mode: 'combined',
      allowAny: [
        { mode: 'token', token: process.env.PARRY_ADMIN_TOKEN },
        { mode: 'ip-allowlist', allowedIps: ['127.0.0.1', '::1'] },
      ],
    },
  },
});
```

Use `requireAll` when a request must satisfy every strategy. `allowAny` and `requireAll` cannot be used together. Nested `combined` strategies are intentionally rejected.

## Insecure None Mode

`none` is for isolated local tests only:

```js
createParryAdminRouter(parry, {
  auth: {
    mode: 'none',
    allowInsecureAdminApi: true,
  },
});
```

It is rejected in production unless `allowInsecureAdminApi` is explicitly true, and Parry emits a warning when it is used.

## Threat Model

Headers can be spoofed by clients. Trust `x-forwarded-for`, `x-real-ip`, and administrative identity headers only when the direct peer is a trusted proxy. In production, put the Admin API behind private networking, VPN, a reverse proxy, IP allowlists, or external authentication. Do not rely on a browser token as a production access-control boundary.
