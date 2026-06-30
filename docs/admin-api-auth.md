# Admin API Authentication

The Parry Admin API is read-only, but it still exposes operational security data. Do not expose it publicly without authentication, network restrictions, or both.

Browser-visible tokens are acceptable only for local demos and development. Production deployments should prefer a private network, VPN, reverse proxy, IP allowlist, identity-aware proxy, or equivalent external control. Parry does not implement users, passwords, OAuth, or an auth database. Cloudflare Access and AWS ALB/Cognito modes trust an external gateway after validating a trusted network boundary; Parry does not become an OAuth provider.

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

## Cloudflare Access

Cloudflare Access should authenticate the user before traffic reaches the Parry app. Parry only trusts Cloudflare identity headers when the request comes from a configured trusted proxy boundary or presents a configured shared proxy secret.

```env
PARRY_ADMIN_AUTH_MODE=cloudflare-access
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=127.0.0.1
PARRY_CLOUDFLARE_EMAIL_HEADER=cf-access-authenticated-user-email
PARRY_CLOUDFLARE_JWT_HEADER=cf-access-jwt-assertion
PARRY_ADMIN_ALLOWED_EMAILS=admin@example.com
PARRY_ADMIN_ALLOWED_DOMAINS=example.com
PARRY_CLOUDFLARE_VERIFY_JWT=false
```

Programmatic configuration:

```js
createParry({
  admin: {
    enabled: true,
    auth: {
      mode: 'cloudflare-access',
      trustedProxies: ['127.0.0.1'],
      emailHeader: 'cf-access-authenticated-user-email',
      jwtHeader: 'cf-access-jwt-assertion',
      allowedEmails: ['admin@example.com'],
      allowedDomains: ['example.com'],
      verifyJwt: false,
    },
  },
});
```

If `verifyJwt: false`, use at least one trusted boundary: `trustedProxies`, a shared proxy secret, or private network controls that prevent direct public access. The current version does not perform cryptographic JWT/JWKS verification. Setting `verifyJwt: true` fails configuration intentionally instead of pretending to validate Cloudflare JWTs.

Never accept `cf-access-authenticated-user-email` from public clients directly. If `allowedEmails` or `allowedDomains` is set, Parry denies users outside those allowlists.

## AWS ALB Auth / Cognito

AWS ALB can authenticate requests with `authenticate-cognito` or `authenticate-oidc` before forwarding to ECS or another target. Parry supports `alb-auth` and `cognito-alb`; `cognito-alb` is a compatibility alias for the same ALB header strategy.

```env
PARRY_ADMIN_AUTH_MODE=cognito-alb
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=10.0.0.0/8
PARRY_ALB_USER_HEADER=x-amzn-oidc-identity
PARRY_ALB_DATA_HEADER=x-amzn-oidc-data
PARRY_ADMIN_ALLOWED_SUBJECTS=
PARRY_ADMIN_ALLOWED_EMAILS=
PARRY_ADMIN_ALLOWED_DOMAINS=example.com
PARRY_ALB_VERIFY_JWT=false
```

Programmatic configuration:

```js
createParry({
  admin: {
    enabled: true,
    auth: {
      mode: 'cognito-alb',
      trustedProxies: ['10.0.0.0/8'],
      userHeader: 'x-amzn-oidc-identity',
      dataHeader: 'x-amzn-oidc-data',
      allowedSubjects: [],
      allowedEmails: [],
      allowedDomains: ['example.com'],
      verifyJwt: false,
    },
  },
});
```

`x-amzn-oidc-identity` provides the subject. `x-amzn-oidc-data` may be decoded only as unverified claims to extract an email for allowlist checks. Parry does not log or return the raw OIDC data header. If an email/domain allowlist is configured and no email can be extracted, access is denied.

The current version does not perform cryptographic ALB JWT/JWKS verification. Setting `verifyJwt: true` fails configuration intentionally. Use HTTPS ALB listeners, ALB auth actions, security groups, and private ECS networking so clients cannot bypass the ALB and send `x-amzn-oidc-*` headers directly.

## VPN / Network-Only Access

When the Admin API does not need to be internet-facing, prefer a private path:

```txt
User
-> VPN
-> private ALB, internal NLB, or private reverse proxy
-> Parry Admin API
```

The Admin API can live behind private subnets and security groups that allow only the VPN CIDR or internal proxy. `ip-allowlist` can complement that network boundary:

```env
PARRY_ADMIN_AUTH_MODE=ip-allowlist
PARRY_ADMIN_ALLOWED_IPS=10.8.0.0/24
```

There is no login inside Parry in this pattern; authentication is handled by the VPN or network gateway. The frontend can be served only on the same internal network or behind the same external gateway.

## Nginx Example

```nginx
location /_parry/ {
  proxy_pass http://parry-demo-api:3000/_parry/;

  proxy_set_header X-Parry-Admin-Authenticated "true";
  proxy_set_header X-Parry-Admin-User $remote_user;
  proxy_set_header X-Parry-Admin-Email $remote_user;
  proxy_set_header X-Parry-Proxy-Secret "<shared-secret>";

  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Real-IP $remote_addr;
}
```

When using this mode, block direct public access to the Node.js app with firewall rules, security groups, private networking, or equivalent controls.

## Caddy Example

```caddyfile
admin.example.com {
  reverse_proxy parry-demo-api:3000 {
    header_up X-Parry-Admin-Authenticated "true"
    header_up X-Parry-Admin-User "{http.auth.user.id}"
    header_up X-Parry-Proxy-Secret "<shared-secret>"
    header_up X-Forwarded-For "{remote_host}"
    header_up X-Real-IP "{remote_host}"
  }
}
```

The Caddy/Nginx examples are reverse-proxy patterns, not a substitute for real authentication. Put basic auth, SSO, VPN, mTLS, Cloudflare Access, or another access-control layer in front of the proxy and prevent direct access to the Node.js app.

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

Headers can be spoofed by clients. Trust `x-forwarded-for`, `x-real-ip`, `cf-access-*`, `x-amzn-oidc-*`, and administrative identity headers only when the direct peer is a trusted proxy or the request includes a valid shared proxy secret. In production, put the Admin API behind private networking, VPN, a reverse proxy, IP allowlists, Cloudflare Access, AWS ALB auth/Cognito, or equivalent external authentication. Do not rely on a browser token as a production access-control boundary.
