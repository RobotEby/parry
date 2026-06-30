# AWS Admin API Authentication

This note covers production-oriented ways to protect the Parry Admin API on AWS. The Admin API is read-only, but it still exposes operational security data and should not be public without authentication and network restrictions.

Parry remains application-layer middleware. CloudFront, AWS WAF, Shield, ALB, private networking, and security groups protect the edge and infrastructure layers. Parry protects inside the Express application.

## Recommended Shape

```txt
Operator
-> VPN, CloudFront/WAF, or private network
-> HTTPS ALB
-> authenticate-cognito or authenticate-oidc on /_parry/*
-> private ECS task running Parry
-> private Redis/ElastiCache
```

ECS tasks should accept traffic only from the ALB security group. Do not expose the task ENI or container port directly to the internet.

## ALB Auth With Cognito

Use an HTTPS listener and add a listener rule for the Admin API path before the default app forward rule:

1. Match path `/_parry/*`.
2. Run `authenticate-cognito`.
3. Forward to the Parry target group.

Example Parry environment:

```env
PARRY_ADMIN_AUTH_MODE=cognito-alb
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=10.0.0.0/8
PARRY_ALB_USER_HEADER=x-amzn-oidc-identity
PARRY_ALB_DATA_HEADER=x-amzn-oidc-data
PARRY_ADMIN_ALLOWED_DOMAINS=example.com
PARRY_ALB_VERIFY_JWT=false
```

The ALB performs authentication. Parry accepts `x-amzn-oidc-*` headers only from trusted ALB/proxy addresses or a configured shared proxy secret. In this version, Parry may decode `x-amzn-oidc-data` as unverified claims for email allowlist checks, but it does not cryptographically verify the JWT signature or JWKS.

## ALB Auth With OIDC

The same Parry `alb-auth` strategy can be used when ALB authenticates with an external OIDC provider:

```env
PARRY_ADMIN_AUTH_MODE=alb-auth
PARRY_ADMIN_TRUST_PROXY_HEADERS=true
PARRY_ADMIN_TRUSTED_PROXIES=10.0.0.0/8
PARRY_ADMIN_ALLOWED_SUBJECTS=provider-subject-id
PARRY_ADMIN_ALLOWED_EMAILS=admin@example.com
PARRY_ALB_VERIFY_JWT=false
```

Store OIDC client secrets in AWS Secrets Manager or SSM Parameter Store. Do not commit them to Terraform variables or application env files.

## Terraform Status

The Terraform reference does not automatically create the `/_parry/*` ALB auth listener rule because Cognito/OIDC configuration, HTTPS listener setup, rule ordering, path precedence, and secret handling vary by environment.

Suggested future variables:

```hcl
enable_alb_auth = false
alb_auth_type   = "cognito" # cognito | oidc

cognito_user_pool_arn       = null
cognito_user_pool_client_id = null
cognito_user_pool_domain    = null

admin_path_pattern  = "/_parry/*"
admin_allowed_cidrs = []
```

Until that is implemented, configure ALB auth manually or keep Admin API access private through VPN/internal networking and use Parry `ip-allowlist` or `trusted-proxy` mode inside the application.

## WAF and CIDR Controls

AWS WAF can add another boundary for `/_parry/*`, such as managed rules, rate-based rules, and IP set allowlists. WAF is not a replacement for application Admin API auth. Use it as a defense-in-depth control.

For private administration, prefer:

- VPN or AWS Client VPN CIDRs allowed to an internal ALB.
- Security groups that allow the Admin API path only through trusted ALB/proxy paths.
- CloudFront/WAF in front of the ALB when public edge exposure is required.

## Security Notes

- Never trust `x-amzn-oidc-*` headers from public clients.
- Block direct access to ECS tasks when relying on ALB auth.
- Use HTTPS in production.
- Keep Terraform state encrypted and locked when it references sensitive ARNs or secrets.
- Prefer AWS Secrets Manager/SSM for OIDC client secrets and Parry proxy shared secrets.
- Consider AWS Shield Advanced, Security Hub, GuardDuty, WAF logging, and centralized SIEM pipelines for production-critical environments.
