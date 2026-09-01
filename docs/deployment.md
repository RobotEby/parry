# Deployment

## Node.js

Parry 2.0.0 requires Node `>=22` and Express `^5.2.1`. CI covers Node 22 and 24.
The package remains CommonJS.

Install reproducibly with `npm ci`. Keep Express body-size limits at or below the
shape expected by the application, and run body parsers before Parry.

## Multiple instances

Use `RedisStore` whenever rate-limit or brute-force state must survive process
boundaries. Redis state does not distribute the in-memory event buffer or metrics;
export events and metrics independently. Choose `storeFailureMode` according to
availability and security requirements.

Configure `trustProxyHeaders` only with the exact IPs/CIDRs of direct proxies.
Parry walks XFF from right to left but cannot compensate for an overly broad
trust boundary.

## Docker demo

The demo image is multi-stage, installs with `npm ci --omit=dev`, and runs as the
non-root `parry` user.

```bash
docker build -f docker/demo-api/Dockerfile -t parry-demo-api .
docker compose up --build
```

Compose does not publish Redis to the host. For local development only, the
Admin token defaults through `${PARRY_ADMIN_TOKEN:-change-me}`. Override it in
your shell. The application never supplies `change-me` when
`NODE_ENV=production`; an enabled production Admin API without a real token
fails construction.

## Optional AWS example

[`infra/examples/aws`](../infra/examples/aws/README.md) is an optional example,
not a production platform or an automated deployment. It composes CloudFront,
WAF, ALB, ECS Fargate, ElastiCache, and CloudWatch Logs. It does not automate
`terraform apply`.

The example disables the Admin API when no Admin token secret ARN is supplied.
It has no unused Admin CIDR or alarm placeholders. Copy the tfvars example,
provide an immutable container image, review all cost-bearing resources, and
protect Terraform state before considering an apply.

```bash
terraform fmt -check -recursive infra/examples/aws
terraform -chdir=infra/examples/aws/environments/dev init -backend=false
terraform -chdir=infra/examples/aws/environments/dev validate
```

The plan workflow requires GitHub OIDC configuration and a real container image
input. It uploads a textual plan and never applies it.

## GitHub and AWS

Repository variables for AWS jobs are environment-specific and are not created
by this repository. Use a least-privilege GitHub OIDC role, environment approvals
for production, protected branches, immutable image tags, and a dedicated secret
manager. Do not store long-lived AWS keys in Actions secrets.
