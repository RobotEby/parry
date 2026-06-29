# AWS Security Notes

Parry is an application-layer security middleware. It runs after traffic reaches
the Express application. It does not absorb volumetric DDoS attacks, network
floods, or connection exhaustion on its own.

## Layered Responsibilities

- CloudFront, AWS WAF, Shield, ALB, and resilient AWS architecture protect the
  edge and infrastructure.
- Parry protects inside the application by enforcing distributed rate limiting,
  brute force policies, payload abuse detectors, request guards, and threat
  events.
- RedisStore coordinates counters across ECS tasks and other replicas.

Use both layers. Do not treat either WAF or Parry as a full substitute for the
other.

## Network Security

- ECS tasks run in private subnets with `assign_public_ip = false`.
- ElastiCache Redis runs in private subnets.
- Redis allows inbound traffic only from the ECS service security group.
- The ALB is public and receives traffic from CloudFront or direct dev tests.
- The Admin API route `/_parry` must not be public without strong authentication
  and network restrictions.

For production, consider private admin access through VPN, private network
paths, identity-aware access, IP allowlists, or a separate internal service.

## Secrets

Do not commit AWS credentials, tokens, Redis passwords, or `terraform.tfvars`.

Use AWS Secrets Manager, SSM Parameter Store, or CI/CD secret storage for:

- `PARRY_ADMIN_TOKEN`
- Redis AUTH token, if enabled
- any future application secrets

If Terraform configures a Redis AUTH token directly through `redis_auth_token`,
the value is sensitive but still stored in Terraform state. Protect state with a
remote encrypted backend and locking, such as S3 with DynamoDB or Terraform
Cloud.

## WAF Tuning

The dev example supports `enable_waf_count_mode = true`. Use count mode to
observe managed rule matches before blocking real production traffic.

Recommended managed rule groups in this base:

- `AWSManagedRulesCommonRuleSet`
- `AWSManagedRulesKnownBadInputsRuleSet`
- `AWSManagedRulesSQLiRuleSet`
- `AWSManagedRulesAmazonIpReputationList`

The WAF also includes rate-based rules for global traffic and common auth paths.
Tune limits using CloudWatch and WAF sampled requests.

## HTTPS

Use HTTPS in production. This base supports an HTTPS ALB listener when
`enable_https = true` and `acm_certificate_arn` is provided. It does not create
or validate ACM certificates automatically.

CloudFront redirects viewers to HTTPS. The origin protocol can be `http-only` for
dev or `https-only` when the ALB has a certificate.

## Production Hardening Ideas

- Use Shield Advanced for critical public workloads.
- Use AWS Firewall Manager in larger AWS Organizations.
- Add VPC endpoints for ECR, CloudWatch Logs, Secrets Manager or SSM, and S3 to
  reduce NAT dependency.
- Enable CloudFront and WAF logs to a controlled S3 bucket.
- Use GuardDuty, Security Hub, IAM Access Analyzer, and centralized CloudWatch or
  SIEM forwarding.
- Use a remote Terraform backend with encryption, versioning, and locking.
- Add least-privilege application IAM permissions only when the app needs them.
