# AWS Infrastructure Reference

This document describes the Terraform reference architecture under
`infra/terraform`. It is designed to demonstrate a realistic deployment shape for
a Parry-protected Express API without adding AWS credentials, secrets, or deploy
automation to the repository.

## Architecture

```text
Client
  -> CloudFront
  -> AWS WAFv2 Web ACL
  -> public Application Load Balancer
  -> ECS Fargate service in private subnets
  -> ElastiCache Redis in private subnets
  -> CloudWatch Logs and Metrics
```

CloudFront, AWS WAF, Shield, the ALB, and resilient AWS architecture protect the
edge and infrastructure. Parry runs inside the Node.js application and helps with
application-layer controls: distributed rate limiting through RedisStore, brute
force protection, payload abuse detection, request guards, and threat events.

This stack does not claim complete volumetric DDoS protection.

## Prerequisites

- Terraform `>= 1.5`
- AWS CLI configured outside this repository
- Docker or another image build tool
- An AWS account with permissions to create VPC, ECR, ECS, ALB, CloudFront, WAF,
  ElastiCache, CloudWatch, and IAM resources
- A containerized Demo API that listens on `PORT` and responds to `GET /health`

## Build and Push the Image

Create the ECR repository first or use the repository created by Terraform after
an initial apply. A typical manual flow is:

```bash
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=123456789012
IMAGE_TAG=2026-06-29
ECR_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/parry-dev-demo-api"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker build -t parry-demo-api:"$IMAGE_TAG" .
docker tag parry-demo-api:"$IMAGE_TAG" "$ECR_REPO:$IMAGE_TAG"
docker push "$ECR_REPO:$IMAGE_TAG"
```

Then set:

```hcl
container_image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/parry-dev-demo-api:2026-06-29"
```

Terraform intentionally does not build images.

## Run Terraform

```bash
cd infra/terraform/environments/dev
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`. Do not commit it.

```bash
terraform init
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
```

Useful outputs:

- `ecr_repository_url`
- `alb_dns_name`
- `cloudfront_domain_name`
- `ecs_cluster_name`
- `ecs_service_name`
- `redis_endpoint`
- `waf_web_acl_arn`
- `cloudwatch_log_group_name`

## Test the Deployment

If CloudFront is enabled:

```bash
curl -i "https://$(terraform output -raw cloudfront_domain_name)/health"
```

If testing the ALB directly in dev:

```bash
curl -i "http://$(terraform output -raw alb_dns_name)/health"
```

View ECS logs:

```bash
aws logs tail "$(terraform output -raw cloudwatch_log_group_name)" \
  --region us-east-1 \
  --follow
```

## Secrets

Do not place secrets in committed files. Use existing AWS Secrets Manager secrets
or SSM parameters and pass their ARNs:

```hcl
parry_admin_token_secret_arn = "arn:aws:secretsmanager:..."
redis_auth_token_secret_arn  = "arn:aws:secretsmanager:..."
```

Redis AUTH is disabled by default for the small dev example because Redis is
private. In production, use TLS/in-transit encryption, AUTH, and a remote
encrypted Terraform backend with locking. If you set `redis_auth_token`,
Terraform must send the value to ElastiCache and the value will be stored in
Terraform state. Do not put real tokens in committed tfvars.

## Networking Notes

ECS tasks and Redis are placed in private subnets. The ALB is placed in public
subnets. Redis accepts traffic only from the ECS security group.

The dev example defaults to `enable_nat_gateway = false` and
`enable_vpc_endpoints = false`. With no NAT and no VPC endpoints, private tasks
may not be able to pull images, read secrets, or publish logs. For private ECS
without NAT, set `enable_vpc_endpoints = true` to create endpoints for ECR,
CloudWatch Logs, Secrets Manager, SSM, and S3.

## Cleanup

Demo resources cost money. Destroy the environment when finished:

```bash
terraform destroy
```

## Not Included

This initial base does not implement multi-account production foundations,
automatic ACM certificate validation, Route 53 records, blue/green deployments,
complex autoscaling, EKS, relational databases, Shield Advanced enrollment,
SIEM integration, or a complete CI/CD pipeline.
