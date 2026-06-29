# Parry AWS Terraform Reference

This Terraform stack is a deployable reference architecture for running a Parry
demo API on AWS behind CloudFront, AWS WAF, an Application Load Balancer, ECS
Fargate, and ElastiCache Redis.

It is intentionally a starting point, not a production platform. It does not
create Route 53 records, ACM certificates, multi-account foundations, CI/CD
deployment, Shield Advanced, or blue/green release automation.

## Architecture

```text
Internet
  -> CloudFront
  -> AWS WAF Web ACL
  -> public Application Load Balancer
  -> ECS Fargate tasks in private subnets
  -> ElastiCache Redis in private subnets
  -> CloudWatch Logs and Metrics
```

Parry remains an application-layer control inside the Express application. AWS
edge and infrastructure services handle edge filtering, resiliency, and
volumetric DDoS mitigation.

## Layout

```text
infra/terraform/
  environments/dev/      Runnable dev environment
  modules/               Small reusable modules
  main.tf                Composes the modules
  variables.tf
  outputs.tf
  versions.tf
```

## Usage

```bash
cd infra/terraform/environments/dev
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your AWS account id, region, and pushed container
image URI. Do not commit `terraform.tfvars`.

```bash
terraform init
terraform plan
terraform apply
```

Destroy demo resources when finished:

```bash
terraform destroy
```

## Container Image

Terraform does not build or push the app image. Build the image separately and
pass the immutable ECR image URI through `container_image`.

The container is expected to:

- listen on `PORT`, default `3000`;
- expose `GET /health` returning `2xx`;
- read Redis configuration from `REDIS_URL` and optional `REDIS_AUTH_TOKEN`;
- protect any Admin API route with strong application-level authentication.

## Cost Controls

The dev example sets `enable_nat_gateway = false` to avoid surprise NAT Gateway
cost. If ECS tasks need outbound internet from private subnets, enable NAT or add
VPC endpoints for ECR, CloudWatch Logs, Secrets Manager or SSM, and S3.

CloudFront, WAF, ALB, Fargate, ElastiCache, and CloudWatch can all generate cost
when applied. Review `docs/aws-cost-notes.md` before running `terraform apply`.

## Security Notes

No secrets are committed. Pass existing Secrets Manager or SSM parameter ARNs for
`PARRY_ADMIN_TOKEN` and optional Redis auth token exposure to the ECS task.

If `redis_auth_token` is used to configure ElastiCache AUTH, protect Terraform
state with a remote encrypted backend and locking, such as S3 with DynamoDB or
Terraform Cloud.

See `docs/aws-security-notes.md` for the full security model.
