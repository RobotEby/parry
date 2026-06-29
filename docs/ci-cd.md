# CI/CD

This repository uses GitHub Actions for CI, Docker image builds, optional ECR
pushes, and Terraform validation/plan. The workflows are intentionally
conservative for a public repository: no static AWS keys, no automatic
`terraform apply`, and no automatic ECS deployment.

## Workflows

| Workflow                               | Purpose                                                               | Pull requests                                                       | Main/master or manual                                    |
| -------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------- |
| `.github/workflows/ci.yml`             | Node.js tests, payload fixtures, package checks, secret sanity checks | Runs all safe checks                                                | Runs all safe checks                                     |
| `.github/workflows/docker.yml`         | Build the demo API Docker image and optionally push to ECR            | Builds only, no AWS auth                                            | Pushes to ECR when AWS variables are configured          |
| `.github/workflows/terraform-plan.yml` | Terraform fmt, validate, and optional plan                            | fmt/validate always; plan only for non-fork PRs with OIDC variables | fmt/validate and plan when OIDC variables are configured |

`terraform apply` is not automated. Apply infrastructure only after human review
of a plan from a trusted environment.

## Required GitHub Variables

Configure these as repository or environment variables:

- `AWS_REGION`: AWS region, for example `us-east-1`.
- `AWS_ROLE_TO_ASSUME`: IAM role ARN trusted by GitHub OIDC.
- `ECR_REPOSITORY`: ECR repository name for Docker pushes.

Optional variables:

- `CONTAINER_IMAGE`: image URI used by Terraform plan.
- `PROJECT_NAME`: Terraform project name, default `parry`.
- `TERRAFORM_ENVIRONMENT`: Terraform environment name, default `dev`.

Do not configure long-lived AWS access keys for GitHub Actions. Use OIDC.

## Pull Request Behavior

Pull requests run Node.js tests, payload regression, package checks, security
sanity checks, Docker build, Terraform fmt, Terraform init with
`-backend=false`, and Terraform validate.

Pull requests from forks do not run AWS-authenticated jobs. This avoids exposing
OIDC trust or repository configuration to untrusted code.

## Main and Manual Behavior

On `main` or `master`, the Docker workflow pushes tags to ECR when variables are
configured:

- `${GITHUB_SHA}`
- `latest`

Manual Docker runs behave the same, except `latest` is only pushed when the run
is on `main` or `master`.

Terraform plan runs on main/manual when OIDC variables are configured. It uploads
the text plan as an artifact. It does not apply changes.

## Local Commands

```bash
npm ci
npm test
npm run test:fixtures
npm run test:payload-regression
npm pack --dry-run
docker build -f docker/demo-api/Dockerfile -t parry-demo-api .
terraform fmt -check -recursive infra/terraform
terraform -chdir=infra/terraform/environments/dev init -backend=false
terraform -chdir=infra/terraform/environments/dev validate
terraform -chdir=infra/terraform/environments/dev plan
```

For a real Terraform plan, provide a valid `container_image`, AWS credentials
through OIDC or your local AWS profile, and any required environment variables.

## Manual Infrastructure Apply

Use a reviewed plan and run apply outside CI:

```bash
cd infra/terraform/environments/dev
terraform init
terraform plan
terraform apply
```

Destroy demo infrastructure when it is not in use:

```bash
terraform destroy
```

## Docker Demo API

The Docker workflow builds `docker/demo-api/Dockerfile`. The image is a small
Express app that imports the repository-local Parry source, exposes `/health`,
and can use RedisStore when `PARRY_STORE=redis` and `REDIS_URL` are provided.

The demo image is not a new public runtime API for the package.

## Cost and Safety

ECR storage, ECS Fargate, ALB, CloudFront, WAF, ElastiCache, CloudWatch, NAT
Gateway, and Terraform-created resources can generate cost. Keep the dev
environment small, review plans, and destroy demo resources after testing.

The CI does not run payloads against external services and does not use shell,
database, or network execution for payload fixtures.
