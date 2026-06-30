# GitHub OIDC for AWS

Use GitHub OpenID Connect (OIDC) to let GitHub Actions assume an AWS IAM role
without storing long-lived AWS access keys in GitHub.

Do not create static AWS access keys for this repository.

## Repository Variables

Configure these GitHub repository or environment variables:

- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`
- `ECR_REPOSITORY`

Optional:

- `CONTAINER_IMAGE`
- `PROJECT_NAME`
- `TERRAFORM_ENVIRONMENT`

Use GitHub Secrets only for application-specific tokens if a future workflow
needs them. The current workflows do not require AWS static secrets.

## Trust Policy Example

Create an IAM OIDC provider for `token.actions.githubusercontent.com`, then
create an IAM role with a trust policy like this. Replace owner, repository, and
branch names.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:OWNER/REPO:ref:refs/heads/main",
            "repo:OWNER/REPO:ref:refs/heads/master",
            "repo:OWNER/REPO:pull_request"
          ]
        }
      }
    }
  ]
}
```

For stricter production use, separate roles by workflow and environment. For
example, allow pull request plan only from trusted internal branches, and use a
different role for ECR pushes.

## ECR Push Permissions

The Docker workflow needs enough permission to authenticate and push to one ECR
repository. Scope the resource to the target repository ARN.

Actions typically needed:

- `ecr:GetAuthorizationToken`
- `ecr:BatchCheckLayerAvailability`
- `ecr:InitiateLayerUpload`
- `ecr:UploadLayerPart`
- `ecr:CompleteLayerUpload`
- `ecr:PutImage`
- `ecr:DescribeRepositories`

`ecr:GetAuthorizationToken` commonly requires resource `*`; keep all other ECR
actions scoped to the repository when possible.

## Terraform Plan Permissions

Terraform plan needs read and planning permissions for resources in
`infra/terraform`: VPC, EC2 networking, ECR, ECS, IAM, ALB, CloudFront, WAFv2,
ElastiCache, and CloudWatch.

The exact IAM policy should be environment-specific. Start narrow and expand
only as Terraform reports missing read permissions. Avoid `AdministratorAccess`.

For production, use:

- a remote Terraform backend with encryption and locking;
- separate roles for plan and apply;
- manual approval before apply;
- least privilege scoped to project resources when practical.

## Fork Safety

The workflows do not run AWS-authenticated jobs for pull requests from forks.
Static CI and Docker build still run, but OIDC role assumption is skipped.

This prevents untrusted fork code from receiving AWS identity tokens for your
account.
