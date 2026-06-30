# AWS Cost Notes

This Terraform base creates real AWS resources when applied. Review expected
costs before running it in any account.

## Cost Drivers

- NAT Gateway can generate meaningful hourly and data processing cost. The dev
  example sets `enable_nat_gateway = false` by default.
- VPC endpoints also generate hourly and data processing cost. The dev example
  sets `enable_vpc_endpoints = false` by default; enable them only when private
  ECS tasks need AWS API access without NAT.
- Application Load Balancer charges hourly and by LCU usage.
- CloudFront charges for data transfer and requests.
- AWS WAF charges for Web ACLs, rules, and inspected requests.
- ECS Fargate charges by vCPU and memory while tasks run.
- ElastiCache Redis runs continuously and charges by node type and count.
- CloudWatch Logs charges for ingestion and retention.
- CloudWatch alarms may add cost if enabled.

## Dev Defaults

The dev environment is intentionally small:

- `desired_count = 1`
- `cpu = 256`
- `memory = 512`
- `redis_node_type = "cache.t4g.micro"`
- `redis_num_cache_clusters = 1`
- `enable_nat_gateway = false`
- `enable_vpc_endpoints = false`
- optional alarms disabled

These defaults reduce cost, but they are still paid AWS resources after
`terraform apply`.

## Cleanup

Destroy demo resources when not actively testing:

```bash
cd infra/terraform/environments/dev
terraform destroy
```

Check the AWS console afterward for resources that can outlive failed or partial
deployments, especially CloudWatch log groups, ECR images, load balancers, and
ElastiCache clusters.

## Production Cost Planning

Production environments should budget for multiple NAT Gateways or VPC
endpoints, multiple ECS tasks, larger Redis nodes or replicas, CloudFront/WAF log
delivery, alerting, and potentially Shield Advanced for critical workloads.
