output "ecr_repository_url" {
  description = "ECR repository URL."
  value       = module.parry.ecr_repository_url
}

output "alb_dns_name" {
  description = "Application Load Balancer DNS name."
  value       = module.parry.alb_dns_name
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name."
  value       = module.parry.cloudfront_domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution id."
  value       = module.parry.cloudfront_distribution_id
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.parry.ecs_cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.parry.ecs_service_name
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint."
  value       = module.parry.redis_endpoint
}

output "waf_web_acl_arn" {
  description = "AWS WAF Web ACL ARN."
  value       = module.parry.waf_web_acl_arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name."
  value       = module.parry.cloudwatch_log_group_name
}

output "vpc_endpoint_ids" {
  description = "VPC endpoint ids when enabled."
  value       = module.parry.vpc_endpoint_ids
}
