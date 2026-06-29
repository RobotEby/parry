output "ecr_repository_url" {
  description = "ECR repository URL for the Parry demo API image."
  value       = module.ecr.repository_url
}

output "alb_dns_name" {
  description = "Public DNS name of the Application Load Balancer."
  value       = module.alb.alb_dns_name
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name when enabled."
  value       = var.enable_cloudfront ? module.cloudfront[0].domain_name : null
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution id when enabled."
  value       = var.enable_cloudfront ? module.cloudfront[0].distribution_id : null
}

output "ecs_cluster_name" {
  description = "ECS cluster name."
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.ecs.service_name
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint address."
  value       = module.redis.primary_endpoint_address
}

output "waf_web_acl_arn" {
  description = "CloudFront-scoped AWS WAF Web ACL ARN when enabled."
  value       = var.enable_cloudfront ? module.waf[0].web_acl_arn : null
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group used by ECS tasks."
  value       = module.observability.log_group_name
}
