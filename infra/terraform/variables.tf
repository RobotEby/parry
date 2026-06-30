variable "project_name" {
  description = "Short project name used for resource naming."
  type        = string
}

variable "environment" {
  description = "Deployment environment name, for example dev or prod."
  type        = string
}

variable "aws_region" {
  description = "Primary AWS region for regional resources."
  type        = string
}

variable "container_image" {
  description = "Container image URI for the Parry demo API. Build and push this outside Terraform."
  type        = string
}

variable "app_port" {
  description = "Port exposed by the container and target group."
  type        = number
  default     = 3000
}

variable "desired_count" {
  description = "Desired ECS task count."
  type        = number
  default     = 1
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 256
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 512
}

variable "enable_nat_gateway" {
  description = "Whether to create NAT Gateways for private subnets. Disabled by default to avoid surprise cost."
  type        = bool
  default     = false
}

variable "enable_vpc_endpoints" {
  description = "Whether to create private VPC endpoints for ECR, CloudWatch Logs, Secrets Manager, SSM, and S3. Disabled by default to avoid surprise cost."
  type        = bool
  default     = false
}

variable "enable_cloudfront" {
  description = "Whether to create CloudFront and CloudFront-scoped WAF."
  type        = bool
  default     = true
}

variable "enable_https" {
  description = "Whether the ALB should expose HTTPS using acm_certificate_arn."
  type        = bool
  default     = false
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN. Use a regional cert for ALB HTTPS and a us-east-1 cert for CloudFront aliases."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Optional CloudFront alternate domain name. Route 53 records are not created by this stack."
  type        = string
  default     = ""
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type for the demo environment."
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_num_cache_clusters" {
  description = "Number of Redis cache clusters in the replication group."
  type        = number
  default     = 1
}

variable "redis_auth_token_secret_arn" {
  description = "Optional Secrets Manager or SSM parameter ARN exposed to the ECS task as REDIS_AUTH_TOKEN."
  type        = string
  default     = ""
}

variable "redis_auth_token" {
  description = "Optional Redis auth token for ElastiCache. This is sensitive and will be stored in Terraform state if used."
  type        = string
  default     = null
  sensitive   = true
}

variable "parry_admin_token_secret_arn" {
  description = "Optional Secrets Manager or SSM parameter ARN exposed to the ECS task as PARRY_ADMIN_TOKEN."
  type        = string
  default     = ""
}

variable "enable_waf_count_mode" {
  description = "When true, WAF rules count sampled traffic instead of blocking. Recommended while tuning."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Global WAF rate-based limit per 5-minute window."
  type        = number
  default     = 2000
}

variable "allowed_admin_cidr" {
  description = "Documented CIDR for admin access policy examples. The Admin API is not exposed by a separate SG in this stack."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags applied to supported resources."
  type        = map(string)
  default     = {}
}
