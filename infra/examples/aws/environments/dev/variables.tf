variable "project_name" {
  description = "Short project name used for resource naming."
  type        = string
  default     = "parry"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "Primary AWS region for regional resources."
  type        = string
  default     = "us-east-1"
}

variable "container_image" {
  description = "Container image URI for the Parry demo API."
  type        = string
}

variable "app_port" {
  description = "Port exposed by the container."
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
  description = "Create NAT Gateways for private subnet egress."
  type        = bool
  default     = false
}

variable "enable_vpc_endpoints" {
  description = "Create VPC endpoints for private ECS access to ECR, logs, secrets, SSM, and S3."
  type        = bool
  default     = false
}

variable "enable_cloudfront" {
  description = "Create CloudFront and CloudFront-scoped WAF."
  type        = bool
  default     = true
}

variable "enable_https" {
  description = "Enable ALB HTTPS listener."
  type        = bool
  default     = false
}

variable "acm_certificate_arn" {
  description = "Optional ACM certificate ARN."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Optional CloudFront alternate domain name."
  type        = string
  default     = ""
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type."
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_num_cache_clusters" {
  description = "Number of Redis cache clusters."
  type        = number
  default     = 1
}

variable "redis_auth_token_secret_arn" {
  description = "Optional secret ARN exposed to the ECS task as REDIS_AUTH_TOKEN."
  type        = string
  default     = ""
}

variable "redis_auth_token" {
  description = "Optional Redis auth token for ElastiCache. Stored in Terraform state if used."
  type        = string
  default     = null
  sensitive   = true
}

variable "parry_admin_token_secret_arn" {
  description = "Optional secret ARN exposed to the ECS task as PARRY_ADMIN_TOKEN."
  type        = string
  default     = ""
}

variable "enable_waf_count_mode" {
  description = "Count WAF matches instead of blocking while tuning."
  type        = bool
  default     = true
}

variable "waf_rate_limit" {
  description = "Global WAF rate limit per IP per 5-minute window."
  type        = number
  default     = 2000
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
