variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "aws_region" {
  description = "AWS region used by the awslogs driver."
  type        = string
}

variable "container_image" {
  description = "Container image URI."
  type        = string
}

variable "app_port" {
  description = "Application container port."
  type        = number
}

variable "desired_count" {
  description = "Desired service task count."
  type        = number
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
}

variable "private_subnet_ids" {
  description = "Private subnet ids for ECS tasks."
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "ECS service security group id."
  type        = string
}

variable "target_group_arn" {
  description = "ALB target group ARN."
  type        = string
}

variable "cloudwatch_log_group_name" {
  description = "CloudWatch log group name."
  type        = string
}

variable "redis_endpoint" {
  description = "Redis primary endpoint address."
  type        = string
}

variable "parry_admin_token_secret_arn" {
  description = "Optional secret ARN for PARRY_ADMIN_TOKEN."
  type        = string
  default     = ""
}

variable "redis_auth_token_secret_arn" {
  description = "Optional secret ARN for REDIS_AUTH_TOKEN."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
