variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 14
}

variable "enable_alarms" {
  description = "Whether to create baseline CloudWatch alarms."
  type        = bool
  default     = false
}

variable "ecs_cluster_name" {
  description = "ECS cluster name for optional alarms."
  type        = string
  default     = ""
}

variable "ecs_service_name" {
  description = "ECS service name for optional alarms."
  type        = string
  default     = ""
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix for optional alarms."
  type        = string
  default     = ""
}

variable "target_group_arn_suffix" {
  description = "Target group ARN suffix for optional alarms."
  type        = string
  default     = ""
}

variable "redis_replication_group_id" {
  description = "Redis replication group id for optional alarms."
  type        = string
  default     = ""
}

variable "waf_web_acl_name" {
  description = "WAF Web ACL name for optional alarms."
  type        = string
  default     = ""
}

variable "sns_topic_arn" {
  description = "Optional SNS topic ARN for alarm actions."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
