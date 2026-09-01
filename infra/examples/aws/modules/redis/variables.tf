variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet ids for ElastiCache."
  type        = list(string)
}

variable "redis_security_group_id" {
  description = "Redis security group id."
  type        = string
}

variable "node_type" {
  description = "ElastiCache node type."
  type        = string
}

variable "num_cache_clusters" {
  description = "Number of cache clusters."
  type        = number
}

variable "auth_token" {
  description = "Optional Redis auth token. Stored in Terraform state if used."
  type        = string
  default     = null
  sensitive   = true
}

variable "snapshot_retention_limit" {
  description = "Number of daily Redis snapshots to retain."
  type        = number
  default     = 1
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
