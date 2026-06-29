variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "vpc_id" {
  description = "VPC id."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block."
  type        = string
}

variable "app_port" {
  description = "Application container port."
  type        = number
}

variable "enable_https" {
  description = "Whether the ALB exposes HTTPS."
  type        = bool
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
