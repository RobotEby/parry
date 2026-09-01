variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
