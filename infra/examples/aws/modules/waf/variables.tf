variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "enable_count_mode" {
  description = "When true, rules count instead of block."
  type        = bool
}

variable "rate_limit" {
  description = "Global WAF rate limit per IP per 5-minute window."
  type        = number
}

variable "auth_rate_limit" {
  description = "Auth-path WAF rate limit per IP per 5-minute window."
  type        = number
  default     = 500
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
