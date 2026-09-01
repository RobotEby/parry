variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "origin_domain_name" {
  description = "ALB DNS name used as CloudFront origin."
  type        = string
}

variable "web_acl_arn" {
  description = "WAF Web ACL ARN."
  type        = string
}

variable "domain_name" {
  description = "Optional CloudFront alternate domain name."
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = "Optional us-east-1 ACM certificate ARN for CloudFront aliases."
  type        = string
  default     = ""
}

variable "origin_protocol_policy" {
  description = "Protocol policy used between CloudFront and ALB."
  type        = string
  default     = "http-only"
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
