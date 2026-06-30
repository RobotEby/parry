variable "name_prefix" {
  description = "Resource name prefix."
  type        = string
}

variable "image_tag_mutability" {
  description = "ECR tag mutability."
  type        = string
  default     = "IMMUTABLE"
}

variable "scan_on_push" {
  description = "Whether to enable image scanning on push."
  type        = bool
  default     = true
}

variable "lifecycle_keep_last" {
  description = "Number of tagged images to keep."
  type        = number
  default     = 20
}

variable "tags" {
  description = "Tags applied to resources."
  type        = map(string)
  default     = {}
}
