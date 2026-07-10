variable "aws_region" {
  description = "AWS region in which regional security services are enabled."
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Short project identifier used in names and tags."
  type        = string
  default     = "security-capabilities-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.project_name))
    error_message = "project_name must contain 3-30 lowercase letters, digits or hyphens."
  }
}

variable "environment" {
  description = "Environment label."
  type        = string
  default     = "lab"
}

variable "notification_email" {
  description = "Optional email subscription for high-severity GuardDuty findings. Confirmation is required."
  type        = string
  default     = null
  nullable    = true
}

variable "enable_inspector" {
  description = "Enable Inspector v2 for EC2, ECR and Lambda in the target account/region."
  type        = bool
  default     = true
}

variable "vpc_id" {
  description = "Optional VPC ID for CloudWatch VPC Flow Logs."
  type        = string
  default     = null
  nullable    = true
}

variable "log_retention_days" {
  description = "CloudWatch retention period for audit and flow logs."
  type        = number
  default     = 365
}

variable "s3_noncurrent_retention_days" {
  description = "Retention for non-current log object versions."
  type        = number
  default     = 90
}

variable "force_destroy" {
  description = "Lab-only switch that permits destruction of non-empty evidence buckets. Keep false outside disposable accounts."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags."
  type        = map(string)
  default     = {}
}
