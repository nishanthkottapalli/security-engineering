variable "project_name" {
  description = "Short project identifier used in resource names."
  type        = string
}

variable "environment" {
  description = "Environment name such as lab, dev, staging, or production."
  type        = string
}

variable "notification_email" {
  description = "Optional email subscription for high-severity GuardDuty alerts."
  type        = string
  default     = null
  nullable    = true
}

variable "enable_inspector" {
  description = "Enable Amazon Inspector v2 for EC2, ECR, and Lambda workloads."
  type        = bool
  default     = true
}

variable "vpc_id" {
  description = "Optional VPC ID for VPC Flow Logs."
  type        = string
  default     = null
  nullable    = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period."
  type        = number
  default     = 365
}

variable "s3_noncurrent_retention_days" {
  description = "Days to retain non-current evidence object versions."
  type        = number
  default     = 90
}

variable "force_destroy" {
  description = "Allow destruction of a non-empty evidence bucket in disposable labs."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
