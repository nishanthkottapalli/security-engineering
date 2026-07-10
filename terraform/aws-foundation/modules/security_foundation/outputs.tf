output "cloudtrail_name" {
  description = "Name of the multi-Region CloudTrail trail."
  value       = aws_cloudtrail.audit.name
}

output "evidence_bucket_name" {
  description = "Name of the encrypted security evidence bucket."
  value       = aws_s3_bucket.evidence.id
}

output "audit_log_group_name" {
  description = "CloudWatch log group receiving CloudTrail events."
  value       = aws_cloudwatch_log_group.audit.name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector identifier."
  value       = aws_guardduty_detector.this.id
}

output "securityhub_account_arn" {
  description = "Security Hub account ARN."
  value       = aws_securityhub_account.this.arn
}

output "alert_topic_arn" {
  description = "SNS topic ARN for high-severity security alerts."
  value       = aws_sns_topic.security_alerts.arn
}
