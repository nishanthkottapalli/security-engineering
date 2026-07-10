output "security_foundation" {
  description = "Identifiers used by evidence collection and operations."
  value = {
    cloudtrail_name          = module.security_foundation.cloudtrail_name
    evidence_bucket_name    = module.security_foundation.evidence_bucket_name
    audit_log_group_name    = module.security_foundation.audit_log_group_name
    guardduty_detector_id   = module.security_foundation.guardduty_detector_id
    securityhub_account_arn = module.security_foundation.securityhub_account_arn
    alert_topic_arn         = module.security_foundation.alert_topic_arn
  }
}
