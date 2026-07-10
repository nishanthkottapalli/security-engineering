mock_provider "aws" {}

run "foundational_baseline_plans_without_credentials" {
  command = plan

  variables {
    aws_region         = "ap-south-1"
    project_name       = "sec-cap-lab"
    environment        = "test"
    enable_inspector   = false
    force_destroy      = true
    notification_email = null
  }

  assert {
    condition     = module.security_foundation.cloudtrail_name == "sec-cap-lab-test"
    error_message = "CloudTrail must use the predictable project/environment prefix."
  }

  assert {
    condition     = can(module.security_foundation.evidence_bucket_name)
    error_message = "An encrypted evidence bucket must be planned."
  }

  assert {
    condition     = can(module.security_foundation.guardduty_detector_id)
    error_message = "GuardDuty must be enabled by the baseline."
  }
}
