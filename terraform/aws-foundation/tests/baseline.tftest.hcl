mock_provider "aws" {

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "ap-south-1"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
}

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

  #
  # This output is fully known during plan.
  #
  assert {
    condition = module.security_foundation.cloudtrail_name == "sec-cap-lab-test"

    error_message = "CloudTrail name should use the project/environment prefix."
  }

  #
  # Verify the outputs exist rather than attempting to evaluate unknown values.
  #
  assert {
    condition = contains(
      keys(module.security_foundation),
      "evidence_bucket_name"
    )

    error_message = "Module should expose evidence_bucket_name."
  }

  assert {
    condition = contains(
      keys(module.security_foundation),
      "guardduty_detector_id"
    )

    error_message = "Module should expose guardduty_detector_id."
  }

  assert {
    condition = contains(
      keys(module.security_foundation),
      "securityhub_account_arn"
    )

    error_message = "Module should expose securityhub_account_arn."
  }

  assert {
    condition = contains(
      keys(module.security_foundation),
      "alert_topic_arn"
    )

    error_message = "Module should expose alert_topic_arn."
  }
}
