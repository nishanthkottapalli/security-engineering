module "security_foundation" {
  source = "./modules/security_foundation"

  project_name                 = var.project_name
  environment                  = var.environment
  notification_email           = var.notification_email
  enable_inspector             = var.enable_inspector
  vpc_id                       = var.vpc_id
  log_retention_days           = var.log_retention_days
  s3_noncurrent_retention_days = var.s3_noncurrent_retention_days
  force_destroy                = var.force_destroy
  tags                         = var.tags
}
