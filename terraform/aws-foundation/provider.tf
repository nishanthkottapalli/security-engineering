provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(
      {
        ManagedBy   = "Terraform"
        Project     = var.project_name
        Environment = var.environment
        Repository  = "detection-engineering"
      },
      var.tags
    )
  }
}
