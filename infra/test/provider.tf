terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.90.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Default tags for all resources
  default_tags {
    tags = merge(
      var.tags,
      {
        Environment = var.environment
        Terraform   = "true"
      }
    )
  }
}




