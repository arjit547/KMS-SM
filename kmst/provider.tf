terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.0, < 4.0"
    }
  }
  required_version = ">= 1.2.9, < 2.0.0"
}

provider "aws" {
  region = var.aws_region
}