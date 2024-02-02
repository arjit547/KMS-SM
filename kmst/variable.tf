
variable "aws_region" {
  description = "AWS region where resources will be created"
  type        = string
  default     = "us-east-1"
}

variable "lambda_zip_path_kms" {
  description = "Path to the Lambda function ZIP file for KMS"
  type        = string
  default     = "C:/Users/chauhanarjit/Desktop/kmst/"
}

variable "lambda_zip_path_secrets_manager" {
  description = "Path to the Lambda function ZIP file for Secrets Manager"
  type        = string
  default     = "C:/Users/chauhanarjit/Desktop/kmst/"
}

variable "s3_bucket_name" {
  description = "Name for the S3 bucket"
  type        = string
  default     = "kmssm" 
}
