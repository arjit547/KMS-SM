# main.tf
module "iam" {
  source = "./modules/iam_module"
}

# Create an S3 bucket
resource "aws_s3_bucket" "report_bucket" {
  bucket = var.s3_bucket_name
  acl    = "private"

  versioning {
    enabled = true
  }
}

# Lambda function for KMS report
resource "aws_lambda_function" "kms_report_lambda" {
  function_name = "kms_report_lambda"
  handler       = "lambda_function_kms.lambda_handler"
  runtime       = "python3.8"
  role          = module.iam.lambda_execution_role_arn

  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.report_bucket.bucket
      S3_FOLDER = "kms_reports"
    }
  }

  # Filename argument to specify the Lambda function code
  filename = "${var.lambda_zip_path_kms}lambda_function_kms.zip"
}

# Lambda function for Secrets Manager report
resource "aws_lambda_function" "secrets_manager_report_lambda" {
  function_name = "secrets_manager_report_lambda"
  handler       = "lambda_function_secrets_manager.lambda_handler"
  runtime       = "python3.8"
  role          = module.iam.lambda_execution_role_arn

  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.report_bucket.bucket
      S3_FOLDER = "secrets_manager_reports"
    }
  }

  # Filename argument to specify the Lambda function code
  filename = "${var.lambda_zip_path_secrets_manager}lambda_function_secrets_manager.zip"
}
