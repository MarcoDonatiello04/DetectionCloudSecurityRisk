# ====================================================================
# INFRASTRUTTURA VULNERABILE: LAMBDA, DYNAMODB, S3, SNS, API GATEWAY
# ====================================================================

# 1. Bucket S3 per gli upload pubblici
resource "aws_s3_bucket" "public_uploads_bucket" {
  bucket = "public-uploads-bucket"
}

resource "aws_s3_bucket_public_access_block" "public_uploads_pab" {
  bucket = aws_s3_bucket.public_uploads_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_uploads_policy" {
  bucket = aws_s3_bucket.public_uploads_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWrite"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.public_uploads_bucket.arn}/*"
      }
    ]
  })
}

# 2. Tabella DynamoDB con configurazioni insicure (no KMS, no point-in-time recovery)
resource "aws_dynamodb_table" "vulnerable_notes_table" {
  name           = "VulnerableNotesTable"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

# 3. SNS Topic con access policy permissiva
resource "aws_sns_topic" "admin_alerts" {
  name = "admin-alerts"
}

resource "aws_sns_topic_policy" "admin_alerts_policy" {
  arn = aws_sns_topic.admin_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.admin_alerts.arn
      }
    ]
  })
}

# 4. IAM Role estremamente permissivo per la Lambda
resource "aws_iam_role" "vulnerable_lambda_role" {
  name = "vulnerable_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "vulnerable_lambda_policy" {
  name = "vulnerable_lambda_policy"
  role = aws_iam_role.vulnerable_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# 5. Lambda Function
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../fixtures/api_vulnerabilities/generic_vulnerabilities"
  output_path = "${path.module}/../../../fixtures/api_vulnerabilities/generic_vulnerabilities.zip"
}

resource "aws_lambda_function" "vulnerable_api_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "vulnerable-api-handler"
  role             = aws_iam_role.vulnerable_lambda_role.arn
  handler          = "app.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"

  environment {
    variables = {
      AWS_ENDPOINT_URL = "http://localstack:4566"
      DEBUG_MODE       = "true"
      SECRET_KEY       = "AKIAIOSFODNN7EXAMPLE" # Hardcoded fake secret
    }
  }
}

# 6. API Gateway per la Lambda
resource "aws_api_gateway_rest_api" "vulnerable_lambda_api" {
  name        = "VulnerableLambdaAPI"
  description = "API Gateway che punta alla Lambda vulnerabile"
}

resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  parent_id   = aws_api_gateway_rest_api.vulnerable_lambda_api.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  resource_id = aws_api_gateway_method.proxy.resource_id
  http_method = aws_api_gateway_method.proxy.http_method

  type             = "AWS_PROXY"
  uri              = aws_lambda_function.vulnerable_api_lambda.invoke_arn
  integration_http_method = "POST"
}

# Configurazione root "/"
resource "aws_api_gateway_method" "proxy_root" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  resource_id   = aws_api_gateway_rest_api.vulnerable_lambda_api.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "lambda_root" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  resource_id = aws_api_gateway_method.proxy_root.resource_id
  http_method = aws_api_gateway_method.proxy_root.http_method

  type             = "AWS_PROXY"
  uri              = aws_lambda_function.vulnerable_api_lambda.invoke_arn
  integration_http_method = "POST"
}

resource "aws_api_gateway_deployment" "vulnerable_api_deployment" {
  depends_on = [
    aws_api_gateway_integration.lambda,
    aws_api_gateway_integration.lambda_root,
  ]

  rest_api_id = aws_api_gateway_rest_api.vulnerable_lambda_api.id
}

resource "aws_api_gateway_stage" "vulnerable_api_stage" {
  deployment_id = aws_api_gateway_deployment.vulnerable_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_lambda_api.id
  stage_name    = "dev"
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.vulnerable_api_lambda.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_api_gateway_rest_api.vulnerable_lambda_api.execution_arn}/*/*"
}

output "vulnerable_api_base_url" {
  value = aws_api_gateway_stage.vulnerable_api_stage.invoke_url
}
