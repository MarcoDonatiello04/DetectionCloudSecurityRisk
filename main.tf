provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3  = "http://localhost:4566"
    sts = "http://localhost:4566"
  }
}

# 1. Bucket con ACL pubblico
resource "aws_s3_bucket" "bucket_1_public_acl" {
  bucket = "bucket-1-public-acl"
}

resource "aws_s3_bucket_ownership_controls" "bucket_1_ownership" {
  bucket = aws_s3_bucket.bucket_1_public_acl.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_1_pab" {
  bucket = aws_s3_bucket.bucket_1_public_acl.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "bucket_1_acl" {
  depends_on = [
    aws_s3_bucket_ownership_controls.bucket_1_ownership,
    aws_s3_bucket_public_access_block.bucket_1_pab,
  ]

  bucket = aws_s3_bucket.bucket_1_public_acl.id
  acl    = "public-read"
}

# 2. Bucket con falle di sicurezza nelle policies
resource "aws_s3_bucket" "bucket_2_flawed_policy" {
  bucket = "bucket-2-flawed-policy"
}

resource "aws_s3_bucket_public_access_block" "bucket_2_pab" {
  bucket = aws_s3_bucket.bucket_2_flawed_policy.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "bucket_2_policy" {
  bucket = aws_s3_bucket.bucket_2_flawed_policy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = ["s3:GetObject", "s3:PutObject"]
        Effect    = "Allow"
        Principal = "*"
        Resource = [
          aws_s3_bucket.bucket_2_flawed_policy.arn,
          "${aws_s3_bucket.bucket_2_flawed_policy.arn}/*"
        ]
      },
    ]
  })
}

# 3. Bucket abbastanza configurato bene ma con un problema (manca il Public Access Block)
resource "aws_s3_bucket" "bucket_3_minor_problem" {
  bucket = "bucket-3-minor-problem"
}

resource "aws_s3_bucket_versioning" "bucket_3_versioning" {
  bucket = aws_s3_bucket.bucket_3_minor_problem.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_3_encryption" {
  bucket = aws_s3_bucket.bucket_3_minor_problem.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 4. Bucket configurato perfettamente
resource "aws_s3_bucket" "bucket_4_perfect" {
  bucket = "bucket-4-perfect"
}

resource "aws_s3_bucket_versioning" "bucket_4_versioning" {
  bucket = aws_s3_bucket.bucket_4_perfect.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_4_encryption" {
  bucket = aws_s3_bucket.bucket_4_perfect.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_4_pab" {
  bucket = aws_s3_bucket.bucket_4_perfect.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "bucket_4_policy" {
  bucket = aws_s3_bucket.bucket_4_perfect.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Action    = "s3:*"
        Effect    = "Deny"
        Principal = "*"
        Resource = [
          aws_s3_bucket.bucket_4_perfect.arn,
          "${aws_s3_bucket.bucket_4_perfect.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

# 5. Bucket impenetrabile
resource "aws_s3_bucket" "bucket_5_impenetrable" {
  bucket              = "bucket-5-impenetrable"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "bucket_5_versioning" {
  bucket = aws_s3_bucket.bucket_5_impenetrable.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_5_encryption" {
  bucket = aws_s3_bucket.bucket_5_impenetrable.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_5_pab" {
  bucket = aws_s3_bucket.bucket_5_impenetrable.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "bucket_5_lock" {
  bucket = aws_s3_bucket.bucket_5_impenetrable.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_5_policy" {
  bucket = aws_s3_bucket.bucket_5_impenetrable.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Action    = "s3:*"
        Effect    = "Deny"
        Principal = "*"
        Resource = [
          aws_s3_bucket.bucket_5_impenetrable.arn,
          "${aws_s3_bucket.bucket_5_impenetrable.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnapprovedIPs"
        Action    = "s3:*"
        Effect    = "Deny"
        Principal = "*"
        Resource = [
          aws_s3_bucket.bucket_5_impenetrable.arn,
          "${aws_s3_bucket.bucket_5_impenetrable.arn}/*"
        ]
        Condition = {
          NotIpAddress = {
            "aws:SourceIp" = ["192.168.1.1/32"]
          }
        }
      }
    ]
  })
}

# ====================================================================
# API GATEWAY - SCENARIO 1: Vulnerabile (Ideale per Test Checkov)
# ====================================================================

resource "aws_api_gateway_rest_api" "vulnerable_api" {
  name        = "VulnerableAPI"
  description = "API Gateway senza logging, WAF o autorizzatori"
}

resource "aws_api_gateway_resource" "vulnerable_resource" {
  rest_api_id = aws_api_gateway_rest_api.vulnerable_api.id
  parent_id   = aws_api_gateway_rest_api.vulnerable_api.root_resource_id
  path_part   = "insecure-data"
}

# CKV_AWS_59: Ensure there is no open access to back-end resources through API
# CKV_AWS_73: Ensure API Gateway has X-Ray Tracing enabled
# CKV_AWS_76: Ensure API Gateway has Access Logging enabled
resource "aws_api_gateway_method" "vulnerable_method" {
  rest_api_id   = aws_api_gateway_rest_api.vulnerable_api.id
  resource_id   = aws_api_gateway_resource.vulnerable_resource.id
  http_method   = "ANY" # CKV_AWS_??? : Evitare ANY
  authorization = "NONE" # Vulnerabilità: Nessun Authorizer
  api_key_required = false # Vulnerabilità: Chiave API non richiesta
}

# ====================================================================
# API GATEWAY - SCENARIO 2: Sicuro
# ====================================================================

resource "aws_api_gateway_rest_api" "secure_api" {
  name        = "SecureAPI"
  description = "API Gateway protetto e configurato correttamente"
}

resource "aws_api_gateway_resource" "secure_resource" {
  rest_api_id = aws_api_gateway_rest_api.secure_api.id
  parent_id   = aws_api_gateway_rest_api.secure_api.root_resource_id
  path_part   = "secure-data"
}

# Authorizer simulato (Cognito)
resource "aws_api_gateway_authorizer" "secure_authorizer" {
  name          = "CognitoAuthorizer"
  rest_api_id   = aws_api_gateway_rest_api.secure_api.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = ["arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abcdefghi"]
}

resource "aws_api_gateway_method" "secure_method" {
  rest_api_id   = aws_api_gateway_rest_api.secure_api.id
  resource_id   = aws_api_gateway_resource.secure_resource.id
  http_method   = "GET" # Metodo restrittivo
  authorization = "COGNITO_USER_POOLS" # Sicuro: Usa un Authorizer
  authorizer_id = aws_api_gateway_authorizer.secure_authorizer.id
  api_key_required = true # Sicuro: Richiede API Key
}

resource "aws_api_gateway_stage" "secure_stage" {
  deployment_id = aws_api_gateway_deployment.secure_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.secure_api.id
  stage_name    = "prod"
  
  # CKV_AWS_73: X-Ray attivo
  xray_tracing_enabled = true

  # CKV_AWS_76: Access Logging
  access_log_settings {
    destination_arn = "arn:aws:logs:us-east-1:123456789012:log-group:api-gateway-logs"
    format          = "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\" }"
  }
}

resource "aws_api_gateway_deployment" "secure_deployment" {
  rest_api_id = aws_api_gateway_rest_api.secure_api.id
  
  depends_on = [
    aws_api_gateway_method.secure_method
  ]
}

# CKV_AWS_193: API Gateway v1 associato a un WAFv2
resource "aws_wafv2_web_acl" "secure_waf" {
  name        = "secure-api-waf"
  description = "WAF per API Gateway"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "secureApiWaf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "secure_api_waf_assoc" {
  resource_arn = aws_api_gateway_stage.secure_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.secure_waf.arn
}
