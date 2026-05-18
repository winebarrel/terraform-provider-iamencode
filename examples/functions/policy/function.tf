terraform {
  required_providers {
    iamencode = {
      source = "winebarrel/iamencode"
    }
  }
}

output "bucket_policy" {
  value = provider::iamencode::policy({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "arn:aws:s3:::my-bucket/*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
          StringEquals = {
            "aws:PrincipalTag/env" = ["prod", "staging"]
          }
        }
      }
    ]
  })
}
