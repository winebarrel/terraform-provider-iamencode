terraform {
  required_providers {
    iamencode = {
      source = "winebarrel/iamencode"
    }
  }
}

# policy_strict catches Action typos that the schema alone cannot. Replace
# "GetObject" with e.g. "Frobnicate" to see the strict check reject it:
#
#   Error: invalid IAM policy:
#     Statement[0]: unknown action "Frobnicate" for service "s3"
output "bucket_policy" {
  value = provider::iamencode::policy_strict({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
