terraform {
  required_providers {
    iamencode = {
      source = "winebarrel/iamencode"
    }
  }
}

# policy_strict catches mistakes the schema alone cannot. Three examples:
#
#   - Replace "GetObject" with e.g. "Frobnicate":
#       Statement[1]: unknown action "Frobnicate" for service "s3"
#
#   - Move "s3:prefix" under the s3:GetObject statement:
#       Statement[1]: condition key "s3:prefix" (under StringEquals)
#         is not valid for the statement's actions
#
#   - Use a bucket-only ARN on the object-reading statement:
#       Statement[1]: resource "arn:aws:s3:::my-bucket" does not match
#         any ARN format for the statement's actions
output "bucket_policy" {
  value = provider::iamencode::policy_strict({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListAllowedPrefix"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::my-bucket"
        Condition = {
          StringEquals = { "s3:prefix" = "logs/" }
        }
      },
      {
        Sid      = "ReadObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::my-bucket/logs/*"
      },
    ]
  })
}
