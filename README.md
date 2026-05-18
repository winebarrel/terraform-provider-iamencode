# terraform-provider-iamencode

Terraform provider with a user-defined function that validates an IAM policy document (passed as a Terraform object) against an embedded JSON Schema and returns it as a JSON string.

The schema is structural (no Action/Resource semantic validation), but it does catch:

- Unknown / typo'd statement keys (`Actoin`, `Resourse`, ...)
- Wrong `Effect` / `Version` values
- Mixing `Action` and `NotAction` (also `Resource`/`NotResource`, `Principal`/`NotPrincipal`) in one statement
- Missing both `Action` and `NotAction`
- Unknown / typo'd Condition operators (`StringEquls`, `ForAllValue:StringEquals`, ...)
- Wrong JSON types (e.g. `Action: 42`, empty arrays, nested arrays)

## Usage

```hcl
terraform {
  required_providers {
    iamencode = {
      source = "winebarrel/iamencode"
    }
  }
}

output "policy" {
  value = provider::iamencode::policy({
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
```
