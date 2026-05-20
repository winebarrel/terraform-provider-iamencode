# terraform-provider-iamencode

[![CI](https://github.com/winebarrel/terraform-provider-iamencode/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/terraform-provider-iamencode/actions/workflows/ci.yml)
[![terraform docs](https://img.shields.io/badge/terraform-docs-%35835CC?logo=terraform)](https://registry.terraform.io/providers/winebarrel/iamencode/latest/docs)
[![codecov](https://codecov.io/gh/winebarrel/terraform-provider-iamencode/graph/badge.svg?token=Edpy75fnRI)](https://codecov.io/gh/winebarrel/terraform-provider-iamencode)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

Terraform provider with a user-defined function that validates an IAM policy document (passed as a Terraform object) against an embedded [JSON Schema](internal/iamvalidate/schema.json) and returns it as a JSON string.

![](https://github.com/user-attachments/assets/477489b0-3eff-4385-8281-4c1ac56bec17)

The schema is structural (no Action/Resource semantic validation), but it does catch:

- Unknown / typo'd statement keys (`Actoin`, `Resourse`, ...)
- Missing required top-level keys (`Version`, `Statement`)
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
      source  = "winebarrel/iamencode"
      version = ">= 1.3.0"
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

## Development

### Requirements

- Go (see `go.mod` for the required version)
- Terraform

### Build & test

```sh
make build      # go vet + go build
make test       # run unit tests
make coverage   # run tests with coverage (writes coverage.txt)
make lint       # golangci-lint
make docs       # regenerate docs under docs/
```

### Trying the provider locally

The repo ships with `dev.tfrc.tpl`, which is rendered into `dev.tfrc` with a `dev_overrides` block pointing Terraform at the freshly built binary in this directory. The `tf-*` targets build the provider and run Terraform with `TF_CLI_CONFIG_FILE=dev.tfrc`:

```sh
cp iamencode.tf.sample iamencode.tf   # or write your own .tf
make tf-plan
make tf-apply
make tf-console
```

When you are done, `make tf-clean` removes the built binary, `dev.tfrc`, and local Terraform state.
