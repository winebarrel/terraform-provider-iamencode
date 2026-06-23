# terraform-provider-iamencode

[![CI](https://github.com/winebarrel/terraform-provider-iamencode/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/terraform-provider-iamencode/actions/workflows/ci.yml)
[![terraform docs](https://img.shields.io/badge/terraform-docs-%35835CC?logo=terraform)](https://registry.terraform.io/providers/winebarrel/iamencode/latest/docs)
[![codecov](https://codecov.io/gh/winebarrel/terraform-provider-iamencode/graph/badge.svg?token=Edpy75fnRI)](https://codecov.io/gh/winebarrel/terraform-provider-iamencode)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

A Terraform provider with user-defined functions that validate an IAM policy document (passed as a Terraform object) and return it as a JSON string. It provides two functions:

- `provider::iamencode::policy`: structural validation against an embedded [JSON Schema](internal/iamvalidate/schema.json). Runs offline, with no network access.
- `provider::iamencode::policy_strict`: the same checks as `policy`, plus semantic checks against the live [AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). The catalog is fetched on demand and cached for the provider process.

![](https://github.com/user-attachments/assets/477489b0-3eff-4385-8281-4c1ac56bec17)

## What gets caught

### `policy` (schema-only)

- Unknown / typo'd statement keys (`Actoin`, `Resourse`, ...)
- Missing required top-level keys (`Version`, `Statement`)
- Wrong `Effect` / `Version` values
- Mixing `Action` and `NotAction` (also `Resource`/`NotResource`, `Principal`/`NotPrincipal`) in one statement
- Missing both `Action` and `NotAction`
- Unknown / typo'd Condition operators (`StringEquls`, `ForAllValue:StringEquals`, ...)
- Wrong JSON types (e.g. `Action: 42`, empty arrays, nested arrays)

### `policy_strict` (schema + catalog)

Everything `policy` catches, plus:

- Unknown service prefix. `s3xx:GetObject` -> `Statement[0]: unknown AWS service prefix "s3xx" in action "s3xx:GetObject"`
- Unknown action. `s3:Frobnicate` -> `Statement[0]: unknown action "Frobnicate" for service "s3"`
- Wildcard pattern that matches nothing. `s3:Frobni*` -> `Statement[0]: action pattern "s3:Frobni*" matches no actions in service "s3"`
- Condition key not valid for the action. `s3:GetObject` + `Condition: { StringEquals: { "s3:prefix": "..." } }` -> `Statement[0]: condition key "s3:prefix" (under StringEquals) is not valid for the statement's actions`. `s3:prefix` applies to `ListBucket`, not `GetObject`.
- Operator type mismatch. `StringEquals: { "s3:max-keys": "100" }` -> `Statement[0]: operator StringEquals expects a String key, but "s3:max-keys" is declared as Numeric`
- Resource ARN shape mismatch. `s3:GetObject` + `Resource: "arn:aws:s3:::my-bucket"` -> `Statement[0]: resource "arn:aws:s3:::my-bucket" does not match any ARN format for the statement's actions`. Object actions need the `bucket/key` form.

## Usage

```hcl
terraform {
  required_providers {
    iamencode = {
      source  = "winebarrel/iamencode"
      version = "~> 1.8"
    }
  }
}

# Schema-only validation, offline.
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

# Schema plus live AWS catalog validation. Catches more typos, at the cost of
# a few HTTP calls (cached per provider process).
output "policy_strict" {
  value = provider::iamencode::policy_strict({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::my-bucket"
        Condition = {
          StringEquals    = { "s3:prefix" = "logs/" }
          NumericLessThan = { "s3:max-keys" = "1000" }
        }
      },
    ]
  })
}
```

### `policy_strict` notes

- Fetches `https://servicereference.us-east-1.amazonaws.com` once per service per provider process. A single `terraform plan` makes at most one HTTP call per referenced service.
- The endpoint can be overridden with the `IAMENCODE_SERVICEREF_ENDPOINT` environment variable, which is useful for corporate mirrors or testing.
- If the catalog endpoint is unreachable, `policy_strict` fails rather than passing the policy unchecked. Use `policy` in airgapped environments.
- Wildcard service prefixes (`*:GetObject`) and the bare `*` action skip the catalog checks, because expanding them would require fetching every AWS service.
- `NotAction` / `NotResource` statements skip the action and resource-ARN checks, because the inverted set has no fixed list to check against.
- Known limitation: a few resource ARNs whose templates lack a literal `/` but whose actual values contain `/` (CloudWatch Logs log-group names such as `/aws/lambda/foo`) get flagged. Use `Resource = "*"` or a wildcard ARN as a workaround.

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

The repo includes `dev.tfrc.tpl`, which is rendered into `dev.tfrc` with a `dev_overrides` block that points Terraform at the built binary in this directory. The `tf-*` targets build the provider and run Terraform with `TF_CLI_CONFIG_FILE=dev.tfrc`:

```sh
cp iamencode.tf.sample iamencode.tf   # or write your own .tf
make tf-plan
make tf-apply
make tf-console
```

When you are done, `make tf-clean` removes the built binary, `dev.tfrc`, and local Terraform state.
