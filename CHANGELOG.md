# Changelog

## [1.4.0] - 2026-05-21

- Added `provider::iamencode::policy_strict(...)`. Runs the same schema validation as `policy`, plus semantic checks against the live [AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). Catches unknown service prefixes, unknown actions, wildcard patterns that match nothing, condition keys that aren't valid for the statement's actions, condition operator vs key-type mismatches, and Resource ARN shapes that don't match the action.
- The catalog is fetched lazily and cached per provider process; a single `terraform plan` makes at most one HTTP call per referenced service. When the endpoint is unreachable `policy_strict` fails hard rather than silently passing - use `policy` for offline environments. Endpoint override via `IAMENCODE_SERVICEREF_ENDPOINT`.

## [1.3.1] - 2026-05-20

- Better error messages for invalid condition operators (truncates long enums, suggests "did you mean…").
- Dropped the line-number gutter from validation snippets - the numbers referred to the canonicalized JSON, not the user's `.tf`.

## [1.3.0] - 2026-05-19

- Match `aws_iam_policy_document` on `Sid`: removed the pattern restriction and added duplicate-Sid detection within a document.

## [1.2.0] - 2026-05-19

- Accept `list` / `set` / `map` values from HCL (in addition to `tuple` / `object`). Unsupported attr types now produce a precise error instead of silently emitting `null`.

## [1.1.0] - 2026-05-19

- Require `Version` at the top level.
- Render validation errors as compile-style snippets with a caret pointing at the offending value.

## [1.0.0] - 2026-05-18

- Initial release. `provider::iamencode::policy(...)` validates an IAM policy document (as a Terraform object) against an embedded [JSON Schema](internal/iamvalidate/schema.json) and returns the canonicalized JSON string.
