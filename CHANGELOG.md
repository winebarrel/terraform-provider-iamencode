# Changelog

## [1.8.1] - 2026-05-28

- Reword the `policy_strict` function description and simplify validation error messages. No behavior change.

## [1.8.0] - 2026-05-27

- Revert the 1.7.0 default-output change. `policy` / `policy_strict` produce minified one-line JSON again (via `json.Marshal`), matching Terraform's built-in `jsonencode` and the `minified_json` attribute of `aws_iam_policy_document`. The indented form 1.7.0 introduced turned out to be the outlier in the Terraform function ecosystem — `jsonencode` and friends all emit compact output by default. Users who want indented JSON should `jsondecode(...)` then re-format externally.

## [1.7.0] - 2026-05-27

- `policy` / `policy_strict`: default output is now indented JSON (2-space indent), matching the `json` attribute of `aws_iam_policy_document`. Previously the output was compact one-line JSON via `json.Marshal`; this release switches to `json.MarshalIndent`. Breaking change for code that string-compares the returned value to a hand-written minified literal — update the expected value to match the indented form.

## [1.6.0] - 2026-05-26

- `policy_strict`: flag Actions whose ARN format(s) don't match any Resource in the Statement. A common mistake — `["s3:GetObject", "s3:ListBucket"]` paired with only `arn:aws:s3:::bucket/key` — now reports `s3:ListBucket` as orphaned, since its bucket-level template can't accept an object ARN and the action would silently never apply at evaluation time. The existing reverse-direction check (Resource that fits no action) is unchanged.

## [1.5.0] - 2026-05-25

- `policy_strict`: accept user condition keys that instantiate a placeholder-tail AWS-declared key. For an AWS-declared key like `kms:EncryptionContext:${EncryptionContextKey}`, a user key like `kms:EncryptionContext:aws:s3:arn` is now matched as a prefix; exact-match lookups previously flagged it as unknown.
- `policy_strict`: reject the docs-template literal itself (e.g. `kms:EncryptionContext:${EncryptionContextKey}`) as a condition key. IAM does not expand `${...}` in condition keys, so a verbatim copy-paste from AWS docs never matches at evaluation time.

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
