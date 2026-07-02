# Changelog

## [1.9.0] - 2026-07-02

- `policy_strict`: retry transient service reference fetch failures (HTTP 429/5xx and network errors) up to 3 attempts with exponential backoff. Previously a single 503 failed the function immediately. Other 4xx statuses and malformed responses still fail on the first attempt.

## [1.8.1] - 2026-05-28

- Reword the `policy_strict` function description and simplify validation error messages. No behavior change.

## [1.8.0] - 2026-05-27

- Revert the 1.7.0 default-output change. `policy` / `policy_strict` produce minified one-line JSON again (via `json.Marshal`), matching `jsonencode` and the `minified_json` attribute of `aws_iam_policy_document`. To get indented JSON, run the result through `jsondecode(...)` and re-format it.

## [1.7.0] - 2026-05-27

- `policy` / `policy_strict`: default output is now indented JSON (2-space indent), matching the `json` attribute of `aws_iam_policy_document`. Previously the output was compact one-line JSON via `json.Marshal`; this release uses `json.MarshalIndent`. This breaks code that compares the returned value to a hand-written minified literal. Update the expected value to the indented form.

## [1.6.0] - 2026-05-26

- `policy_strict`: flag Actions whose ARN format does not match any Resource in the Statement. For example, `["s3:GetObject", "s3:ListBucket"]` paired with only `arn:aws:s3:::bucket/key` now reports `s3:ListBucket`, because its bucket-level template cannot accept an object ARN and the action would never apply. The reverse check (a Resource that fits no action) is unchanged.

## [1.5.0] - 2026-05-25

- `policy_strict`: accept condition keys that fill in a placeholder tail of an AWS-declared key. For a declared key like `kms:EncryptionContext:${EncryptionContextKey}`, a key like `kms:EncryptionContext:aws:s3:arn` now matches as a prefix. Exact-match lookups previously flagged it as unknown.
- `policy_strict`: reject the template literal itself (for example `kms:EncryptionContext:${EncryptionContextKey}`) as a condition key. IAM does not expand `${...}` in condition keys, so a verbatim copy from the AWS docs never matches.

## [1.4.0] - 2026-05-21

- Added `provider::iamencode::policy_strict(...)`. Runs the same schema validation as `policy`, plus semantic checks against the live [AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). Catches unknown service prefixes, unknown actions, wildcard patterns that match nothing, condition keys that are not valid for the statement's actions, condition operator and key-type mismatches, and Resource ARN shapes that do not match the action.
- The catalog is fetched on demand and cached per provider process; a single `terraform plan` makes at most one HTTP call per referenced service. When the endpoint is unreachable, `policy_strict` fails rather than passing the policy unchecked. Use `policy` for offline environments. The endpoint can be overridden with `IAMENCODE_SERVICEREF_ENDPOINT`.

## [1.3.1] - 2026-05-20

- Better error messages for invalid condition operators (truncates long enums, suggests "did you mean").
- Dropped the line-number gutter from validation snippets, because the numbers referred to the canonicalized JSON, not the user's `.tf`.

## [1.3.0] - 2026-05-19

- Match `aws_iam_policy_document` on `Sid`: removed the pattern restriction and added duplicate-Sid detection within a document.

## [1.2.0] - 2026-05-19

- Accept `list` / `set` / `map` values from HCL (in addition to `tuple` / `object`). Unsupported attr types now produce a precise error instead of silently emitting `null`.

## [1.1.0] - 2026-05-19

- Require `Version` at the top level.
- Render validation errors as compile-style snippets with a caret pointing at the offending value.

## [1.0.0] - 2026-05-18

- Initial release. `provider::iamencode::policy(...)` validates an IAM policy document (as a Terraform object) against an embedded [JSON Schema](internal/iamvalidate/schema.json) and returns the canonicalized JSON string.
