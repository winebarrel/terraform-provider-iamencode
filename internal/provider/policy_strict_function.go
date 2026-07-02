package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamvalidate"
)

var _ function.Function = PolicyStrictFunction{}

// PolicyStrictFunction holds the catalog it consults instead of a package-level
// singleton. The provider injects it when registering the function; tests
// construct it directly with a fake catalog.
type PolicyStrictFunction struct {
	catalog *iamcatalog.Catalog
}

func (r PolicyStrictFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "policy_strict"
}

func (r PolicyStrictFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "policy_strict function",
		MarkdownDescription: "Like `policy`, but also validates the policy against the live " +
			"[AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). " +
			"Four checks run on top of the JSON Schema:\n\n" +
			"1. Non-wildcard `Action` / `NotAction` values (such as `s3:GetObject`) must name a real service and action. " +
			"This catches typos like `s3:Frobnicate`. Wildcard patterns in the action name (`s3:Get*`, `s3:G?tObject`) are " +
			"expanded against the service's action list and must match at least one action, so `s3:Frobni*` is flagged too. " +
			"The bare `*` and wildcard service prefixes (`*:GetObject`) are accepted without a catalog lookup, because " +
			"expanding them would require fetching every AWS service.\n" +
			"2. Every key inside `Condition` must be valid for the statement's actions. Keys with the `aws:` prefix are " +
			"AWS-global and always allowed; service-specific keys are looked up per action (so `s3:prefix` is allowed on " +
			"`s3:ListBucket` but rejected on `s3:GetObject`). A wildcard action name (`s3:*`, `s3:Get*`) falls back to the " +
			"service-wide set of condition keys. A wildcard service prefix (`*:GetObject`) or the bare `*` Action skips the " +
			"check, because the keyspace cannot be narrowed.\n" +
			"3. Each `Condition` operator must match its key's declared type. For example `s3:max-keys` is numeric, so " +
			"using it under `StringEquals` is flagged; only `NumericEquals`, `NumericLessThan`, and the like are valid. " +
			"The `ForAllValues:` / `ForAnyValue:` prefixes and the `IfExists` suffix are stripped before lookup. The " +
			"`Null` operator works on any type. `aws:*` keys skip the type check, since the catalog does not publish " +
			"their types.\n" +
			"4. Every `Resource` ARN must match an ARN template of at least one of the statement's actions. This catches " +
			"mismatches such as a bucket-only ARN (`arn:aws:s3:::my-bucket`) on `s3:GetObject`, which operates only on " +
			"object ARNs (`.../my-bucket/key`). The bare `*` Resource always passes, and the wildcard rules from check 2 " +
			"apply to the action list. `NotResource` statements skip the check. Known limitation: a few services use " +
			"resource names that contain `/` even though their ARN templates have no literal `/`; CloudWatch Logs " +
			"log-group names (`/aws/lambda/foo`) are the main case. Such ARNs are flagged; use `Resource = \"*\"` or a " +
			"wildcard in the ARN as a workaround.\n\n" +
			"Service prefixes and action names are fetched on first use and cached for the lifetime of the provider " +
			"process, so a single plan fetches each referenced service at most once. Transient failures of that fetch " +
			"(HTTP 429/5xx and network errors) are retried up to 3 attempts with exponential backoff. If the reference " +
			"endpoint is still unreachable after that, the function fails rather than passing the policy unchecked. " +
			"Use `policy` when catalog validation is not wanted.\n\n" +
			"The endpoint defaults to `https://servicereference.us-east-1.amazonaws.com` and can be overridden with the " +
			"`IAMENCODE_SERVICEREF_ENDPOINT` environment variable, which is useful for a corporate mirror or a local fake " +
			"in tests.",
		Parameters: []function.Parameter{
			function.DynamicParameter{
				Name:                "policy",
				MarkdownDescription: "IAM policy document as a Terraform object.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r PolicyStrictFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var input attr.Value
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &input))
	if resp.Error != nil {
		return
	}

	native, err := attrValueToNative(input)
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, err.Error()))
		return
	}

	if err := iamvalidate.Validate(native); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, fmt.Sprintf("invalid IAM policy: %v", err)))
		return
	}

	if err := iamcatalog.CheckPolicy(ctx, r.catalog, native); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, fmt.Sprintf("invalid IAM policy:\n%v", err)))
		return
	}

	encoded, err := json.Marshal(native)
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, fmt.Sprintf("encode IAM policy: %v", err)))
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, string(encoded)))
}
