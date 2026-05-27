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

// PolicyStrictFunction carries the catalog instance it consults, rather than
// reaching for a package-level singleton. The provider hands it in when
// registering the function; tests construct it directly with a fake catalog.
type PolicyStrictFunction struct {
	catalog *iamcatalog.Catalog
}

func (r PolicyStrictFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "policy_strict"
}

func (r PolicyStrictFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "policy_strict function",
		MarkdownDescription: "Like `policy`, but additionally validates the policy against the live " +
			"[AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). " +
			"Four extra checks run on top of the JSON Schema:\n\n" +
			"1. Non-wildcard `Action` / `NotAction` values (e.g. `s3:GetObject`) must name a real service and a real " +
			"action — this is what catches typos like `s3:Frobnicate`. Wildcard patterns within the action name " +
			"(e.g. `s3:Get*`, `s3:G?tObject`) are expanded against the service's real action list and must match " +
			"at least one action, so something like `s3:Frobni*` is also flagged. The bare `*` and wildcard service " +
			"prefixes (`*:GetObject`) are accepted without catalog lookup because they would require fetching every " +
			"AWS service catalog to expand.\n" +
			"2. Every key inside `Condition` must be one that the statement's actions actually consume. Keys with the `aws:` " +
			"prefix are AWS-global and always allowed; service-specific keys are looked up per action (so `s3:prefix` is " +
			"accepted on `s3:ListBucket` but rejected on `s3:GetObject`). When an action's name is itself a wildcard " +
			"(e.g. `s3:*`, `s3:Get*`), the check falls back to the service-wide union of condition keys; statements " +
			"whose service prefix is a wildcard (e.g. `*:GetObject`) or whose Action is the bare `*` skip the condition " +
			"check entirely because the keyspace can't be narrowed.\n" +
			"3. Each `Condition` operator must match its key's declared type. For example `s3:max-keys` is a numeric " +
			"condition key, so using it under `StringEquals` is flagged — only `NumericEquals` / `NumericLessThan` / etc. " +
			"are valid. Operator modifiers `ForAllValues:`, `ForAnyValue:`, and the `IfExists` suffix are stripped before " +
			"the lookup. The `Null` operator works on any key type. `aws:*` keys skip the type check (the catalog does " +
			"not publish their types).\n" +
			"4. Every `Resource` ARN must match one of the ARN templates declared for at least one of the statement's " +
			"actions. This catches mismatches like a bucket-only ARN (`arn:aws:s3:::my-bucket`) on `s3:GetObject` — that " +
			"action only operates on object ARNs (`.../my-bucket/key`). The bare `*` Resource always passes; the same " +
			"wildcard rules from check (2) apply to the action list. `NotResource` statements skip the check entirely. " +
			"Known limitation: a handful of services use resource names that legitimately contain `/` even though their " +
			"AWS-declared ARN templates have no literal `/` — CloudWatch Logs log-group names (`/aws/lambda/foo`) are the " +
			"canonical case. Such ARNs will be flagged; use `Resource = \"*\"` or a wildcard in the ARN as a workaround.\n\n" +
			"Service prefixes and action names are fetched lazily on first use and cached in memory for the lifetime of the " +
			"provider process; a single plan therefore makes at most one HTTP call per referenced service. " +
			"If the reference endpoint is unreachable the function fails — strict mode never silently passes a policy it " +
			"couldn't actually verify. Use `policy` instead when strict catalog validation isn't desired.\n\n" +
			"The endpoint defaults to `https://servicereference.us-east-1.amazonaws.com` and can be overridden by setting " +
			"the `IAMENCODE_SERVICEREF_ENDPOINT` environment variable when Terraform is run — useful for pointing at a " +
			"corporate mirror or, in tests, a local fake.",
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
