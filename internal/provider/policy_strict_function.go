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
			"Two extra checks run on top of the JSON Schema:\n\n" +
			"1. Every `Action` / `NotAction` must name a real service and a real action (catches typos like `s3:Frobnicate`).\n" +
			"2. Every key inside `Condition` must be one the statement's actions actually consume. Keys with the `aws:` " +
			"prefix are AWS-global and always allowed; service-specific keys are looked up per action (so `s3:prefix` is " +
			"accepted on `s3:ListBucket` but rejected on `s3:GetObject`).\n\n" +
			"Service prefixes and action names are fetched lazily on first use and cached in memory for the lifetime of the " +
			"provider process; a single plan therefore makes at most one HTTP call per referenced service. " +
			"If the reference endpoint is unreachable the catalog checks are skipped (schema validation still runs).\n\n" +
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
