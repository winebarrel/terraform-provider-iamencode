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
		MarkdownDescription: "Like `policy`, but additionally checks every Action / NotAction against the live " +
			"[AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html). " +
			"Service prefixes and action names are fetched lazily on first use and cached in memory for the lifetime of the " +
			"provider process; a single plan therefore makes at most one HTTP call per referenced service. " +
			"If the reference endpoint is unreachable the catalog check is skipped (schema validation still runs).",
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

	if err := iamcatalog.CheckActions(ctx, r.catalog, native); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, fmt.Sprintf("invalid IAM policy:\n%v", err)))
		return
	}

	encoded, _ := json.Marshal(native)
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, string(encoded)))
}
