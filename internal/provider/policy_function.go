package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamvalidate"
)

var _ function.Function = PolicyFunction{}

func NewPolicyFunction() function.Function {
	return PolicyFunction{}
}

type PolicyFunction struct{}

func (r PolicyFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "policy"
}

func (r PolicyFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "policy function",
		MarkdownDescription: "Validates an IAM policy document object against an embedded JSON Schema and returns it as a JSON string. Action/Resource/Principal-style fields accept either a single string or a list of strings.",
		Parameters: []function.Parameter{
			function.DynamicParameter{
				Name:                "policy",
				MarkdownDescription: "IAM policy document as a Terraform object.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r PolicyFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var input types.Dynamic
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &input))
	if resp.Error != nil {
		return
	}

	native := attrValueToNative(input.UnderlyingValue())

	if err := iamvalidate.Validate(native); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, fmt.Sprintf("invalid IAM policy: %v", err)))
		return
	}

	encoded, _ := json.Marshal(native) // map[string]any with string/bool/float64/[]any: cannot fail
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, string(encoded)))
}

// attrValueToNative converts a Terraform dynamic value into a Go native value
// suitable for json.Marshal and jsonschema validation. The framework's
// DynamicParameter only emits the cases handled here; anything else (or null /
// unknown buried in a structure) collapses to nil.
func attrValueToNative(v attr.Value) any {
	if v == nil || v.IsNull() || v.IsUnknown() {
		return nil
	}
	switch x := v.(type) {
	case basetypes.StringValue:
		return x.ValueString()
	case basetypes.BoolValue:
		return x.ValueBool()
	case basetypes.NumberValue:
		f, _ := x.ValueBigFloat().Float64()
		return f
	case basetypes.TupleValue:
		return elementsToNative(x.Elements())
	case basetypes.ObjectValue:
		return attributesToNative(x.Attributes())
	case basetypes.DynamicValue:
		return attrValueToNative(x.UnderlyingValue())
	}
	return nil
}

func elementsToNative(elems []attr.Value) []any {
	out := make([]any, len(elems))
	for i, e := range elems {
		out[i] = attrValueToNative(e)
	}
	return out
}

func attributesToNative(attrs map[string]attr.Value) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, e := range attrs {
		out[k] = attrValueToNative(e)
	}
	return out
}
