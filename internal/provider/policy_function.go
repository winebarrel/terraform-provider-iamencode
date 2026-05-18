package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
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
	// Receive the argument as a generic attr.Value rather than types.Dynamic:
	// Arguments.Get takes a fast path for *attr.Value targets that skips the
	// tftypes round-trip, which both saves work and preserves the original
	// attr.Value implementation (the DynamicValue case below unwraps it).
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

	encoded, _ := json.Marshal(native) // map[string]any with string/bool/float64/[]any: cannot fail
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, string(encoded)))
}

// attrValueToNative converts a Terraform dynamic value into a Go native value
// suitable for json.Marshal and jsonschema validation. Null and unknown
// values collapse to nil so the downstream JSON Schema validator can report
// a precise "got null, want X" diagnostic pointing at the offending field.
// An unrecognized attr.Value implementation returns an error rather than
// silently emitting nil — silent nil corrupts the JSON in a way the schema
// validator cannot diagnose ergonomically.
func attrValueToNative(v attr.Value) (any, error) {
	if v == nil || v.IsNull() || v.IsUnknown() {
		return nil, nil
	}
	switch x := v.(type) {
	case basetypes.StringValue:
		return x.ValueString(), nil
	case basetypes.BoolValue:
		return x.ValueBool(), nil
	case basetypes.NumberValue:
		f, _ := x.ValueBigFloat().Float64()
		return f, nil
	case basetypes.TupleValue:
		return elementsToNative(x.Elements())
	case basetypes.ListValue:
		return elementsToNative(x.Elements())
	case basetypes.SetValue:
		return elementsToNative(x.Elements())
	case basetypes.ObjectValue:
		return attributesToNative(x.Attributes())
	case basetypes.MapValue:
		return attributesToNative(x.Elements())
	case basetypes.DynamicValue:
		return attrValueToNative(x.UnderlyingValue())
	}
	return nil, fmt.Errorf("unsupported terraform value type %T", v)
}

func elementsToNative(elems []attr.Value) ([]any, error) {
	out := make([]any, len(elems))
	for i, e := range elems {
		v, err := attrValueToNative(e)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func attributesToNative(attrs map[string]attr.Value) (map[string]any, error) {
	out := make(map[string]any, len(attrs))
	for k, e := range attrs {
		v, err := attrValueToNative(e)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}
