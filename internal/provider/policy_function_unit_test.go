package provider

import (
	"context"
	"math/big"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAttrValue is an attr.Value that doesn't match any case in
// attrValueToNative — used to cover the default branch.
type fakeAttrValue struct{}

func (fakeAttrValue) Type(context.Context) attr.Type { return nil }
func (fakeAttrValue) ToTerraformValue(context.Context) (tftypes.Value, error) {
	return tftypes.Value{}, nil
}
func (fakeAttrValue) Equal(attr.Value) bool { return false }
func (fakeAttrValue) IsNull() bool          { return false }
func (fakeAttrValue) IsUnknown() bool       { return false }
func (fakeAttrValue) String() string        { return "fake" }

func TestAttrValueToNative(t *testing.T) {
	tuple, diags := basetypes.NewTupleValue(
		[]attr.Type{basetypes.StringType{}, basetypes.BoolType{}},
		[]attr.Value{basetypes.NewStringValue("a"), basetypes.NewBoolValue(false)},
	)
	require.False(t, diags.HasError(), diags)

	object, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"k": basetypes.StringType{}},
		map[string]attr.Value{"k": basetypes.NewStringValue("v")},
	)
	require.False(t, diags.HasError(), diags)

	cases := []struct {
		name string
		in   attr.Value
		want any
	}{
		{"nil", nil, nil},
		{"null", basetypes.NewStringNull(), nil},
		{"unknown", basetypes.NewStringUnknown(), nil},
		{"string", basetypes.NewStringValue("x"), "x"},
		{"bool", basetypes.NewBoolValue(true), true},
		{"number", basetypes.NewNumberValue(big.NewFloat(42.5)), 42.5},
		{"tuple", tuple, []any{"a", false}},
		{"object", object, map[string]any{"k": "v"}},
		{"dynamic wraps string", basetypes.NewDynamicValue(basetypes.NewStringValue("inner")), "inner"},
		{"unsupported type", fakeAttrValue{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, attrValueToNative(c.in))
		})
	}
}

func TestRun_NoArguments(t *testing.T) {
	// No arguments triggers the defensive guard after req.Arguments.Get.
	req := function.RunRequest{Arguments: function.NewArgumentsData(nil)}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyFunction{}.Run(context.Background(), req, resp)
	assert.NotNil(t, resp.Error)
}
