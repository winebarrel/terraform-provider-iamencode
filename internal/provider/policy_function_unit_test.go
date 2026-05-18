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
// attrValueToNative — used to cover the unsupported-type error branch.
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

	list, diags := basetypes.NewListValue(
		basetypes.StringType{},
		[]attr.Value{basetypes.NewStringValue("a"), basetypes.NewStringValue("b")},
	)
	require.False(t, diags.HasError(), diags)

	set, diags := basetypes.NewSetValue(
		basetypes.StringType{},
		[]attr.Value{basetypes.NewStringValue("x")},
	)
	require.False(t, diags.HasError(), diags)

	mapValue, diags := basetypes.NewMapValue(
		basetypes.StringType{},
		map[string]attr.Value{"k": basetypes.NewStringValue("v")},
	)
	require.False(t, diags.HasError(), diags)

	cases := []struct {
		name    string
		in      attr.Value
		want    any
		wantErr bool
	}{
		{name: "nil", in: nil, want: nil},
		{name: "null", in: basetypes.NewStringNull(), want: nil},
		{name: "unknown", in: basetypes.NewStringUnknown(), want: nil},
		{name: "string", in: basetypes.NewStringValue("x"), want: "x"},
		{name: "bool", in: basetypes.NewBoolValue(true), want: true},
		{name: "number", in: basetypes.NewNumberValue(big.NewFloat(42.5)), want: 42.5},
		{name: "tuple", in: tuple, want: []any{"a", false}},
		{name: "object", in: object, want: map[string]any{"k": "v"}},
		{name: "list", in: list, want: []any{"a", "b"}},
		{name: "set", in: set, want: []any{"x"}},
		{name: "map", in: mapValue, want: map[string]any{"k": "v"}},
		{name: "dynamic wraps string", in: basetypes.NewDynamicValue(basetypes.NewStringValue("inner")), want: "inner"},
		{name: "unsupported type", in: fakeAttrValue{}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := attrValueToNative(c.in)
			if c.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// Errors from nested elements must propagate up through elementsToNative.
func TestElementsToNative_ErrorPropagates(t *testing.T) {
	got, err := elementsToNative([]attr.Value{
		basetypes.NewStringValue("ok"),
		fakeAttrValue{},
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

// Errors from nested attributes must propagate up through attributesToNative.
func TestAttributesToNative_ErrorPropagates(t *testing.T) {
	got, err := attributesToNative(map[string]attr.Value{
		"bad": fakeAttrValue{},
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestRun_NoArguments(t *testing.T) {
	// No arguments triggers the defensive guard after req.Arguments.Get.
	req := function.RunRequest{Arguments: function.NewArgumentsData(nil)}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyFunction{}.Run(context.Background(), req, resp)
	assert.NotNil(t, resp.Error)
}

// Run must surface the error from attrValueToNative as a function argument error.
func TestRun_UnsupportedValue(t *testing.T) {
	dyn := basetypes.NewDynamicValue(fakeAttrValue{})
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{dyn})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyFunction{}.Run(context.Background(), req, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "unsupported terraform value type")
}
