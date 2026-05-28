package provider_test

import (
	"context"
	"math"
	"math/big"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	iamencodeprovider "github.com/winebarrel/terraform-provider-iamencode/internal/provider"
)

// fakeAttrValue is an attr.Value that doesn't match any case in
// attrValueToNative, used to cover the unsupported-type error branch.
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
			got, err := iamencodeprovider.AttrValueToNative(c.in)
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
	got, err := iamencodeprovider.ElementsToNative([]attr.Value{
		basetypes.NewStringValue("ok"),
		fakeAttrValue{},
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

// Errors from nested attributes must propagate up through attributesToNative.
func TestAttributesToNative_ErrorPropagates(t *testing.T) {
	got, err := iamencodeprovider.AttributesToNative(map[string]attr.Value{
		"bad": fakeAttrValue{},
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestRun_NoArguments(t *testing.T) {
	// No arguments triggers the defensive guard after req.Arguments.Get.
	req := function.RunRequest{Arguments: function.NewArgumentsData(nil)}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.PolicyFunction{}.Run(context.Background(), req, resp)
	assert.NotNil(t, resp.Error)
}

// HCL lets users write huge literals like 1e1000. big.Float represents those
// faithfully, but Float64() collapses them to +/-Inf, which json refuses. The
// function must surface that as a function error rather than silently emit
// truncated/empty output.
func TestRun_MarshalFailsOnInfinityNumber(t *testing.T) {
	bf, _, err := big.ParseFloat("1e1000", 10, 53, big.ToNearestEven)
	require.NoError(t, err)
	require.True(t, math.IsInf(mustFloat(bf), 1), "setup: 1e1000 should collapse to +Inf")

	// Wrap in a minimal policy shape so it survives schema validation: a Number
	// inside Condition.NumericLessThan is structurally fine for the schema.
	condInner, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"k": basetypes.NumberType{}},
		map[string]attr.Value{"k": basetypes.NewNumberValue(bf)},
	)
	require.False(t, diags.HasError(), diags)
	cond, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"NumericLessThan": condInner.Type(context.Background())},
		map[string]attr.Value{"NumericLessThan": condInner},
	)
	require.False(t, diags.HasError(), diags)
	stmt, diags := basetypes.NewObjectValue(
		map[string]attr.Type{
			"Effect":    basetypes.StringType{},
			"Action":    basetypes.StringType{},
			"Resource":  basetypes.StringType{},
			"Condition": cond.Type(context.Background()),
		},
		map[string]attr.Value{
			"Effect":    basetypes.NewStringValue("Allow"),
			"Action":    basetypes.NewStringValue("s3:GetObject"),
			"Resource":  basetypes.NewStringValue("*"),
			"Condition": cond,
		},
	)
	require.False(t, diags.HasError(), diags)
	tup, diags := basetypes.NewTupleValue([]attr.Type{stmt.Type(context.Background())}, []attr.Value{stmt})
	require.False(t, diags.HasError(), diags)
	policy, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"Version": basetypes.StringType{}, "Statement": tup.Type(context.Background())},
		map[string]attr.Value{"Version": basetypes.NewStringValue("2012-10-17"), "Statement": tup},
	)
	require.False(t, diags.HasError(), diags)

	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{basetypes.NewDynamicValue(policy)})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.PolicyFunction{}.Run(context.Background(), req, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "encode IAM policy")
}

func mustFloat(bf *big.Float) float64 {
	f, _ := bf.Float64()
	return f
}

// Run must surface the error from attrValueToNative as a function argument error.
func TestRun_UnsupportedValue(t *testing.T) {
	dyn := basetypes.NewDynamicValue(fakeAttrValue{})
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{dyn})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.PolicyFunction{}.Run(context.Background(), req, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "unsupported terraform value type")
}
