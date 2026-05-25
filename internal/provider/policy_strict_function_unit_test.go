package provider_test

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
	iamencodeprovider "github.com/winebarrel/terraform-provider-iamencode/internal/provider"
)

// fakeCatalog returns a Catalog backed by an httptest server with the given
// services and actions. Each test owns its own instance — no global state.
func fakeCatalog(t *testing.T, services map[string][]string) *iamcatalog.Catalog {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "[")
		first := true
		for p := range services {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `{"service":%q,"url":%q}`, p, srv.URL+"/v1/"+p+"/"+p+".json")
		}
		fmt.Fprint(w, "]")
	})
	for p, acts := range services {
		path := "/v1/" + p + "/" + p + ".json"
		name := p
		al := acts
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"Name":%q,"Actions":[`, name)
			for i, a := range al {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprintf(w, `{"Name":%q}`, a)
			}
			fmt.Fprint(w, "]}")
		})
	}
	return iamcatalog.New(srv.URL)
}

func runStrict(t *testing.T, cat *iamcatalog.Catalog, policy attr.Value) *function.RunResponse {
	t.Helper()
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{
		basetypes.NewDynamicValue(policy),
	})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.NewPolicyStrictFunctionForTest(cat).Run(context.Background(), req, resp)
	return resp
}

func policyObject(t *testing.T, action string) attr.Value {
	t.Helper()
	stmt, diags := basetypes.NewObjectValue(
		map[string]attr.Type{
			"Effect":   basetypes.StringType{},
			"Action":   basetypes.StringType{},
			"Resource": basetypes.StringType{},
		},
		map[string]attr.Value{
			"Effect":   basetypes.NewStringValue("Allow"),
			"Action":   basetypes.NewStringValue(action),
			"Resource": basetypes.NewStringValue("*"),
		},
	)
	require.False(t, diags.HasError(), diags)
	tup, diags := basetypes.NewTupleValue(
		[]attr.Type{stmt.Type(context.Background())},
		[]attr.Value{stmt},
	)
	require.False(t, diags.HasError(), diags)
	obj, diags := basetypes.NewObjectValue(
		map[string]attr.Type{
			"Version":   basetypes.StringType{},
			"Statement": tup.Type(context.Background()),
		},
		map[string]attr.Value{
			"Version":   basetypes.NewStringValue("2012-10-17"),
			"Statement": tup,
		},
	)
	require.False(t, diags.HasError(), diags)
	return obj
}

func TestPolicyStrictFunction_OK_ValidAction(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, cat, policyObject(t, "s3:GetObject"))
	assert.Nil(t, resp.Error, "expected success: %v", resp.Error)
}

func TestPolicyStrictFunction_Err_UnknownAction(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, cat, policyObject(t, "s3:Frobnicate"))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "Frobnicate")
}

func TestPolicyStrictFunction_Err_UnknownService(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, cat, policyObject(t, "s3xx:GetObject"))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "s3xx")
}

// Schema failure must short-circuit before the catalog check — otherwise we'd
// chase an Action typo on a policy whose Effect was misspelled.
func TestPolicyStrictFunction_Err_SchemaFailsBeforeCatalog(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	// Effect = "Allowx" — schema rejects it.
	stmt, diags := basetypes.NewObjectValue(
		map[string]attr.Type{
			"Effect": basetypes.StringType{},
			"Action": basetypes.StringType{},
		},
		map[string]attr.Value{
			"Effect": basetypes.NewStringValue("Allowx"),
			"Action": basetypes.NewStringValue("s3:GetObject"),
		},
	)
	require.False(t, diags.HasError(), diags)
	tup, diags := basetypes.NewTupleValue([]attr.Type{stmt.Type(context.Background())}, []attr.Value{stmt})
	require.False(t, diags.HasError(), diags)
	obj, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"Version": basetypes.StringType{}, "Statement": tup.Type(context.Background())},
		map[string]attr.Value{"Version": basetypes.NewStringValue("2012-10-17"), "Statement": tup},
	)
	require.False(t, diags.HasError(), diags)
	resp := runStrict(t, cat, obj)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "invalid IAM policy")
}

// If the catalog endpoint is unreachable, policy_strict must say so rather
// than quietly return the policy as if validation had passed. The whole
// point of strict mode is the catalog check, so swallowing the failure
// would let typo'd policies slip past in airgapped/misconfigured runs.
func TestPolicyStrictFunction_Err_CatalogUnavailable(t *testing.T) {
	cat := iamcatalog.New("http://127.0.0.1:1")
	resp := runStrict(t, cat, policyObject(t, "s3:GetObject"))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "AWS service reference unavailable")
}

func TestPolicyStrictFunction_Err_NoArguments(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	req := function.RunRequest{Arguments: function.NewArgumentsData(nil)}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.NewPolicyStrictFunctionForTest(cat).Run(context.Background(), req, resp)
	assert.NotNil(t, resp.Error)
}

func TestPolicyStrictFunction_Err_UnsupportedValue(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	dyn := basetypes.NewDynamicValue(fakeAttrValue{})
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{dyn})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	iamencodeprovider.NewPolicyStrictFunctionForTest(cat).Run(context.Background(), req, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "unsupported terraform value type")
}

// HCL number literals can overflow float64 to ±Inf, which json.Marshal
// refuses. The function must surface that as a function error instead of
// silently emitting truncated output.
func TestPolicyStrictFunction_Err_MarshalFailsOnInfinity(t *testing.T) {
	cat := fakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	bf, _, err := big.ParseFloat("1e1000", 10, 53, big.ToNearestEven)
	require.NoError(t, err)

	// Use an aws:* key — the strict catalog accepts all aws-prefixed globals,
	// so the condition-key check passes and we reach the json.Marshal step.
	condInner, diags := basetypes.NewObjectValue(
		map[string]attr.Type{"aws:EpochTime": basetypes.NumberType{}},
		map[string]attr.Value{"aws:EpochTime": basetypes.NewNumberValue(bf)},
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

	resp := runStrict(t, cat, policy)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "encode IAM policy")
}

func TestPolicyStrictFunction_MetadataAndDefinition(t *testing.T) {
	f := iamencodeprovider.PolicyStrictFunction{}
	var meta function.MetadataResponse
	f.Metadata(context.Background(), function.MetadataRequest{}, &meta)
	assert.Equal(t, "policy_strict", meta.Name)
	var def function.DefinitionResponse
	f.Definition(context.Background(), function.DefinitionRequest{}, &def)
	assert.NotEmpty(t, def.Definition.Summary)
}
