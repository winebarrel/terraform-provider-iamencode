package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
)

// swapCatalog points iamcatalog.Default at an httptest server that serves the
// given service prefix with the given actions. Cleanup restores the previous
// Default so tests don't bleed into each other.
func swapCatalog(t *testing.T, services map[string][]string) {
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
	prev := iamcatalog.Default
	iamcatalog.Default = iamcatalog.New(srv.URL)
	t.Cleanup(func() { iamcatalog.Default = prev })
}

func runStrict(t *testing.T, policy attr.Value) *function.RunResponse {
	t.Helper()
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{
		basetypes.NewDynamicValue(policy),
	})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyStrictFunction{}.Run(context.Background(), req, resp)
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
	swapCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, policyObject(t, "s3:GetObject"))
	assert.Nil(t, resp.Error, "expected success: %v", resp.Error)
}

func TestPolicyStrictFunction_Err_UnknownAction(t *testing.T) {
	swapCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, policyObject(t, "s3:Frobnicate"))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "Frobnicate")
}

func TestPolicyStrictFunction_Err_UnknownService(t *testing.T) {
	swapCatalog(t, map[string][]string{"s3": {"GetObject"}})
	resp := runStrict(t, policyObject(t, "s3xx:GetObject"))
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "s3xx")
}

// Schema failure must short-circuit before the catalog check — otherwise we'd
// chase an Action typo on a policy whose Effect was misspelled.
func TestPolicyStrictFunction_Err_SchemaFailsBeforeCatalog(t *testing.T) {
	swapCatalog(t, map[string][]string{"s3": {"GetObject"}})
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
	tup, _ := basetypes.NewTupleValue([]attr.Type{stmt.Type(context.Background())}, []attr.Value{stmt})
	obj, _ := basetypes.NewObjectValue(
		map[string]attr.Type{"Version": basetypes.StringType{}, "Statement": tup.Type(context.Background())},
		map[string]attr.Value{"Version": basetypes.NewStringValue("2012-10-17"), "Statement": tup},
	)
	resp := runStrict(t, obj)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "invalid IAM policy")
}

// When the catalog endpoint is unreachable, the function must still succeed
// for an otherwise-valid policy — graceful degrade by design.
func TestPolicyStrictFunction_OK_CatalogUnavailable(t *testing.T) {
	prev := iamcatalog.Default
	iamcatalog.Default = iamcatalog.New("http://127.0.0.1:1")
	t.Cleanup(func() { iamcatalog.Default = prev })
	resp := runStrict(t, policyObject(t, "s3:GetObject"))
	assert.Nil(t, resp.Error)
}

func TestPolicyStrictFunction_Err_NoArguments(t *testing.T) {
	req := function.RunRequest{Arguments: function.NewArgumentsData(nil)}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyStrictFunction{}.Run(context.Background(), req, resp)
	assert.NotNil(t, resp.Error)
}

func TestPolicyStrictFunction_Err_UnsupportedValue(t *testing.T) {
	dyn := basetypes.NewDynamicValue(fakeAttrValue{})
	req := function.RunRequest{Arguments: function.NewArgumentsData([]attr.Value{dyn})}
	resp := &function.RunResponse{Result: function.NewResultData(basetypes.NewStringNull())}
	PolicyStrictFunction{}.Run(context.Background(), req, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "unsupported terraform value type")
}

func TestNewPolicyStrictFunction_Returns_Function(t *testing.T) {
	f := NewPolicyStrictFunction()
	require.NotNil(t, f)
	var meta function.MetadataResponse
	f.Metadata(context.Background(), function.MetadataRequest{}, &meta)
	assert.Equal(t, "policy_strict", meta.Name)
	var def function.DefinitionResponse
	f.Definition(context.Background(), function.DefinitionRequest{}, &def)
	assert.NotEmpty(t, def.Definition.Summary)
}
