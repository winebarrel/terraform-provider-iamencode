package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.ProviderWithFunctions = &IAMEncodeProvider{}

type IAMEncodeProvider struct {
	version string
}

func (p *IAMEncodeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "iamencode"
	resp.Version = p.version
}

func (p *IAMEncodeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *IAMEncodeProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *IAMEncodeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *IAMEncodeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *IAMEncodeProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{
		NewPolicyFunction,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &IAMEncodeProvider{
			version: version,
		}
	}
}
