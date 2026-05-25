package provider_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/stretchr/testify/assert"
	iamencodeprovider "github.com/winebarrel/terraform-provider-iamencode/internal/provider"
)

func TestProvider_Configure_NoOp(t *testing.T) {
	p := &iamencodeprovider.IAMEncodeProvider{}
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), provider.ConfigureRequest{}, &resp)
	assert.False(t, resp.Diagnostics.HasError(), resp.Diagnostics)
}
