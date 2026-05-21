package provider_test

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/winebarrel/terraform-provider-iamencode/internal/provider"
)

// testAccProtoV6ProviderFactories builds a fresh provider on every invocation
// rather than capturing a single instance at package init. This lets tests
// that need a custom IAMENCODE_SERVICEREF_ENDPOINT call t.Setenv before the
// test step runs and have the new provider pick up the value.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"iamencode": func() (tfprotov6.ProviderServer, error) {
		return providerserver.NewProtocol6WithError(provider.New("test")())()
	},
}
