package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func okStep(t *testing.T, config, expected string) {
	t.Helper()
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  resource.TestCheckOutput("test", expected),
			},
		},
	})
}

func errStep(t *testing.T, config, errPattern string) {
	t.Helper()
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(errPattern),
			},
		},
	})
}

// Smoke test: the full HCL -> framework -> attrValueToNative -> JSON -> validate -> string path.
func TestPolicyFunction_OK_Smoke(t *testing.T) {
	okStep(t, `
		output "test" {
			value = provider::iamencode::policy({
				Version = "2012-10-17"
				Statement = [
					{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }
				]
			})
		}
	`, `{"Statement":[{"Action":"s3:GetObject","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}`)
}

// Verifies that attrValueToNative correctly converts every Terraform type the
// function is likely to receive (string, bool, number, list, nested object).
func TestPolicyFunction_OK_TypeConversion(t *testing.T) {
	okStep(t, `
		output "test" {
			value = provider::iamencode::policy({
				Statement = [{
					Effect    = "Allow"
					Principal = { Service = ["lambda.amazonaws.com", "ec2.amazonaws.com"] }
					Action    = ["s3:GetObject", "s3:PutObject"]
					Resource  = "*"
					Condition = {
						Bool            = { "aws:SecureTransport" = true }
						NumericLessThan = { "s3:max-keys"          = 100 }
						StringEquals    = { "aws:PrincipalTag/env" = ["prod", "staging"] }
					}
				}]
			})
		}
	`, `{"Statement":[{"Action":["s3:GetObject","s3:PutObject"],"Condition":{"Bool":{"aws:SecureTransport":true},"NumericLessThan":{"s3:max-keys":100},"StringEquals":{"aws:PrincipalTag/env":["prod","staging"]}},"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","ec2.amazonaws.com"]},"Resource":"*"}]}`)
}

// Verifies a single Statement object (not array) round-trips correctly.
func TestPolicyFunction_OK_StatementAsObject(t *testing.T) {
	okStep(t, `
		output "test" {
			value = provider::iamencode::policy({
				Statement = { Effect = "Allow", Action = "s3:*", Resource = "*" }
			})
		}
	`, `{"Statement":{"Action":"s3:*","Effect":"Allow","Resource":"*"}}`)
}

// Verifies that a schema validation error surfaces through the function.
// Exhaustive schema rules are covered by iamvalidate testdata cases.
func TestPolicyFunction_Err_Validation(t *testing.T) {
	errStep(t, `
		output "test" {
			value = provider::iamencode::policy({
				Statement = [{ Effect = "Allow", Actoin = "s3:*", Resource = "*" }]
			})
		}
	`, `(?i)invalid IAM policy`)
}

func TestPolicyFunction_Err_NullInput(t *testing.T) {
	errStep(t, `
		output "test" {
			value = provider::iamencode::policy(null)
		}
	`, `(?i)null`)
}
