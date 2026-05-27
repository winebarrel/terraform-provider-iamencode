package provider_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// startFakeCatalog spins up an httptest server that mimics the AWS service
// reference root index and per-service JSON, then sets
// IAMENCODE_SERVICEREF_ENDPOINT so the provider factory wires it in. t.Setenv
// auto-restores; t.Cleanup tears the server down.
func startFakeCatalog(t *testing.T, services map[string][]string) {
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
	t.Setenv("IAMENCODE_SERVICEREF_ENDPOINT", srv.URL)
}

func TestPolicyStrictFunction_OK_HCL(t *testing.T) {
	startFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	okStep(t, `
		output "test" {
			value = provider::iamencode::policy_strict({
				Version = "2012-10-17"
				Statement = [
					{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }
				]
			})
		}
	`, `{
  "Statement": [
    {
      "Action": "s3:GetObject",
      "Effect": "Allow",
      "Resource": "*"
    }
  ],
  "Version": "2012-10-17"
}`)
}

func TestPolicyStrictFunction_Err_HCL_UnknownAction(t *testing.T) {
	startFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	errStep(t, `
		output "test" {
			value = provider::iamencode::policy_strict({
				Version = "2012-10-17"
				Statement = [
					{ Effect = "Allow", Action = "s3:Frobnicate", Resource = "*" }
				]
			})
		}
	`, `(?s)unknown action.*Frobnicate`)
}
