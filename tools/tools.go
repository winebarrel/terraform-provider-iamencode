//go:build generate

package tools

//go:generate terraform fmt -recursive ../examples/
//go:generate go tool tfplugindocs generate --provider-dir .. -provider-name iamencode
