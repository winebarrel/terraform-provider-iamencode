package iamvalidate

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema.json
var schemaBytes []byte

const schemaURL = "iam-policy.schema.json"

var compiled = mustCompile(schemaBytes)

func mustCompile(data []byte) *jsonschema.Schema {
	s, err := compile(data)
	if err != nil {
		panic(fmt.Sprintf("iamvalidate: %v", err))
	}
	return s
}

func compile(data []byte) (*jsonschema.Schema, error) {
	loader, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	_ = c.AddResource(schemaURL, loader) // fresh compiler + unique URL: cannot fail
	s, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return s, nil
}

// Validate checks whether v (already unmarshaled JSON, e.g. map[string]any)
// conforms to the embedded IAM policy schema.
func Validate(v any) error {
	return compiled.Validate(v)
}
