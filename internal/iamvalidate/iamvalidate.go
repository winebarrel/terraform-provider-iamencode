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
// conforms to the embedded IAM policy schema. On failure the returned error
// renders a compile-error-style snippet pointing at the offending value.
//
// After schema validation, Validate also enforces uniqueness of non-empty
// Sid values within a document (matching aws_iam_policy_document, which
// errors on duplicate Sids). Empty / missing Sids are exempt.
func Validate(v any) error {
	if err := compiled.Validate(v); err != nil {
		return &Error{inner: err.(*jsonschema.ValidationError), value: v}
	}
	return checkDuplicateSids(v)
}

// checkDuplicateSids must only be called after schema validation succeeds, so
// the input shape (map at the root, statements being either an object or an
// array of objects) is assumed.
func checkDuplicateSids(v any) error {
	obj := v.(map[string]any)
	arr, ok := obj["Statement"].([]any)
	if !ok {
		return nil // single statement object: no possibility of duplicates
	}
	seen := make(map[string]int, len(arr))
	for i, st := range arr {
		sid, _ := st.(map[string]any)["Sid"].(string)
		if sid == "" {
			continue
		}
		if prev, exists := seen[sid]; exists {
			return fmt.Errorf("duplicate Sid %q in Statement[%d] (previously in Statement[%d])", sid, i, prev)
		}
		seen[sid] = i
	}
	return nil
}

type Error struct {
	inner *jsonschema.ValidationError
	value any
}

func (e *Error) Error() string { return formatError(e.value, e.inner) }
func (e *Error) Unwrap() error { return e.inner }
