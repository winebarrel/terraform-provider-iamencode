package iamvalidate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompile_InvalidJSON(t *testing.T) {
	_, err := compile([]byte("{not json"))
	assert.ErrorContains(t, err, "parse schema")
}

func TestCompile_InvalidSchema(t *testing.T) {
	_, err := compile([]byte(`{"$ref": "#/definitions/missing"}`))
	assert.ErrorContains(t, err, "compile schema")
}

func TestMustCompile_PanicsOnInvalidSchema(t *testing.T) {
	assert.PanicsWithValue(t, "iamvalidate: parse schema: invalid character 'n' looking for beginning of object key string", func() {
		mustCompile([]byte("{not json"))
	})
}
