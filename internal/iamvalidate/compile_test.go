package iamvalidate_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamvalidate"
)

func TestCompile_InvalidJSON(t *testing.T) {
	_, err := iamvalidate.Compile([]byte("{not json"))
	assert.ErrorContains(t, err, "parse schema")
}

func TestCompile_InvalidSchema(t *testing.T) {
	_, err := iamvalidate.Compile([]byte(`{"$ref": "#/definitions/missing"}`))
	assert.ErrorContains(t, err, "compile schema")
}

func TestMustCompile_PanicsOnInvalidSchema(t *testing.T) {
	assert.PanicsWithValue(t, "iamvalidate: parse schema: invalid character 'n' looking for beginning of object key string", func() {
		iamvalidate.MustCompile([]byte("{not json"))
	})
}
