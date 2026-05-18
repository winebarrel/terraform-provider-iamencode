package iamvalidate_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamvalidate"
)

type assertFn func(assert.TestingT, error, ...any) bool

func loadCase(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var v any
	require.NoError(t, json.Unmarshal(data, &v))
	return v
}

func runDir(t *testing.T, dir string, check assertFn) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		t.Run(name, func(t *testing.T) {
			v := loadCase(t, filepath.Join(dir, e.Name()))
			check(t, iamvalidate.Validate(v))
		})
	}
}

func TestValidate_Valid(t *testing.T) {
	runDir(t, "testdata/valid", assert.NoError)
}

func TestValidate_Invalid(t *testing.T) {
	runDir(t, "testdata/invalid", assert.Error)
}

// Duplicate non-empty Sids in the same document must be rejected, matching
// aws_iam_policy_document. The error message names the duplicate Sid and
// both statement indexes.
func TestValidate_DuplicateSid_Message(t *testing.T) {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Sid": "Dup", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
			map[string]any{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"},
			map[string]any{"Sid": "Dup", "Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
		},
	}
	err := iamvalidate.Validate(policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate Sid "Dup"`)
	assert.Contains(t, err.Error(), "Statement[2]")
	assert.Contains(t, err.Error(), "Statement[0]")
}

// Empty Sids are exempt — they may appear on multiple statements.
func TestValidate_EmptySid_AllowsDuplicates(t *testing.T) {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
			map[string]any{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
		},
	}
	assert.NoError(t, iamvalidate.Validate(policy))
}
