package iamcatalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFakeCatalog swaps Default for the duration of the test. Multiple tests
// run sequentially in t.Run subtests, so this is safe; do not call from a
// t.Parallel() test that races with another swap.
func withFakeCatalog(t *testing.T, services map[string][]string) {
	t.Helper()
	fs := newFakeServer(t, services)
	prev := Default
	Default = New(fs.server.URL)
	t.Cleanup(func() { Default = prev })
}

func TestCheckActions_AllValid(t *testing.T) {
	withFakeCatalog(t, map[string][]string{
		"s3":  {"GetObject", "PutObject"},
		"iam": {"GetRole"},
	})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObject"},
			map[string]any{"Action": []any{"s3:PutObject", "iam:GetRole"}},
		},
	}
	require.NoError(t, CheckActions(context.Background(), policy))
}

func TestCheckActions_UnknownService(t *testing.T) {
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3xx:GetObject"},
		},
	}
	err := CheckActions(context.Background(), policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown AWS service prefix "s3xx"`)
	assert.Contains(t, err.Error(), "Statement[0]")
}

func TestCheckActions_UnknownAction(t *testing.T) {
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObjectXX"},
		},
	}
	err := CheckActions(context.Background(), policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "GetObjectXX" for service "s3"`)
}

func TestCheckActions_WildcardsSkipped(t *testing.T) {
	// Wildcards must not trip the catalog check — without expansion logic we
	// can't know which actions they expand to, so we treat them as valid.
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:*"},
			map[string]any{"Action": "s3:Get*"},
			map[string]any{"Action": "*"},
		},
	}
	require.NoError(t, CheckActions(context.Background(), policy))
}

func TestCheckActions_NotActionChecked(t *testing.T) {
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"NotAction": "s3:Frobnicate"},
		},
	}
	err := CheckActions(context.Background(), policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Frobnicate")
}

func TestCheckActions_StatementAsObject(t *testing.T) {
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": map[string]any{"Action": "s3:Frobnicate"},
	}
	err := CheckActions(context.Background(), policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Frobnicate")
}

func TestCheckActions_MultipleIssuesCollected(t *testing.T) {
	withFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:Frobnicate"},
			map[string]any{"Action": "fakesvc:Foo"},
		},
	}
	err := CheckActions(context.Background(), policy)
	require.Error(t, err)
	// Both issues must appear; the user wants to fix everything in one pass,
	// not whack-a-mole through repeated terraform plan invocations.
	assert.Contains(t, err.Error(), "Frobnicate")
	assert.Contains(t, err.Error(), "fakesvc")
}

func TestCheckActions_NetworkFailure_GracefulDegrade(t *testing.T) {
	// Default points at a dead catalog; CheckActions must not surface the
	// network failure as a validation error.
	prev := Default
	Default = New("http://127.0.0.1:1") // refused
	t.Cleanup(func() { Default = prev })
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObject"},
			map[string]any{"Action": "totallyfakeservice:Bar"},
		},
	}
	assert.NoError(t, CheckActions(context.Background(), policy))
}

func TestCheckActions_NotAPolicyShape(t *testing.T) {
	// Defensive: schema validation should reject these upstream, but the
	// helper must not panic if called with garbage.
	require.NoError(t, CheckActions(context.Background(), nil))
	require.NoError(t, CheckActions(context.Background(), "not a map"))
	require.NoError(t, CheckActions(context.Background(), map[string]any{"Statement": 42}))
}

func TestSplitAction(t *testing.T) {
	cases := []struct {
		in           string
		prefix, name string
		ok           bool
	}{
		{"s3:GetObject", "s3", "GetObject", true},
		{"s3:", "", "", false},
		{":GetObject", "", "", false},
		{"noColon", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		p, n, ok := splitAction(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.prefix, p, tc.in)
		assert.Equal(t, tc.name, n, tc.in)
	}
}
