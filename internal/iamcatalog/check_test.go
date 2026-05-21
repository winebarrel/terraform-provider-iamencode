package iamcatalog

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeCatalog builds a Catalog backed by a per-test httptest server, so each
// test owns its own instance and there's no shared mutable state to race over.
func newFakeCatalog(t *testing.T, services map[string][]string) *Catalog {
	t.Helper()
	fs := newFakeServer(t, services)
	return New(fs.server.URL)
}

func TestCheckPolicy_AllValid(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{
		"s3":  {"GetObject", "PutObject"},
		"iam": {"GetRole"},
	})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObject"},
			map[string]any{"Action": []any{"s3:PutObject", "iam:GetRole"}},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_UnknownService(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3xx:GetObject"},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown AWS service prefix "s3xx"`)
	assert.Contains(t, err.Error(), "Statement[0]")
}

func TestCheckPolicy_UnknownAction(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObjectXX"},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "GetObjectXX" for service "s3"`)
}

func TestCheckPolicy_WildcardsSkipped(t *testing.T) {
	// Wildcards must not trip the catalog check — without expansion logic we
	// can't know which actions they expand to, so we treat them as valid.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:*"},
			map[string]any{"Action": "s3:Get*"},
			map[string]any{"Action": "*"},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_NotActionChecked(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"NotAction": "s3:Frobnicate"},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Frobnicate")
}

func TestCheckPolicy_StatementAsObject(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": map[string]any{"Action": "s3:Frobnicate"},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Frobnicate")
}

func TestCheckPolicy_MultipleIssuesCollected(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:Frobnicate"},
			map[string]any{"Action": "fakesvc:Foo"},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	// Both issues must appear; the user wants to fix everything in one pass,
	// not whack-a-mole through repeated terraform plan invocations.
	assert.Contains(t, err.Error(), "Frobnicate")
	assert.Contains(t, err.Error(), "fakesvc")
}

func TestCheckPolicy_NetworkFailure_SurfacesError(t *testing.T) {
	// Pointed at a port that refuses connections. The whole point of
	// policy_strict is to consult the catalog; if we can't reach it we must
	// say so rather than silently pretend everything is fine.
	c := New("http://127.0.0.1:1")
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObject"},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestCheckPolicy_NilCatalog_Skips(t *testing.T) {
	// Defensive: a zero-value PolicyStrictFunction or a caller that forgot to
	// inject a catalog must not panic. nil is treated as "unavailable" → skip.
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "totallyfake:Action"},
		},
	}
	assert.NoError(t, CheckPolicy(context.Background(), nil, policy))
}

func TestCheckPolicy_MalformedAction(t *testing.T) {
	// The JSON Schema only requires Action to be a string, so it lets these
	// through. Strict mode must catch them — that's the whole point.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	cases := []string{
		"GetObject",  // no colon
		"s3:",        // empty action
		":GetObject", // empty prefix
		"",           // empty string
		"s3:*:foo",   // multiple colons — must not slip past via the wildcard branch
		"s3:a:b",     // multiple colons, no wildcard
	}
	for _, a := range cases {
		t.Run(a, func(t *testing.T) {
			policy := map[string]any{"Statement": []any{map[string]any{"Action": a}}}
			err := CheckPolicy(context.Background(), c, policy)
			require.Error(t, err, "malformed action %q should fail strict validation", a)
			assert.Contains(t, err.Error(), "malformed action")
		})
	}
}

func TestCheckPolicy_BareStarAccepted(t *testing.T) {
	// "*" alone is a legitimate IAM wildcard (all actions). It does not match
	// the splitAction shape, so it must be handled explicitly before that check.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{"Statement": []any{map[string]any{"Action": "*"}}}
	assert.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_NotAPolicyShape(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	// Defensive: schema validation should reject these upstream, but the
	// helper must not panic if called with garbage.
	require.NoError(t, CheckPolicy(context.Background(), c, nil))
	require.NoError(t, CheckPolicy(context.Background(), c, "not a map"))
	require.NoError(t, CheckPolicy(context.Background(), c, map[string]any{"Statement": 42}))
}

// withConditionKeys wires up a catalog where s3 has ListBucket (with the
// usual prefix/max-keys keys) and GetObject (with none). Used by the
// condition-key tests below.
func withConditionKeys(t *testing.T) *Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"s3": {
			actions: map[string][]string{
				"ListBucket": {"s3:prefix", "s3:max-keys"},
				"GetObject":  nil,
			},
			svcConditionKeys: []string{"s3:prefix", "s3:max-keys"},
		},
	})
	return New(fs.server.URL)
}

func TestCheckPolicy_ConditionKey_Valid(t *testing.T) {
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_NotValidForAction(t *testing.T) {
	// s3:prefix is meaningful for ListBucket, but not for GetObject — exactly
	// the kind of typo policy_strict is designed to surface.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:GetObject",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `condition key "s3:prefix"`)
	assert.Contains(t, err.Error(), "StringEquals")
}

func TestCheckPolicy_ConditionKey_GlobalAwsPrefixAllowed(t *testing.T) {
	// aws:* keys are AWS-global condition keys; they must pass regardless of
	// which service the action belongs to.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:GetObject",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:PrincipalTag/env": "prod",
						"aws:SourceIp":         "10.0.0.0/8",
					},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_UnknownService_FlagsBoth(t *testing.T) {
	// Action references a service we can't resolve. checkOne flags the
	// prefix; checkConditions doesn't get to add that service's keys to the
	// allowed set, so the condition key gets flagged too. We'd rather emit
	// two errors than silently pass on a typo'd policy.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "unknownsvc:DoThing",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"unknownsvc:Foo": "x"},
				},
			},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown AWS service prefix")
	assert.Contains(t, err.Error(), `condition key "unknownsvc:Foo"`)
}

func TestCheckPolicy_ConditionKey_WildcardActionFallsBackToServiceKeys(t *testing.T) {
	// s3:* doesn't narrow to one action, so we accept any key the s3 service
	// declares anywhere — including s3:prefix.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_BareStarActionSkipsCheck(t *testing.T) {
	// Action="*" spans every service; we can't tell what keys are valid, so
	// don't flag anything — degrade silently.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"totallymade:Up": "x"},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_MultipleServices_UnionsKeys(t *testing.T) {
	// Statement mixes s3 and lambda. Each Condition key must be valid for at
	// least one of the actions (union semantics); a key that belongs to
	// neither service is rejected.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"s3": {
			actions:          map[string][]string{"ListBucket": {"s3:prefix"}},
			svcConditionKeys: []string{"s3:prefix"},
		},
		"lambda": {
			actions:          map[string][]string{"InvokeFunction": {"lambda:FunctionUrlAuthType"}},
			svcConditionKeys: []string{"lambda:FunctionUrlAuthType"},
		},
	})
	c := New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"s3:ListBucket", "lambda:InvokeFunction"},
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"s3:prefix":                  "logs/", // valid for s3:ListBucket
						"lambda:FunctionUrlAuthType": "NONE",  // valid for lambda:InvokeFunction
						"aws:SourceIp":               "0/0",   // aws:* global
					},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))

	// Same actions, but one key belongs to neither service — flagged.
	policy["Statement"].([]any)[0].(map[string]any)["Condition"] = map[string]any{
		"StringEquals": map[string]any{"iam:PassedToService": "lambda.amazonaws.com"},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iam:PassedToService")
}

func TestCheckPolicy_ConditionKey_MultipleActions_UnionsKeys(t *testing.T) {
	// ListBucket allows s3:prefix, GetObject does not. With both in the same
	// Statement the union does, so s3:prefix passes.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"s3:ListBucket", "s3:GetObject"},
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_WildcardServicePrefixSkipsCheck(t *testing.T) {
	// "*:GetObject" is a wildcard service — checkOne accepts it (wildcards
	// are out of scope) and checkConditions bails on the condition key
	// because we can't tell what service's keyspace to consult.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "*:GetObject",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"madeup:Key": "x"},
				},
			},
		},
	}
	assert.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_NoActionsOnStatement(t *testing.T) {
	// Schema rejects this upstream, but checkConditions must not panic or
	// flag keys when a Statement somehow reaches us without Action/NotAction.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Condition": map[string]any{"StringEquals": map[string]any{"x:y": "z"}},
			},
		},
	}
	assert.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_OperandIsNotAMap(t *testing.T) {
	// Defensive: schema would reject this, but a non-map operand value must
	// be silently skipped, not crash.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":    "s3:GetObject",
				"Condition": map[string]any{"StringEquals": "not a map"},
			},
		},
	}
	assert.NoError(t, CheckPolicy(context.Background(), c, policy))
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
		{"s3:*:foo", "", "", false},
		{"s3:a:b", "", "", false},
		{"a:b:c:d", "", "", false},
	}
	for _, tc := range cases {
		p, n, ok := splitAction(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.prefix, p, tc.in)
		assert.Equal(t, tc.name, n, tc.in)
	}
}
