package iamcatalog_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
)

// newFakeCatalog builds a Catalog backed by a per-test httptest server, so each
// test owns its own instance and there's no shared mutable state to race over.
func newFakeCatalog(t *testing.T, services map[string][]string) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServer(t, services)
	return iamcatalog.New(fs.server.URL)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_UnknownService(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3xx:GetObject"},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "GetObjectXX" for service "s3"`)
}

func TestCheckPolicy_BareStarAction_Skipped(t *testing.T) {
	// The bare "*" is a universal wildcard — every IAM action across every
	// service. We can't usefully validate it against any one service
	// catalog, so it passes without lookup. Wildcard *names* (like "s3:*"
	// or "s3:Get*") are now expanded — see TestCheckPolicy_WildcardName_*.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "*"},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_WildcardName_MatchesRealAction(t *testing.T) {
	// "s3:Get*" should expand against the service catalog. Since the fake
	// catalog has a real GetObject action, the pattern resolves and passes.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject", "PutObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:Get*"},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_WildcardName_NoMatch_Flagged(t *testing.T) {
	// "s3:Frobni*" looks plausible (right service, "*" suffix is common) but
	// matches no real s3 action. That's the typo we want to catch.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject", "PutObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:Frobni*"},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `action pattern "s3:Frobni*" matches no actions in service "s3"`)
}

func TestCheckPolicy_WildcardName_SingleCharMatcher(t *testing.T) {
	// "?" matches exactly one character — "G?tObject" should hit GetObject.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:G?tObject"},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_WildcardName_BareStar(t *testing.T) {
	// "s3:*" matches everything in s3, so it always passes whenever any
	// action exists in the service.
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:*"},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_WildcardName_EmptyService_Flagged(t *testing.T) {
	// Edge case: a service that has zero actions — any non-trivial wildcard
	// pattern matches nothing. (A real AWS service won't have zero actions,
	// but the helper handles it gracefully rather than panicking.)
	c := newFakeCatalog(t, map[string][]string{"s3": {}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:Get*"},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "matches no actions")
}

func TestCheckPolicy_WildcardServicePrefix_StillSkipped(t *testing.T) {
	// A wildcard in the *service* prefix can't be expanded without fetching
	// every service catalog (hundreds of services). Keep skipping silently
	// — and not just for "*", but also for "?" (the other IAM wildcard).
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	for _, a := range []string{"*:GetObject", "s*:GetObject", "s?:GetObject", "?3:GetObject"} {
		t.Run(a, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{"Action": a},
				},
			}
			require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
		})
	}
}

func TestCheckPolicy_NotActionChecked(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"NotAction": "s3:Frobnicate"},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Frobnicate")
}

func TestCheckPolicy_StatementAsObject(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	policy := map[string]any{
		"Statement": map[string]any{"Action": "s3:Frobnicate"},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	c := iamcatalog.New("http://127.0.0.1:1")
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "s3:GetObject"},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestCheckPolicy_NilCatalog_Skips(t *testing.T) {
	// Defensive: a zero-value PolicyStrictFunction or a caller that forgot to
	// inject a catalog must not panic. nil is treated as "unavailable" → skip.
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Action": "totallyfake:Action"},
		},
	}
	assert.NoError(t, iamcatalog.CheckPolicy(context.Background(), nil, policy))
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
			err := iamcatalog.CheckPolicy(context.Background(), c, policy)
			require.Error(t, err, "malformed action %q should fail strict validation", a)
			assert.Contains(t, err.Error(), "malformed action")
		})
	}
}

func TestCheckPolicy_NotAPolicyShape(t *testing.T) {
	c := newFakeCatalog(t, map[string][]string{"s3": {"GetObject"}})
	// Defensive: schema validation should reject these upstream, but the
	// helper must not panic if called with garbage.
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, nil))
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, "not a map"))
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, map[string]any{"Statement": 42}))
}

// withConditionKeys wires up a catalog where s3 has ListBucket (with the
// usual prefix/max-keys keys) and GetObject (with none). Used by the
// condition-key tests below.
func withConditionKeys(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"s3": {
			actions: map[string][]string{
				"ListBucket": {"s3:prefix", "s3:max-keys"},
				"GetObject":  nil,
			},
			svcConditionKeys: []string{"s3:prefix", "s3:max-keys"},
			svcKeyTypes: map[string]string{
				"s3:prefix":   "String",
				"s3:max-keys": "Numeric",
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_NetworkFailure_FromCheckConditionsPath(t *testing.T) {
	// Wildcard action names skip checkOne's Lookup, so the first time the
	// catalog is consulted for this prefix is inside checkConditions. If
	// the catalog is unreachable that error must propagate out of
	// CheckPolicy — exercising the err branch in checkConditions itself.
	c := iamcatalog.New("http://127.0.0.1:1")
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:Get*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestCheckPolicy_ConditionKey_UnknownActionFallsBackToServiceKeys(t *testing.T) {
	// checkOne flags the unknown action; checkConditions can't find the
	// action in keysByAction and so falls back to svc.allKeys. Any key
	// present in that union must still pass.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:NotARealAction",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:prefix": "logs/"}, // in svc.allKeys
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "NotARealAction"`)
	assert.NotContains(t, err.Error(), "condition key")
}

func TestCheckPolicy_ConditionKey_NotActionStatement_SkipsConditionCheck(t *testing.T) {
	// NotAction means "every IAM action EXCEPT these," so the listed entries
	// don't define the keyspace the way Action entries do. Validating
	// condition keys against the NotAction list would falsely flag keys that
	// are perfectly valid for actions the statement actually authorizes.
	// checkOne still validates each NotAction name exists (catches typos).
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"NotAction": "s3:GetObject",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"iam:PassedToService": "lambda.amazonaws.com"},
				},
			},
		},
	}
	// Real NotAction entries that exist must still pass.
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))

	// And a typo in NotAction is still caught by checkOne even though
	// checkConditions skipped.
	policy["Statement"].([]any)[0].(map[string]any)["NotAction"] = "s3:GetObjectx"
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "GetObjectx"`)
	assert.NotContains(t, err.Error(), "condition key", "NotAction must not drive the condition-key keyspace")
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
	c := iamcatalog.New(fs.server.URL)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))

	// Same actions, but one key belongs to neither service — flagged.
	policy["Statement"].([]any)[0].(map[string]any)["Condition"] = map[string]any{
		"StringEquals": map[string]any{"iam:PassedToService": "lambda.amazonaws.com"},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	assert.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	assert.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
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
	assert.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

// withStsForOIDC wires up a minimal sts service for the OIDC condition-key
// tests below. AssumeRoleWithWebIdentity is the trigger action; TagSession
// is a co-listed sts action that does NOT enable OIDC keys. lambda is
// added so the "wildcard from an unrelated service must not trigger the
// carve-out" case can exercise a real wildcard expansion.
func withStsForOIDC(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"sts": {
			actions: map[string][]string{
				"AssumeRoleWithWebIdentity": {"sts:RoleSessionName"},
				"TagSession":                nil,
			},
			svcConditionKeys: []string{"sts:RoleSessionName"},
		},
		"lambda": {
			actions: map[string][]string{
				"InvokeFunction": nil,
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_ConditionKey_OIDCAcceptedForWebIdentity(t *testing.T) {
	// A user-registered OIDC provider contributes "<hostname>:<key>"
	// condition keys that aren't in the static service reference (only
	// AWS-preregistered providers like accounts.google.com are listed).
	// When the statement targets AssumeRoleWithWebIdentity, accept these
	// dynamic keys instead of flagging them as unknown.
	c := withStsForOIDC(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"sts:AssumeRoleWithWebIdentity", "sts:TagSession"},
				"Condition": map[string]any{
					"StringLike": map[string]any{
						"oidc.example.com:sub": "repo:org/proj:*",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_OIDCRejectedWithoutWebIdentity(t *testing.T) {
	// Without an AssumeRoleWithWebIdentity action in the statement the
	// OIDC carve-out doesn't apply — "<hostname>:<key>" remains an
	// unknown key and is flagged. (TagSession alone is a co-listed sts
	// action that doesn't itself drive OIDC federation.)
	c := withStsForOIDC(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "sts:TagSession",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"oidc.example.com:sub": "repo:org/proj",
					},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"oidc.example.com:sub"`)
}

func TestCheckPolicy_ConditionKey_OIDCRequiresDottedHostnamePrefix(t *testing.T) {
	// The carve-out only applies to keys whose prefix looks like a
	// hostname (contains a '.'). A typo'd non-hostname key like
	// "tokenhost:sub" still goes through the strict catalog check and
	// gets flagged — otherwise the OIDC fix would mask real mistakes.
	c := withStsForOIDC(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "sts:AssumeRoleWithWebIdentity",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"tokenhost:sub": "repo:org/proj",
					},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"tokenhost:sub"`)
}

func TestIsOIDCConditionKey(t *testing.T) {
	// Direct unit test for the hostname-prefix predicate. Drives the
	// LDH-charset, dot-required, single-colon, and label-shape rules.
	cases := []struct {
		in   string
		want bool
	}{
		// Happy path — real OIDC issuer hostnames.
		{"oidc.example.com:sub", true},
		{"oidc.example.com:aud", true},
		{"token.actions.githubusercontent.com:sub", true},
		{"id.subdomain.example.org:sub", true},
		// Hostnames are case-insensitive.
		{"OIDC.Example.COM:sub", true},
		// Hyphen inside labels is fine.
		{"my-oidc.example-co.com:sub", true},

		// Not OIDC — single-label / no dot. Falls through to catalog check.
		{"sts:RoleSessionName", false},
		{"saml:aud", false},
		{"localhost:sub", false},

		// Missing pieces.
		{"oidc.example.com:", false},
		{":sub", false},
		{"oidc.example.com", false},
		{"", false},

		// Multi-colon — single-colon rule.
		{"oidc.example.com:sub:extra", false},
		{"a.b:c:d", false},

		// Leading / trailing dot, empty labels.
		{".example.com:sub", false},
		{"example.com.:sub", false},
		{"a..b:sub", false},

		// Labels can't start or end with hyphen.
		{"-a.b:sub", false},
		{"a-.b:sub", false},
		{"a.-b:sub", false},
		{"a.b-:sub", false},

		// Disallowed characters.
		{"oidc/example.com:sub", false},
		{"oidc_example.com:sub", false},
		{"oidc.example.com/path:sub", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, iamcatalog.IsOIDCConditionKey(tc.in))
		})
	}
}

func TestCheckPolicy_ConditionKey_OIDCAcceptedForWildcardActions(t *testing.T) {
	// Wildcard action patterns that cover AssumeRoleWithWebIdentity must
	// also enable the OIDC carve-out. Without this, the common shorthand
	// "sts:AssumeRoleWith*" or "sts:*" in a federation policy would still
	// flag every "<hostname>:<key>" condition entry.
	c := withStsForOIDC(t)
	for _, action := range []string{
		"sts:AssumeRoleWithWebIdentity", // exact
		"sts:AssumeRoleWith*",           // common prefix wildcard
		"sts:AssumeRoleWithWeb*",        // longer prefix
		"sts:*",                         // service-wide
		"sts:AssumeRoleW?thWebIdentity", // single-char wildcard
	} {
		t.Run(action, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action": action,
						"Condition": map[string]any{
							"StringLike": map[string]any{
								"oidc.example.com:sub": "repo:org/proj:*",
							},
						},
					},
				},
			}
			require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
		})
	}
}

func TestCheckPolicy_ConditionKey_OIDCNotTriggeredByOtherServiceWildcards(t *testing.T) {
	// A wildcard from an unrelated service must not turn on the OIDC
	// carve-out — "lambda:Invoke*" matches a real lambda action and
	// otherwise validates fine, but it doesn't cover
	// sts:AssumeRoleWithWebIdentity, so the OIDC hostname:keyname must
	// still be flagged.
	c := withStsForOIDC(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "lambda:Invoke*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"oidc.example.com:sub": "repo:org/proj",
					},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"oidc.example.com:sub"`)
}

// withPlaceholderKeys wires up two services that use placeholder-tail
// condition keys. AWS expresses these as "<prefix><sep>${<placeholder>}"
// where <sep> is ':' (kms:EncryptionContext:${EncryptionContextKey}) or '/'
// (s3:ExistingObjectTag/${key}). Each instantiated user key shares the
// declared prefix but supplies a value in place of the placeholder. The
// validator must accept those instantiations while still rejecting genuine
// typos that don't match any declared prefix.
//
// kms:Encrypt lists the placeholder key as an ActionConditionKey;
// kms:DescribeKey deliberately does not, so the per-action enforcement
// path can be exercised. svcKeyTypes pins a declared type so the
// operator type-check tests have something to read.
func withPlaceholderKeys(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"kms": {
			actions: map[string][]string{
				"Encrypt":     {"kms:EncryptionContext:${EncryptionContextKey}"},
				"DescribeKey": nil,
			},
			svcConditionKeys: []string{"kms:EncryptionContext:${EncryptionContextKey}"},
			svcKeyTypes: map[string]string{
				"kms:EncryptionContext:${EncryptionContextKey}": "String",
			},
		},
		"s3": {
			actions: map[string][]string{
				"GetObject": {"s3:ExistingObjectTag/${key}"},
			},
			svcConditionKeys: []string{"s3:ExistingObjectTag/${key}"},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_ConditionKey_PlaceholderColonForm_Allowed(t *testing.T) {
	// The canonical KMS shape: a real policy instantiates
	// kms:EncryptionContext:${EncryptionContextKey} as
	// kms:EncryptionContext:<some-user-defined-name>. The strict check used
	// to flag this as an unknown key — the catalog only stores the templated
	// form. The new prefix-pattern path accepts any value with the declared
	// prefix.
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "kms:Encrypt",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::bucket/key",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_PlaceholderSlashForm_Allowed(t *testing.T) {
	// Service-specific tag-style keys (s3:ExistingObjectTag/${key},
	// iam:ResourceTag/${TagKey}, etc.) use '/' as the placeholder
	// separator. They share the same prefix-pattern semantics as the colon
	// form. (The aws:* tag keys are short-circuited by the aws:* early-
	// return in checkConditions and never reach the prefix path, so this
	// test deliberately uses a non-aws service to exercise it.)
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:GetObject",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"s3:ExistingObjectTag/Owner": "alice",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_MultipleUserValues(t *testing.T) {
	// Different user values under the same declared prefix must all pass.
	// Real policies often pin several encryption-context keys at once.
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "kms:Encrypt",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::b/k",
						"kms:EncryptionContext:tenant":     "alice",
						"kms:EncryptionContext:purpose":    "audit-log",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_Rejections(t *testing.T) {
	// Negative cases the prefix-pattern path must still reject so the new
	// permissiveness doesn't mask real typos:
	//   - "kms:EncryptionContext" (no trailing separator): looks like the
	//     parent name but isn't a real catalog key.
	//   - "kms:EncryptionContext:" (separator but empty value): would be
	//     a nonsensical key at IAM evaluation time; flagging it here keeps
	//     the validator strict.
	//   - "kms:EncryptionContextX:foo" (typo in the prefix): genuine
	//     mistake that the new path must not swallow.
	c := withPlaceholderKeys(t)
	cases := []string{
		"kms:EncryptionContext",
		"kms:EncryptionContext:",
		"kms:EncryptionContextX:foo",
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action": "kms:Encrypt",
						"Condition": map[string]any{
							"StringEquals": map[string]any{k: "x"},
						},
					},
				},
			}
			err := iamcatalog.CheckPolicy(context.Background(), c, policy)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "condition key")
		})
	}
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_NotValidForAction(t *testing.T) {
	// kms:DescribeKey is wired with no ActionConditionKeys, so the per-
	// action lookup returns an empty set and the placeholder key declared
	// only at the service level (and on kms:Encrypt) must be rejected.
	// This proves the per-action enforcement applies to placeholders the
	// same way it does to exact keys.
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "kms:DescribeKey",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"kms:EncryptionContext:tenant": "alice",
					},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"kms:EncryptionContext:tenant"`)
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_TemplateLiteral_Rejected(t *testing.T) {
	// A user who copy-pastes the AWS docs example verbatim ends up writing
	// the placeholder template ("${EncryptionContextKey}") as the literal
	// tail of the condition key. IAM doesn't expand "${...}" in condition
	// keys, so this never matches anything at evaluation time — it's
	// exactly the kind of typo strict mode exists to surface. The prefix
	// path must NOT silently accept it just because the leading bytes
	// agree with the declared prefix.
	c := withPlaceholderKeys(t)
	cases := []string{
		"kms:EncryptionContext:${EncryptionContextKey}", // verbatim docs paste
		"kms:EncryptionContext:${}",                     // empty-body template typo
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action": "kms:Encrypt",
						"Condition": map[string]any{
							"StringEquals": map[string]any{k: "x"},
						},
					},
				},
			}
			err := iamcatalog.CheckPolicy(context.Background(), c, policy)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "condition key")
		})
	}
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_LiteralDollarInValue_Accepted(t *testing.T) {
	// Sanity guard for the template-literal rejection: a user value that
	// happens to contain "${...}" somewhere past the leading byte (e.g. as
	// a substring inside an opaque tag value) must still be accepted. The
	// reject rule keys on the leading "${" only, so "prefix${literal}" in
	// the middle of a tail doesn't get caught.
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "kms:Encrypt",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"kms:EncryptionContext:tenant${literal}id": "alice",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_WildcardActionFallback(t *testing.T) {
	// "kms:*" doesn't narrow to one action, so we accept any condition key
	// the service declares anywhere — placeholder prefixes included.
	c := withPlaceholderKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "kms:*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"kms:EncryptionContext:tenant": "alice",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_TypeCheck(t *testing.T) {
	// The declared type on a placeholder key must apply to every user
	// instantiation under that prefix. Catalog declares
	// kms:EncryptionContext:${...} as String, so:
	//   - StringEquals on kms:EncryptionContext:foo passes
	//   - NumericEquals on kms:EncryptionContext:foo flags an operator
	//     mismatch, just like it would on a non-placeholder String key.
	c := withPlaceholderKeys(t)

	t.Run("StringEquals matches String type", func(t *testing.T) {
		policy := map[string]any{
			"Statement": []any{
				map[string]any{
					"Action": "kms:Encrypt",
					"Condition": map[string]any{
						"StringEquals": map[string]any{
							"kms:EncryptionContext:tenant": "alice",
						},
					},
				},
			},
		}
		require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
	})

	t.Run("NumericEquals mismatches String type", func(t *testing.T) {
		policy := map[string]any{
			"Statement": []any{
				map[string]any{
					"Action": "kms:Encrypt",
					"Condition": map[string]any{
						"NumericEquals": map[string]any{
							"kms:EncryptionContext:tenant": "1",
						},
					},
				},
			},
		}
		err := iamcatalog.CheckPolicy(context.Background(), c, policy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expects a Numeric key")
		assert.Contains(t, err.Error(), "is declared as String")
	})
}

func TestCheckPolicy_ConditionKey_PlaceholderKey_FromResource_Allowed(t *testing.T) {
	// Placeholder keys declared only via Actions[].Resources[].ConditionKeys
	// must also be merged into the per-action allowed set. The existing
	// exact-key merge path (TestCheckPolicy_ConditionKey_FromActionResource_Allowed)
	// confirmed it works for non-placeholder keys; this guards the placeholder
	// case the same way.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"DoThing": nil},
			actionResources: map[string][]string{"DoThing": {"widget"}},
			actionResourceKeys: map[string]map[string][]string{
				"DoThing": {"widget": {"svc:WidgetTag/${TagKey}"}},
			},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "svc:DoThing",
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"svc:WidgetTag/owner": "alice",
					},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionType_OperatorMatchesKeyType(t *testing.T) {
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"NumericLessThan": map[string]any{"s3:max-keys": "100"},
					"StringEquals":    map[string]any{"s3:prefix": "logs/"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionType_OperatorMismatch_Flagged(t *testing.T) {
	// s3:max-keys is Numeric in the catalog; StringEquals expects a String
	// key — this is a real mistake we want to surface.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"s3:max-keys": "100"},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `operator StringEquals expects a String key, but "s3:max-keys" is declared as Numeric`)
}

func TestCheckPolicy_ConditionType_OperatorModifiersStripped(t *testing.T) {
	// ForAllValues:/ForAnyValue: prefix and IfExists suffix don't change
	// the operator's expected type. The check should normalize them away
	// before looking up the type.
	c := withConditionKeys(t)
	cases := []string{
		"ForAllValues:StringEquals",
		"ForAnyValue:StringEquals",
		"StringEqualsIfExists",
		"ForAllValues:StringEqualsIfExists",
	}
	for _, op := range cases {
		t.Run(op, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action": "s3:ListBucket",
						"Condition": map[string]any{
							op: map[string]any{"s3:prefix": "logs/"},
						},
					},
				},
			}
			require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy), op)
		})
	}
}

func TestCheckPolicy_ConditionType_NullOperator_AcceptsAnyType(t *testing.T) {
	// "Null" tests for the presence/absence of a key — it works regardless
	// of the key's declared type, so Null on a Numeric key must pass.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"Null": map[string]any{"s3:max-keys": "true"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionType_AwsPrefixKey_SkipsTypeCheck(t *testing.T) {
	// AWS-global keys (aws:*) aren't in any service's catalog, so we don't
	// know their types. Skip the type check — better than false positives.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"aws:RequestedRegion": "us-east-1"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_FromActionResource_Allowed(t *testing.T) {
	// AWS lists many condition keys only under Actions[].Resources[].ConditionKeys —
	// they don't appear in ActionConditionKeys at all. ec2:CreateNetworkInterfacePermission
	// is the canonical example: its ActionConditionKeys is just ec2:Region, but
	// ec2:AuthorizedService is declared under its network-interface resource and
	// is the documented way to scope the permission. The validator has to merge
	// resource-level keys into the per-action allowed set or it will falsely
	// reject correct policies.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"DoThing": {"svc:Region"}},
			actionResources: map[string][]string{"DoThing": {"widget"}},
			actionResourceKeys: map[string]map[string][]string{
				"DoThing": {"widget": {"svc:WidgetOwner"}},
			},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "svc:DoThing",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"svc:WidgetOwner": "alice"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_FromTopLevelResource_Allowed(t *testing.T) {
	// Other services declare the resource's full ConditionKeys list only at
	// the top-level Resources[] entry and leave Actions[].Resources[].ConditionKeys
	// empty. Both shapes appear in production catalogs; the validator must
	// accept keys from either place when the action targets that resource type.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"DoThing": nil},
			actionResources: map[string][]string{"DoThing": {"widget"}},
			resources:       map[string][]string{"widget": {"arn:${Partition}:svc:::${Name}"}},
			resourceKeys:    map[string][]string{"widget": {"svc:WidgetOwner"}},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "svc:DoThing",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"svc:WidgetOwner": "alice"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionKey_ResourceLevel_StillRejectsUnknown(t *testing.T) {
	// Sanity: widening the allowed set with resource-level keys must not also
	// silently swallow genuine typos. A key not declared anywhere on the
	// action OR its resources is still flagged.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"DoThing": nil},
			actionResources: map[string][]string{"DoThing": {"widget"}},
			actionResourceKeys: map[string]map[string][]string{
				"DoThing": {"widget": {"svc:WidgetOwner"}},
			},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "svc:DoThing",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"svc:TotallyMadeUp": "x"},
				},
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `condition key "svc:TotallyMadeUp"`)
}

func TestCheckPolicy_ConditionKey_WildcardAction_IncludesResourceLevelKeys(t *testing.T) {
	// Wildcard action names fall back to svc.allKeys. Resource-level keys
	// must be merged into that union too, otherwise s3:* would silently lose
	// access to keys that real-but-unspecified actions need.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"DoThing": nil},
			actionResources: map[string][]string{"DoThing": {"widget"}},
			actionResourceKeys: map[string]map[string][]string{
				"DoThing": {"widget": {"svc:WidgetOwner"}},
			},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "svc:*",
				"Condition": map[string]any{
					"StringEquals": map[string]any{"svc:WidgetOwner": "alice"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_ConditionType_UnknownOperator_SkipsTypeCheck(t *testing.T) {
	// An operator we don't recognize (future AWS addition, or just garbage)
	// must not produce a type-mismatch flag. The keyspace check still
	// catches genuine typos in the key itself.
	c := withConditionKeys(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": "s3:ListBucket",
				"Condition": map[string]any{
					"FutureOperator": map[string]any{"s3:max-keys": "100"},
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

// withResources wires up a catalog where s3 has GetObject (object only),
// ListBucket (bucket only), and PutBucketPolicy (bucket only), each tied to
// the appropriate resource type with realistic ARN templates.
func withResources(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"s3": {
			actions: map[string][]string{
				"GetObject":       nil,
				"ListBucket":      nil,
				"PutBucketPolicy": nil,
			},
			actionResources: map[string][]string{
				"GetObject":       {"object"},
				"ListBucket":      {"bucket"},
				"PutBucketPolicy": {"bucket"},
			},
			resources: map[string][]string{
				"object": {"arn:${Partition}:s3:::${BucketName}/${ObjectName}"},
				"bucket": {"arn:${Partition}:s3:::${BucketName}"},
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_Resource_Valid(t *testing.T) {
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/key/path",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_BucketArnOnObjectAction_Rejected(t *testing.T) {
	// Classic mistake: writing a bucket-level ARN for an action that only
	// operates on objects. The catalog's ARN templates make this trivial
	// to catch (object template requires "/" + ObjectName).
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `resource "arn:aws:s3:::my-bucket"`)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCheckPolicy_Resource_BareStar(t *testing.T) {
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "*",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_BareStar_InsideList(t *testing.T) {
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": []any{"arn:aws:s3:::ok/key", "*"},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_WildcardWithinARN(t *testing.T) {
	// "arn:aws:s3:::*" is an IAM wildcard ARN. IAM treats '*' as "any
	// chars, including ':' and '/'", so the same value can satisfy
	// either the bucket template (when '*' expands to a bucket name)
	// or the object template (when '*' expands to "bucket/key"). The
	// validator follows IAM's semantics here: when strict matching
	// fails and the value carries '*' or '?', it falls back to a
	// language-intersection check. The bucket-vs-object distinction
	// is still enforced for *concrete* ARNs — see
	// TestCheckPolicy_Resource_BucketArnOnObjectAction_Rejected.
	c := withResources(t)
	for _, action := range []string{"s3:ListBucket", "s3:GetObject"} {
		t.Run(action, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action":   action,
						"Resource": "arn:aws:s3:::*",
					},
				},
			}
			require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
		})
	}
}

func TestCheckPolicy_Resource_MultipleActions_UnionsPatterns(t *testing.T) {
	// One ARN is a bucket, the other an object; with both ListBucket and
	// GetObject in the statement the union of their resource types covers
	// both.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:ListBucket", "s3:GetObject"},
				"Resource": []any{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/key"},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_WildcardActionFallsBackToServiceArns(t *testing.T) {
	// "s3:*" covers every s3 action; we can't narrow which resource types,
	// so use the service-wide union — every declared template.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:*",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_BareStarAction_SkipsCheck(t *testing.T) {
	// Action="*" spans every service, so we can't pin a service catalog.
	// The resource check skips, even when the ARN is nonsense.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "*",
				"Resource": "arn:nonsense:bad",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_NotResource_Skipped(t *testing.T) {
	// NotResource means "everything except these," which is the wrong
	// domain for matching against action ARN templates.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":      "s3:GetObject",
				"NotResource": "arn:aws:s3:::my-bucket",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_NetworkFailure_Surfaces(t *testing.T) {
	// Wildcard action skips checkOne's Lookup so the first network attempt
	// happens inside checkResources. The iamcatalog.ErrUnavailable must bubble out.
	c := iamcatalog.New("http://127.0.0.1:1")
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:Get*",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestCheckPolicy_Resource_WildcardServicePrefix_SkipsCheck(t *testing.T) {
	// "*:GetObject" can't be pinned to a single service catalog, so the
	// resource check bails — even if the ARN is obviously wrong.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "*:GetObject",
				"Resource": "arn:nonsense:bad",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_UnknownService_ContinuesEvaluation(t *testing.T) {
	// One action's service is a typo (continue past it), the other resolves;
	// the Resource must match the resolved service's patterns. checkOne
	// flags the typo separately.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"unknownsvc:Foo", "s3:GetObject"},
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err) // checkOne flags unknownsvc
	assert.Contains(t, err.Error(), "unknown AWS service prefix")
	assert.NotContains(t, err.Error(), "does not match", "valid s3 object ARN must still pass")
}

func TestCheckPolicy_Resource_NotActionStatement_Skipped(t *testing.T) {
	// NotAction means "every action except these," so we don't know which
	// resource templates to consult. checkResources skips.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"NotAction": "s3:GetObject",
				"Resource":  "arn:something:weird",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_ObjectArnOnBucketAction_Rejected(t *testing.T) {
	// The reverse of the bucket-on-object mistake: an object ARN given to
	// a bucket-only action. The bucket template ("...:::${BucketName}")
	// now declines to match because ${BucketName} no longer spans the "/"
	// separator. This is the case the regex tightening was added for.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:ListBucket",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `resource "arn:aws:s3:::my-bucket/key"`)
}

func TestCheckPolicy_Resource_ObjectKey_WithSlashes_Accepted(t *testing.T) {
	// S3 object keys legitimately contain "/". The last placeholder in a
	// template that has a "/" literal compiles greedily, so deeply nested
	// keys must still match.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/logs/2026/05/21/file.log",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_AllActionsUnresolved_SkipsCheck(t *testing.T) {
	// Single unknown-service action with a Resource. checkOne flags the
	// service typo; checkResources has no service catalog to consult, so
	// flagging the ARN (which would be perfectly valid against the
	// *intended* service) would be misleading.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "unknownsvc:Foo",
				"Resource": "arn:aws:s3:::my-bucket",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err) // checkOne still flags the unknown service
	assert.Contains(t, err.Error(), "unknown AWS service prefix")
	assert.NotContains(t, err.Error(), "does not match")
}

func TestCheckPolicy_Resource_AllActionsMalformed_SkipsCheck(t *testing.T) {
	// Malformed action (no colon) + Resource. checkOne flags the malformed
	// action; checkResources skips so we don't double-error.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "GetObject",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed action")
	assert.NotContains(t, err.Error(), "does not match")
}

// withServiceLevelAction wires up a service with one normal action (operates
// on a "thing" resource) and one service-level action whose service-reference
// Resources entry is absent. The fake server emits "Resources":[]; the live
// AWS catalog emits "Resources":null or omits the field entirely. encoding/
// json decodes [] to an empty (non-nil) slice and null/missing to nil, but
// our handling only looks at len(), where both shapes are equivalent — so
// the test exercises exactly the same code path checkResources hits in
// production for iam:ListUsers and friends.
func withServiceLevelAction(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions: map[string][]string{
				"WriteThing":    nil,
				"ListAllThings": nil,
			},
			actionResources: map[string][]string{
				"WriteThing": {"thing"},
				// "ListAllThings" omitted → "Resources":[] in the fake JSON.
				// The live catalog uses "Resources":null for the same case;
				// both decode to a zero-length slice, which is all the
				// per-action ARN check looks at.
			},
			resources: map[string][]string{
				"thing": {"arn:${Partition}:svc:::${Name}"},
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_Resource_ServiceLevelAction_AcceptsServiceShapedArn(t *testing.T) {
	// When the service reference declares an action with no Resources
	// (e.g. iam:ListUsers), IAM evaluates it at the account scope. The
	// AWS-documented "let users self-manage" pattern still pairs these
	// actions with a concrete IAM-shaped Resource ARN
	// ("arn:aws:iam::ACCOUNT:user/"); the validator must accept any
	// service-shaped ARN rather than rejecting against the empty
	// per-action pattern set.
	c := withServiceLevelAction(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:ListAllThings",
				"Resource": "arn:aws:svc:::main",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_ServiceLevelAction_RejectsCrossServiceArn(t *testing.T) {
	// The allArns fallback only widens within the same service. A
	// resource belonging to a different service is still flagged so
	// real cross-service typos don't slip through.
	c := withServiceLevelAction(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:ListAllThings",
				"Resource": "arn:aws:OTHERSVC:::main",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCheckPolicy_Resource_UnknownAction_NoDoubleFlag(t *testing.T) {
	// Typo'd action: checkOne reports it; checkResources falls back to the
	// service-wide ARN union so a valid s3 ARN doesn't ALSO get flagged as
	// "doesn't match" against an empty per-action pattern set.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:NotARealAction",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "NotARealAction"`)
	assert.NotContains(t, err.Error(), "does not match", "valid s3 ARN should not be flagged when only the action name is wrong")
}

// Direction 2 — Action-side enforcement. Direction 1 (Resource → Action)
// is exercised by the tests above; the cases below cover the mirror
// requirement: each Action listed in a Statement must have at least one
// Resource in that Statement whose ARN matches the action's templates.

func TestCheckPolicy_Resource_PerAction_OrphanedAction_Flagged(t *testing.T) {
	// The canonical mistake: s3:GetObject + s3:ListBucket together with only
	// an object ARN. ListBucket operates on the bucket itself, so no Resource
	// in the Statement matches its templates — it's silently orphaned.
	// Strict mode names the orphan so the user knows whether to add a bucket
	// ARN or drop ListBucket.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:GetObject", "s3:ListBucket"},
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `action "s3:ListBucket"`)
	assert.Contains(t, err.Error(), "has no resource that matches its ARN format")
	assert.Contains(t, err.Error(), "Statement[0]")
	// GetObject does have a matching resource — it must not be flagged.
	assert.NotContains(t, err.Error(), `action "s3:GetObject"`)
}

func TestCheckPolicy_Resource_PerAction_BareStarResource_CoversAllActions(t *testing.T) {
	// A bare "*" Resource grants every action in the Statement — direction 2
	// must short-circuit so the otherwise-orphaned action isn't flagged.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:GetObject", "s3:ListBucket"},
				"Resource": "*",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_BareStarInsideList_CoversAllActions(t *testing.T) {
	// "*" sitting alongside a concrete ARN inside the Resource list still
	// covers every action — the catch-all wins even when the concrete entry
	// only fits one of the listed actions.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:GetObject", "s3:ListBucket"},
				"Resource": []any{"arn:aws:s3:::my-bucket/key", "*"},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_BareStarAction_SkipsCheck(t *testing.T) {
	// Action="*" already bypasses checkResources entirely — direction 2 must
	// follow the same skip even though the Resource is plainly nonsense.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "*",
				"Resource": "arn:aws:s3:::my-bucket", // wrong for nothing in particular
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_WildcardServicePrefix_SkipsCheck(t *testing.T) {
	// "*:GetObject" can't be pinned to one service catalog, so the whole
	// resource check skips. Direction 2 must skip alongside direction 1.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "*:GetObject",
				"Resource": "arn:aws:s3:::my-bucket", // wrong shape — must not be flagged
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_WildcardActionName_UsesServiceWideArns(t *testing.T) {
	// "s3:*" widens to the full s3 ARN union. Even with a concrete bucket
	// ARN that no per-action set would accept on its own, the wildcard's
	// allArns view includes the bucket template, so the action is covered.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:*",
				"Resource": "arn:aws:s3:::my-bucket",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_WildcardAlongsideOrphanAction_StillFlagsOrphan(t *testing.T) {
	// "s3:*" alongside "s3:ListBucket" with only an object ARN. The
	// wildcard pulls in allArns (object + bucket templates) so it's
	// covered, but the concrete ListBucket action still constrains to the
	// bucket template — which no Resource matches. ListBucket stays
	// orphaned. Direction 2 must not let the wildcard's permissiveness
	// hide the concrete mismatch.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:*", "s3:ListBucket"},
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `action "s3:ListBucket"`)
	assert.NotContains(t, err.Error(), `action "s3:*"`)
}

func TestCheckPolicy_Resource_PerAction_MultipleOrphans_AllNamed(t *testing.T) {
	// When two actions are orphaned, both must appear in the error so the
	// user can fix the Statement in one pass rather than discovering each
	// orphan one at a time.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:GetObject", "s3:ListBucket", "s3:PutBucketPolicy"},
				"Resource": "arn:aws:s3:::my-bucket/key", // only object — both bucket-only actions orphan
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `action "s3:ListBucket"`)
	assert.Contains(t, err.Error(), `action "s3:PutBucketPolicy"`)
	assert.NotContains(t, err.Error(), `action "s3:GetObject"`)
}

func TestCheckPolicy_Resource_PerAction_NotActionStatement_Skipped(t *testing.T) {
	// NotAction means "every IAM action except these," so the listed entries
	// don't define a keyspace direction 2 can consult — the action-side check
	// would otherwise falsely orphan a resource that's perfectly valid for
	// one of the (unlisted, much larger) NotAction complement.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"NotAction": "s3:GetObject",
				"Resource":  "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_UnknownServiceMixed_KnownStillEnforced(t *testing.T) {
	// unknownsvc:Foo skips from the per-action set (checkOne reports it on
	// its own line); s3:ListBucket is still subject to direction 2 and
	// must be flagged when no matching Resource exists. The unknown
	// service must not silently absorb the orphan check for the known one.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"unknownsvc:Foo", "s3:ListBucket"},
				"Resource": "arn:aws:s3:::my-bucket/key", // object-only, ListBucket orphan
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown AWS service prefix")
	assert.Contains(t, err.Error(), `action "s3:ListBucket" has no resource`)
	// unknownsvc:Foo was skipped from the per-action set, so it must not
	// pick up a direction 2 "has no resource" line on top of the unknown-
	// service line. The substring `action "unknownsvc:Foo"` appears
	// inside checkOne's unknown-service message ("...in action
	// \"unknownsvc:Foo\""), so we anchor the negative assertion on the
	// direction 2 phrasing instead.
	assert.NotContains(t, err.Error(), `action "unknownsvc:Foo" has no resource`)
}

func TestCheckPolicy_Resource_PerAction_MultipleStatements_IndexedSeparately(t *testing.T) {
	// Each Statement is evaluated independently, and the error must carry
	// the Statement index so the user can locate which one to fix. The
	// good Statement must not produce a direction 2 line at all.
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:GetObject", "s3:ListBucket"},
				"Resource": "arn:aws:s3:::my-bucket/key", // orphans ListBucket
			},
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::other-bucket/key", // fine
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Statement[0]")
	assert.Contains(t, err.Error(), `action "s3:ListBucket"`)
	assert.NotContains(t, err.Error(), "Statement[1]")
}

func TestCheckPolicy_Resource_PerAction_DuplicateActionTokens_EmitOneOrphanLine(t *testing.T) {
	// Generated configs and copy-paste sometimes leave the same action token
	// in an Action list twice — or twice in different casing, since IAM
	// action names are case-insensitive. Direction 2 must emit one orphan
	// line per distinct action, not one per occurrence.
	c := withResources(t)
	for _, actions := range [][]any{
		{"s3:ListBucket", "s3:ListBucket"}, // identical spelling
		{"s3:ListBucket", "s3:listbucket"}, // action-name case differs
		{"s3:ListBucket", "S3:ListBucket"}, // service-prefix case differs
	} {
		t.Run(fmt.Sprint(actions...), func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{
						"Action":   actions,
						"Resource": "arn:aws:s3:::my-bucket/key", // orphans ListBucket
					},
				},
			}
			err := iamcatalog.CheckPolicy(context.Background(), c, policy)
			require.Error(t, err)
			count := strings.Count(err.Error(), "has no resource that matches")
			assert.Equal(t, 1, count, "expected one direction 2 line, got:\n%s", err.Error())
		})
	}
}

func TestCheckPolicy_Resource_PerAction_FullyCoveredPairs_ShortCircuit(t *testing.T) {
	// When every Resource and every Action already has its "matched" bit
	// set, subsequent pair iterations must skip the inner regex work — the
	// optimization that lets the matching loop decay toward the old pooled-
	// patterns cost in well-formed policies. Two bucket-only actions paired
	// with two bucket ARNs exercises the late-iteration "both already true"
	// branch (the last pair sees resourceMatched and actionCovered both
	// already set from earlier pairs).
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   []any{"s3:ListBucket", "s3:PutBucketPolicy"},
				"Resource": []any{"arn:aws:s3:::bucket-one", "arn:aws:s3:::bucket-two"},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_PerAction_ServiceWithoutArns_SkipsActionCheck(t *testing.T) {
	// Defensive: a service whose catalog declares zero ARN templates
	// anywhere yields an empty per-action pattern set. Without info to
	// enforce against, direction 2 must skip — matching the same
	// "no info → don't double-flag" philosophy checkOne already uses
	// for unknown actions. A real AWS catalog won't produce this shape,
	// but the validator must not flag the action if it ever did.
	//
	// Two sub-cases exercise the skip from different angles:
	//   - bare "*" Resource: direction 2 short-circuits before reaching
	//     the empty-patterns guard at all (hasBareStar wins).
	//   - concrete Resource: direction 1 flags it ("no ARN format"), but
	//     direction 2 hits the empty-patterns continue and the action
	//     must NOT additionally appear in the error.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions: map[string][]string{"DoThing": nil},
			// no actionResources, no resources → allArns and per-action ARNs
			// are both empty.
		},
	})
	c := iamcatalog.New(fs.server.URL)

	t.Run("bare star resource", func(t *testing.T) {
		policy := map[string]any{
			"Statement": []any{
				map[string]any{
					"Action":   "svc:DoThing",
					"Resource": "*",
				},
			},
		}
		require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
	})

	t.Run("concrete resource — direction 2 still skips the empty action", func(t *testing.T) {
		policy := map[string]any{
			"Statement": []any{
				map[string]any{
					"Action":   "svc:DoThing",
					"Resource": "arn:aws:svc:::anything",
				},
			},
		}
		err := iamcatalog.CheckPolicy(context.Background(), c, policy)
		// Direction 1 flags the resource (no pattern to match against).
		require.Error(t, err)
		assert.Contains(t, err.Error(), `resource "arn:aws:svc:::anything"`)
		// Direction 2 must NOT also flag the action — len(patterns)==0
		// short-circuits the per-action check.
		assert.NotContains(t, err.Error(), `action "svc:DoThing" has no resource`)
	})
}

func TestCheckPolicy_Resource_PerAction_SingleAction_BothDirectionsReportConflict(t *testing.T) {
	// When the only action and the only resource conflict, both directions
	// detect the same mismatch from opposite angles: direction 1 names the
	// resource, direction 2 names the action. The wording is intentionally
	// distinct — readers should see both perspectives, not a single line
	// that hides which side of the pair is "wrong."
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket", // bucket on object-only action
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `resource "arn:aws:s3:::my-bucket" does not match`)
	assert.Contains(t, err.Error(), `action "s3:GetObject" has no resource`)
}

// withColonExtendedTemplates wires up a service whose long template extends
// the short one with ':' rather than '/'. This mirrors the CloudWatch Logs
// pair (log-group → log-stream) where log-group names contain '/' and the
// log-stream template adds ":log-stream:..." rather than "/...". The
// resource validator's heuristic must let the last placeholder of the short
// template span '/'.
func withColonExtendedTemplates(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions: map[string][]string{
				"WriteGroup": nil,
				"WriteSub":   nil,
			},
			actionResources: map[string][]string{
				"WriteGroup": {"group"},
				"WriteSub":   {"sub"},
			},
			resources: map[string][]string{
				"group": {"arn:${Partition}:svc:${Region}:${Account}:group:${GroupName}"},
				"sub":   {"arn:${Partition}:svc:${Region}:${Account}:group:${GroupName}:sub:${SubName}"},
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_Resource_ColonExtendedSibling_LastPlaceholderAllowsSlash(t *testing.T) {
	// The short template's last placeholder must span '/' because the long
	// sibling extends with ':' (not '/'). Real-world shape: a CloudWatch
	// Logs log-group ARN whose name is "/aws/codebuild/foo" — the old
	// "[^:/]*" rule rejected it as not matching any ARN format.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteGroup",
				"Resource": "arn:aws:svc:r:a:group:/path/to/foo",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_IntermediatePlaceholder_AllowsSlash(t *testing.T) {
	// Non-last placeholder followed by ':' (not '/') gets "[^:]*", so values
	// containing '/' must match. Real-world shape: the log-stream ARN
	// "...:group:<GroupName>:sub:<SubName>" where <GroupName> is a slash-
	// containing log-group name like "/aws/codebuild/foo".
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteSub",
				"Resource": "arn:aws:svc:r:a:group:/path/to/foo:sub:bar",
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_IamWildcardSpansColon(t *testing.T) {
	// IAM treats '*' as "any chars including ':' and '/'". The canonical
	// CodeBuild-style policy uses
	//   "...:group:/path/to/foo:*"
	// to mean "the group plus all sub-resources." The short (group)
	// template's last placeholder must be greedy enough for this to
	// match — otherwise valid IAM policies are falsely rejected. Union
	// semantics let it match against the group template even though the
	// statement also lists actions that target the sub resource type.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"svc:WriteGroup", "svc:WriteSub"},
				"Resource": []any{
					"arn:aws:svc:r:a:group:/path/to/foo:*",
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_IamWildcard_SpansColonExtensionLiteral(t *testing.T) {
	// When the action only targets the long resource (e.g. log-stream), the
	// user often writes the short-template prefix plus an IAM ":*" tail —
	// expecting IAM to expand ":*" over the literal ":sub:<name>" segment
	// the long template requires. Strict regex matching can't honor that
	// (':' is a hard separator), so the validator falls back to the
	// language-intersection check.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"svc:WriteSub"},
				"Resource": []any{
					"arn:aws:svc:r:a:group:/path/to/foo:*",
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_IamWildcard_BroadServicePrefix(t *testing.T) {
	// "arn:aws:svc:*:*:*" is a fully-wildcarded ARN — every segment after
	// the service prefix is '*'. IAM expands these wildcards over the
	// template's literal anchors (":group:" etc.), so the validator must
	// accept it via the intersection check rather than insisting on the
	// literal anchors appearing in the user value.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action": []any{"svc:WriteGroup", "svc:WriteSub"},
				"Resource": []any{
					"arn:aws:svc:*:*:*",
				},
			},
		},
	}
	require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_IamWildcard_RejectsCrossServiceMismatch(t *testing.T) {
	// The intersection fallback must still reject obvious typos. A
	// wildcard-laden ARN that names the wrong service in its literal
	// prefix can't be a valid expansion of the template, no matter how
	// far IAM '*' is allowed to span.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteGroup",
				"Resource": "arn:aws:OTHERSVC:r:a:group:/path:*",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCheckPolicy_Resource_IamWildcard_RejectsConcreteMismatch(t *testing.T) {
	// Sanity: a concrete ARN (no '*' / '?') still goes through the strict
	// path; the intersection fallback must not engage when there are no
	// wildcards to expand.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteGroup",
				"Resource": "arn:aws:OTHERSVC:r:a:group:/path/to/foo",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCheckPolicy_Resource_ColonExtendedSibling_RejectsConcreteChildShape(t *testing.T) {
	// The colon-extended fix relaxes the short template's last placeholder
	// to span '/' (so log-group names with slashes pass) and to accept IAM
	// wildcard tails like ":*". It must NOT also accept *concrete* ARNs
	// whose suffix looks like the long template's structure — e.g. a real
	// log-stream ARN paired with a log-group-only action like
	// CreateLogGroup. Without this guard the validator would silently lose
	// its action/resource-type mismatch check for colon-extended families.
	c := withColonExtendedTemplates(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteGroup",
				"Resource": "arn:aws:svc:r:a:group:/path/to/foo:sub:bar",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCheckPolicy_Resource_SlashExtendedSibling_LastPlaceholderStaysBounded(t *testing.T) {
	// Regression guard: when a sibling extends with "/<X>" (not ':<X>'),
	// the short template's last placeholder must remain bounded to "[^:/]*"
	// so an ARN containing '/' is correctly diagnosed as belonging to the
	// long template, not the short one. Mirrors S3 bucket-vs-object.
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions:         map[string][]string{"WriteShort": nil},
			actionResources: map[string][]string{"WriteShort": {"short"}},
			resources: map[string][]string{
				"short": {"arn:${Partition}:svc:::${Name}"},
				"long":  {"arn:${Partition}:svc:::${Name}/${SubName}"},
			},
		},
	})
	c := iamcatalog.New(fs.server.URL)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:WriteShort",
				"Resource": "arn:aws:svc:::main/sub",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

// withLambdaShape wires up a service with a base "function" resource and
// a colon-extension "function-alias" sibling — the structural shape AWS
// uses for Lambda function vs function-alias / function-version. Used by
// the qualifier-tail end-to-end tests below.
func withLambdaShape(t *testing.T) *iamcatalog.Catalog {
	t.Helper()
	fs := newFakeServerWithKeys(t, map[string]fakeServiceData{
		"svc": {
			actions: map[string][]string{
				"InvokeThing": nil,
			},
			actionResources: map[string][]string{
				"InvokeThing": {"thing"}, // base resource only, mirroring lambda:InvokeFunction
			},
			resources: map[string][]string{
				"thing":         {"arn:${Partition}:svc:${Region}:${Account}:thing:${ThingName}"},
				"thing-alias":   {"arn:${Partition}:svc:${Region}:${Account}:thing:${ThingName}:${Alias}"},
				"thing-version": {"arn:${Partition}:svc:${Region}:${Account}:thing:${ThingName}:${Version}"},
			},
		},
	})
	return iamcatalog.New(fs.server.URL)
}

func TestCheckPolicy_Resource_QualifierTail_Accepted(t *testing.T) {
	// The base "thing" resource has colon-extending siblings ("thing:${A}",
	// "thing:${V}"). IAM accepts qualified ARNs on the base action, and the
	// strict validator should too — even though the catalog only lists the
	// base resource type against the action.
	c := withLambdaShape(t)
	for _, arn := range []string{
		"arn:aws:svc:us-east-1:123456789012:thing:my-thing",
		"arn:aws:svc:us-east-1:123456789012:thing:my-thing:my-alias",
		"arn:aws:svc:us-east-1:123456789012:thing:my-thing:5",
		"arn:aws:svc:us-east-1:123456789012:thing:my-thing:$LATEST",
		"arn:aws:svc:us-east-1:123456789012:thing:my-thing:*",
	} {
		t.Run(arn, func(t *testing.T) {
			policy := map[string]any{
				"Statement": []any{
					map[string]any{"Action": "svc:InvokeThing", "Resource": arn},
				},
			}
			require.NoError(t, iamcatalog.CheckPolicy(context.Background(), c, policy))
		})
	}
}

func TestCheckPolicy_Resource_QualifierTail_RejectsTwoDeep(t *testing.T) {
	// AWS only nests one qualifier level (alias or version). A second
	// colon-separated segment after the qualifier doesn't correspond to any
	// real AWS form and must still be flagged.
	c := withLambdaShape(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "svc:InvokeThing",
				"Resource": "arn:aws:svc:us-east-1:123456789012:thing:my-thing:alias:extra",
			},
		},
	}
	err := iamcatalog.CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any ARN format")
}

func TestCompileARNTemplate_MalformedReturnsNil(t *testing.T) {
	// An unterminated ${ should not panic or compile garbage; the parser
	// returns nil and the caller drops the template.
	assert.Nil(t, iamcatalog.CompileARNTemplate("arn:${broken", nil))
}

func TestCompileARNTemplate_ColonExtendedSiblingAllowsQualifierTail(t *testing.T) {
	// Lambda's "function:${F}" base has a "function:${F}:${Alias}" sibling.
	// The colon-extension means the base regex must accept "function:f" and
	// "function:f:my-alias" but reject "function:f:alias:typo" (AWS doesn't
	// have two-deep qualifiers). The literal IAM wildcard form ":*" continues
	// to work via the new regex's "[^:]+" segment.
	base := "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}"
	alias := "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}:${Alias}"
	re := iamcatalog.CompileARNTemplate(base, []string{base, alias})
	require.NotNil(t, re)
	for _, ok := range []string{
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn:my-alias",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn:5",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn:*",
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn*",
	} {
		assert.True(t, re.MatchString(ok), "should match: %s", ok)
	}
	for _, bad := range []string{
		"arn:aws:lambda:us-east-1:123456789012:function:my-fn:alias:extra",
		"arn:aws:s3:::not-lambda", // wrong service
	} {
		assert.False(t, re.MatchString(bad), "should NOT match: %s", bad)
	}
}

func TestCompileARNTemplate_LiteralBetweenColonSiblingKeepsRule4(t *testing.T) {
	// CloudWatch Logs log-group's sibling extends with ":log-stream:${LS}" —
	// the literal "log-stream" between the colon and the next "${" means
	// rule 3a does NOT fire. Rule 4 stays in force and the only colon-tail
	// accepted on the base is the IAM wildcard ":*" / ":?". A concrete
	// "<group>:log-stream:<stream>" must still fail against the log-group
	// template (it has to match log-stream's own template instead).
	base := "arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}"
	stream := "arn:${Partition}:logs:${Region}:${Account}:log-group:${LogGroupName}:log-stream:${LogStreamName}"
	re := iamcatalog.CompileARNTemplate(base, []string{base, stream})
	require.NotNil(t, re)
	assert.True(t, re.MatchString("arn:aws:logs:us-east-1:1:log-group:/aws/codebuild/foo"))
	assert.True(t, re.MatchString("arn:aws:logs:us-east-1:1:log-group:/aws/codebuild/foo:*"))
	// log-stream form must NOT match the log-group base.
	assert.False(t, re.MatchString("arn:aws:logs:us-east-1:1:log-group:foo:log-stream:bar"))
	// A literal qualifier tail (no wildcard) must NOT match the base either —
	// rule 4 only allows IAM wildcard tails.
	assert.False(t, re.MatchString("arn:aws:logs:us-east-1:1:log-group:foo:bar"))
}

func TestSplitPlaceholderKey(t *testing.T) {
	// Direct unit test for the placeholder-tail detector. The integration
	// tests above exercise the happy path through CheckPolicy, but the
	// defensive branches (missing "${" opener, unsupported separator) need
	// targeted coverage to stay honest about what's verified.
	cases := []struct {
		in     string
		prefix string
		ok     bool
	}{
		// Happy path: both colon and slash separators with a real placeholder.
		{"kms:EncryptionContext:${EncryptionContextKey}", "kms:EncryptionContext:", true},
		{"s3:ExistingObjectTag/${key}", "s3:ExistingObjectTag/", true},

		// Exact-match keys (no placeholder tail) — fall through cleanly.
		{"s3:prefix", "", false},
		{"sts:RoleSessionName", "", false},
		{"", "", false},

		// Defensive branches: trailing '}' but no "${" opener, or the opener
		// sits at position 0 with no prefix to keep. Real catalogs don't
		// produce these shapes, but the early-out keeps the validator from
		// inventing a meaningless prefix if AWS ever ships oddly-formed data.
		{"foo}", "", false},
		{"${EncryptionContextKey}", "", false},

		// Defensive: '${' is present but the immediately preceding rune is
		// not the ':' or '/' separator we recognize. Treating this as an
		// exact key avoids silently turning a typo'd key into a prefix.
		{"kms:EncryptionContext${EncryptionContextKey}", "", false},
		{"kms.EncryptionContext:${X}", "kms.EncryptionContext:", true},
		{"foo.bar${X}", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			p, ok := iamcatalog.SplitPlaceholderKey(tc.in)
			assert.Equal(t, tc.ok, ok, "ok mismatch")
			assert.Equal(t, tc.prefix, p, "prefix mismatch")
		})
	}
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
		p, n, ok := iamcatalog.SplitAction(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.prefix, p, tc.in)
		assert.Equal(t, tc.name, n, tc.in)
	}
}
