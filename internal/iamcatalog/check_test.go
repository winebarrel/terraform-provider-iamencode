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
			svcKeyTypes: map[string]string{
				"s3:prefix":   "String",
				"s3:max-keys": "Numeric",
			},
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

func TestCheckPolicy_ConditionKey_NetworkFailure_FromCheckConditionsPath(t *testing.T) {
	// Wildcard action names skip checkOne's Lookup, so the first time the
	// catalog is consulted for this prefix is inside checkConditions. If
	// the catalog is unreachable that error must propagate out of
	// CheckPolicy — exercising the err branch in checkConditions itself.
	c := New("http://127.0.0.1:1")
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
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
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
	err := CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))

	// And a typo in NotAction is still caught by checkOne even though
	// checkConditions skipped.
	policy["Statement"].([]any)[0].(map[string]any)["NotAction"] = "s3:GetObjectx"
	err := CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	err := CheckPolicy(context.Background(), c, policy)
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
			require.NoError(t, CheckPolicy(context.Background(), c, policy), op)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

// withResources wires up a catalog where s3 has GetObject (object only),
// ListBucket (bucket only), and PutBucketPolicy (bucket only), each tied to
// the appropriate resource type with realistic ARN templates.
func withResources(t *testing.T) *Catalog {
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
	return New(fs.server.URL)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	err := CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_WildcardWithinARN(t *testing.T) {
	// "arn:aws:s3:::*" is a valid IAM wildcard for "any bucket" — the
	// catalog's bucket template matches it as a bucket-level ARN. For
	// GetObject (object-only) it shouldn't match, since the object template
	// requires "/${ObjectName}".
	c := withResources(t)
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:ListBucket",
				"Resource": "arn:aws:s3:::*",
			},
		},
	}
	require.NoError(t, CheckPolicy(context.Background(), c, policy))

	policy["Statement"].([]any)[0].(map[string]any)["Action"] = "s3:GetObject"
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "arn:aws:s3:::*")
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
}

func TestCheckPolicy_Resource_NetworkFailure_Surfaces(t *testing.T) {
	// Wildcard action skips checkOne's Lookup so the first network attempt
	// happens inside checkResources. The ErrUnavailable must bubble out.
	c := New("http://127.0.0.1:1")
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:Get*",
				"Resource": "arn:aws:s3:::my-bucket/key",
			},
		},
	}
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	err := CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	err := CheckPolicy(context.Background(), c, policy)
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
	require.NoError(t, CheckPolicy(context.Background(), c, policy))
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
	err := CheckPolicy(context.Background(), c, policy)
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
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed action")
	assert.NotContains(t, err.Error(), "does not match")
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
	err := CheckPolicy(context.Background(), c, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown action "NotARealAction"`)
	assert.NotContains(t, err.Error(), "does not match", "valid s3 ARN should not be flagged when only the action name is wrong")
}

func TestCompileARNTemplate_MalformedReturnsNil(t *testing.T) {
	// An unterminated ${ should not panic or compile garbage; the parser
	// returns nil and the caller drops the template.
	assert.Nil(t, compileARNTemplate("arn:${broken"))
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
