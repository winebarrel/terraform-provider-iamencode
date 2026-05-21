package iamcatalog

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CheckPolicy walks the IAM policy and runs catalog-backed checks against the
// AWS service reference. It is designed to be called *after* schema validation
// has already passed, so structural shapes are assumed valid. Three checks run:
//
//  1. Action existence. Non-wildcard Action/NotAction values like "s3:GetObject"
//     are verified against the catalog — both the service prefix and the
//     action name must exist. Any wildcard ("*", "s3:*", "s3:Get*",
//     "*:GetObject") is accepted without catalog lookup; we don't try to
//     expand patterns against the catalog.
//
//  2. Condition keys. Each key under Condition is checked against the union
//     of condition keys the statement's actions consume. Keys with the
//     "aws:" prefix are AWS-global and always pass; service-specific keys
//     are looked up per action (so "s3:prefix" passes on "s3:ListBucket"
//     but fails on "s3:GetObject"). Wildcards behave asymmetrically here:
//     a wildcard *name* like "s3:*" or "s3:Get*" falls back to the service-
//     wide ConditionKeys union, while a wildcard *service prefix* like
//     "*:GetObject" or the bare "*" skip the condition check entirely
//     because no single service catalog can be selected.
//
//  3. Resource ARNs. Each Resource value must match one of the ARN templates
//     declared for at least one of the statement's actions (e.g. a bucket
//     ARN doesn't pass on s3:GetObject — that action only operates on object
//     ARNs). The bare "*" Resource always passes. Wildcards in Action follow
//     the same scheme as the condition-key check: wildcard names use the
//     service-wide union of ARN formats, while a wildcard service prefix or
//     bare "*" Action skip the check entirely. NotResource statements skip
//     the check too (their semantics invert the keyspace).
//
// Strings that are neither "*" nor "service:action" shape (e.g. plain
// "GetObject" with no colon) are rejected outright — the JSON Schema only
// checks that Action is a string, so this is where we catch missing prefixes.
//
// Errors surface, they don't get swallowed:
//   - ErrUnknownService (a typo'd prefix) — reported per-action; the rest of
//     the statement is still evaluated so other typos still come out.
//   - ErrUnavailable (the catalog endpoint is unreachable) — surfaces as a
//     hard error from CheckPolicy. The whole point of policy_strict is to
//     consult the catalog; without it the function cannot do its job.
//
// A nil catalog is the one exception: it's a defensive guard for default-
// constructed PolicyStrictFunction values in tests, not a graceful-degrade
// path. Production always sets a real catalog.
func CheckPolicy(ctx context.Context, c *Catalog, policy any) error {
	if c == nil {
		return nil
	}
	stmts := statements(policy)
	var issues []string
	for i, s := range stmts {
		for _, a := range actionsOf(s) {
			msg, err := checkOne(ctx, c, a, i)
			if err != nil {
				return err
			}
			if msg != "" {
				issues = append(issues, msg)
			}
		}
		condIssues, err := checkConditions(ctx, c, s, i)
		if err != nil {
			return err
		}
		issues = append(issues, condIssues...)
		resIssues, err := checkResources(ctx, c, s, i)
		if err != nil {
			return err
		}
		issues = append(issues, resIssues...)
	}
	if len(issues) == 0 {
		return nil
	}
	return errors.New(strings.Join(issues, "\n"))
}

// checkOne validates a single Action/NotAction string. Returns (issue, err).
// A non-nil err is ErrUnavailable, meaning the catalog itself is unreachable
// — CheckPolicy bubbles it up directly so the user sees one clear message
// instead of one per failed Lookup.
func checkOne(ctx context.Context, c *Catalog, action string, stmtIndex int) (string, error) {
	if action == "*" {
		return "", nil // the all-actions wildcard — valid IAM, nothing to check
	}
	prefix, name, ok := splitAction(action)
	if !ok {
		return fmt.Sprintf("Statement[%d]: malformed action %q (expected \"service:action\" or \"*\")", stmtIndex, action), nil
	}
	if strings.ContainsRune(prefix, '*') || strings.ContainsRune(name, '*') {
		return "", nil // wildcards: out of scope for the catalog check
	}
	svc, err := c.Lookup(ctx, prefix)
	switch {
	case errors.Is(err, ErrUnavailable):
		return "", err
	case errors.Is(err, ErrUnknownService):
		return fmt.Sprintf("Statement[%d]: unknown AWS service prefix %q in action %q", stmtIndex, prefix, action), nil
	case err != nil:
		return "", err
	}
	if !svc.HasAction(name) {
		return fmt.Sprintf("Statement[%d]: unknown action %q for service %q", stmtIndex, name, prefix), nil
	}
	return "", nil
}

// statements normalizes the two valid Statement shapes (single object / array
// of objects) into a flat slice. Returns nil for anything else; schema
// validation should have rejected it before we reach this point.
func statements(policy any) []map[string]any {
	root, ok := policy.(map[string]any)
	if !ok {
		return nil
	}
	switch s := root["Statement"].(type) {
	case map[string]any:
		return []map[string]any{s}
	case []any:
		out := make([]map[string]any, 0, len(s))
		for _, e := range s {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// actionsOf collects Action and NotAction values from a statement. Each may be
// a string or a list of strings.
func actionsOf(stmt map[string]any) []string {
	var out []string
	out = appendStringOrList(out, stmt["Action"])
	out = appendStringOrList(out, stmt["NotAction"])
	return out
}

func appendStringOrList(out []string, v any) []string {
	switch x := v.(type) {
	case string:
		return append(out, x)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// checkConditions validates that every key in Statement.Condition is one that
// the statement's actions actually consume. Returns (issues, err). A non-nil
// err is ErrUnavailable; CheckPolicy bubbles it up directly.
//
// Wildcards are handled asymmetrically by design:
//   - Bare "*" or a wildcard service prefix ("*:GetObject") skip the whole
//     condition check — no single service catalog can be selected.
//   - A wildcard action name ("s3:*", "s3:Get*") DOES proceed: we look up
//     the service and use its service-wide ConditionKeys union (svc.allKeys)
//     in place of per-action keys.
//
// Only positive Action entries drive the keyspace. A NotAction statement
// means "every IAM action except these," so validating its Condition keys
// against the listed exclusions would be backwards (a key valid for any of
// the other 10,000 actions would get falsely flagged). For NotAction-only
// statements we skip the check.
func checkConditions(ctx context.Context, c *Catalog, stmt map[string]any, stmtIdx int) ([]string, error) {
	cond, _ := stmt["Condition"].(map[string]any)
	if len(cond) == 0 {
		return nil, nil
	}
	actions := appendStringOrList(nil, stmt["Action"])
	if len(actions) == 0 {
		return nil, nil
	}

	allowed := make(map[string]struct{})
	for _, a := range actions {
		if a == "*" {
			return nil, nil // can't narrow which keys are valid
		}
		prefix, name, ok := splitAction(a)
		if !ok {
			continue // checkOne already flags malformed actions
		}
		if strings.ContainsRune(prefix, '*') {
			return nil, nil // wildcard service → can't constrain
		}
		svc, err := c.Lookup(ctx, prefix)
		switch {
		case errors.Is(err, ErrUnavailable):
			return nil, err
		case errors.Is(err, ErrUnknownService):
			// Typo'd prefix: this action contributes nothing to the allowed
			// set, but we keep evaluating so condition keys are still
			// validated against the actions whose services did resolve.
			// checkOne reports the unknown prefix on its own line.
			continue
		case err != nil || svc == nil:
			return nil, err
		}
		var keys map[string]struct{}
		if strings.ContainsRune(name, '*') {
			keys = svc.allKeys
		} else if perAction, has := svc.keysByAction[strings.ToLower(name)]; has {
			keys = perAction
		} else {
			keys = svc.allKeys
		}
		for k := range keys {
			allowed[k] = struct{}{}
		}
	}

	var issues []string
	for opName, op := range cond {
		operands, ok := op.(map[string]any)
		if !ok {
			continue
		}
		for key := range operands {
			lk := strings.ToLower(key)
			if strings.HasPrefix(lk, "aws:") {
				continue // AWS-global condition keys are always allowed
			}
			if _, ok := allowed[lk]; ok {
				continue
			}
			issues = append(issues, fmt.Sprintf(
				"Statement[%d]: condition key %q (under %s) is not valid for the statement's actions",
				stmtIdx, key, opName))
		}
	}
	return issues, nil
}

// checkResources validates that each Resource ARN matches one of the ARN
// templates declared by at least one of the statement's actions. Returns
// (issues, err) where err is ErrUnavailable. Wildcards skip in the same
// pattern as checkConditions: wildcard service prefix or bare "*" Action
// skips the whole check; wildcard action name falls back to the service-
// wide union of ARN formats. NotResource statements skip entirely — the
// listed exclusions are the wrong domain to validate against.
func checkResources(ctx context.Context, c *Catalog, stmt map[string]any, stmtIdx int) ([]string, error) {
	resources := appendStringOrList(nil, stmt["Resource"])
	if len(resources) == 0 {
		return nil, nil
	}
	actions := appendStringOrList(nil, stmt["Action"])
	if len(actions) == 0 {
		return nil, nil
	}

	patterns := make([]*regexp.Regexp, 0)
	for _, a := range actions {
		if a == "*" {
			return nil, nil
		}
		prefix, name, ok := splitAction(a)
		if !ok {
			continue
		}
		if strings.ContainsRune(prefix, '*') {
			return nil, nil
		}
		svc, err := c.Lookup(ctx, prefix)
		switch {
		case errors.Is(err, ErrUnavailable):
			return nil, err
		case errors.Is(err, ErrUnknownService):
			continue
		case err != nil || svc == nil:
			return nil, err
		}
		if strings.ContainsRune(name, '*') {
			patterns = append(patterns, svc.allArns...)
			continue
		}
		if perAction, has := svc.arnsByAction[strings.ToLower(name)]; has {
			patterns = append(patterns, perAction...)
		} else {
			// Unknown action (typo). checkOne reports the action separately;
			// fall back to the service-wide union here so a typo'd action
			// doesn't also trigger a misleading "resource doesn't match"
			// error against an empty pattern set.
			patterns = append(patterns, svc.allArns...)
		}
	}

	var issues []string
	for _, r := range resources {
		if r == "*" {
			continue // catch-all is always valid
		}
		matched := false
		for _, p := range patterns {
			if p.MatchString(r) {
				matched = true
				break
			}
		}
		if !matched {
			issues = append(issues, fmt.Sprintf(
				"Statement[%d]: resource %q does not match any ARN format for the statement's actions",
				stmtIdx, r))
		}
	}
	return issues, nil
}

// splitAction parses "service:action" into its parts. Returns ok=false when
// the input has zero or multiple colons, or when either half is empty.
// IAM action names always have exactly one colon; accepting more would let
// strings like "s3:*:foo" slip past the strict check via the wildcard branch.
func splitAction(a string) (prefix, name string, ok bool) {
	if strings.Count(a, ":") != 1 {
		return "", "", false
	}
	i := strings.IndexByte(a, ':')
	if i == 0 || i == len(a)-1 {
		return "", "", false
	}
	return a[:i], a[i+1:], true
}
