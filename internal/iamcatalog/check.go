package iamcatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CheckPolicy walks the IAM policy and runs catalog-backed checks against the
// AWS service reference. It is designed to be called *after* schema validation
// has already passed, so structural shapes are assumed valid. Two checks run:
//
//  1. Every Action / NotAction names a real service and a real action.
//
//  2. Every key inside Condition is one that the statement's actions actually
//     consume. Keys with the "aws:" prefix are AWS-global and always allowed;
//     service-specific keys must appear in the union of allowed keys for the
//     statement's actions (per-action ActionConditionKeys, falling back to
//     the service-wide ConditionKeys list when the action is a wildcard).
//
// Wildcard tokens (the bare "*", or "*" anywhere within a service:action pair)
// are out of scope: pattern expansion against the catalog isn't implemented,
// so we don't try to validate them. Strings that are neither "*" nor
// "service:action" shape are rejected outright — the JSON Schema only checks
// that Action is a string, so it's our job here to catch values like
// "GetObject" (missing the service prefix).
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

// checkConditions validates that every key in Statement.Condition is one the
// statement's actions actually consume. Returns (issues, err). A non-nil err
// is ErrUnavailable; CheckPolicy bubbles it up directly. Wildcard actions
// (bare "*" or "*:Foo") yield no issues — pattern expansion is out of scope.
func checkConditions(ctx context.Context, c *Catalog, stmt map[string]any, stmtIdx int) ([]string, error) {
	cond, _ := stmt["Condition"].(map[string]any)
	if len(cond) == 0 {
		return nil, nil
	}
	actions := actionsOf(stmt)
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
