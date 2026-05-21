package iamcatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// CheckActions walks the IAM policy and verifies that every Action / NotAction
// names a real service and a real action via the AWS service reference. It is
// designed to be called *after* schema validation has already passed, so the
// shapes (Statement object-or-array, Action string-or-array) are assumed valid.
//
// Wildcard tokens ("*" anywhere in the prefix or name) are skipped — matching
// wildcards against the catalog would require pattern expansion that we don't
// want to take on yet.
//
// Network failures degrade gracefully: ErrUnavailable from a lookup skips that
// action rather than failing the whole call. Only "definitely a typo" results
// (ErrUnknownService, unknown action under a known service) surface as errors.
func CheckActions(ctx context.Context, c *Catalog, policy any) error {
	stmts := statements(policy)
	var issues []string
	for i, s := range stmts {
		for _, a := range actionsOf(s) {
			if msg := checkOne(ctx, c, a, i); msg != "" {
				issues = append(issues, msg)
			}
		}
	}
	if len(issues) == 0 {
		return nil
	}
	return errors.New(strings.Join(issues, "\n"))
}

func checkOne(ctx context.Context, c *Catalog, action string, stmtIndex int) string {
	prefix, name, ok := splitAction(action)
	if !ok {
		return "" // not "service:action" shape — schema would have caught real malformations
	}
	if strings.ContainsRune(prefix, '*') || strings.ContainsRune(name, '*') {
		return "" // wildcards: out of scope for the catalog check
	}
	svc, err := c.Lookup(ctx, prefix)
	switch {
	case errors.Is(err, ErrUnavailable):
		return "" // graceful degrade
	case errors.Is(err, ErrUnknownService):
		return fmt.Sprintf("Statement[%d]: unknown AWS service prefix %q in action %q", stmtIndex, prefix, action)
	case err != nil:
		return "" // unexpected — be conservative and skip
	}
	if !svc.HasAction(name) {
		return fmt.Sprintf("Statement[%d]: unknown action %q for service %q", stmtIndex, name, prefix)
	}
	return ""
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

// splitAction parses "service:action" into its parts. Returns ok=false when
// the input is not in that form (no colon, or empty halves).
func splitAction(a string) (prefix, name string, ok bool) {
	i := strings.IndexByte(a, ':')
	if i <= 0 || i == len(a)-1 {
		return "", "", false
	}
	return a[:i], a[i+1:], true
}
