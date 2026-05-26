package iamcatalog

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// CheckPolicy walks the IAM policy and runs catalog-backed checks against the
// AWS service reference. It is designed to be called *after* schema validation
// has already passed, so structural shapes are assumed valid. Three checks run:
//
//  1. Action existence. Non-wildcard Action/NotAction values like "s3:GetObject"
//     are verified against the catalog — both the service prefix and the
//     action name must exist. Wildcards within the action name ("s3:Get*",
//     "s3:G?tObject", "s3:*") are expanded against the service's action set
//     and must match at least one real action, so plausible-looking typos
//     like "s3:Frobni*" are still caught. The bare "*" and wildcards in the
//     service prefix ("*:GetObject", "s*:Foo") are accepted without catalog
//     lookup — expanding them would require fetching every service catalog.
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
	if strings.ContainsAny(prefix, "*?") {
		// Wildcard in the service prefix would require fetching every
		// service in the catalog (449+ at time of writing) to know if any
		// real action matches — pattern expansion of that scope is out of
		// scope. Skip silently.
		return "", nil
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
	if strings.ContainsAny(name, "*?") {
		// Wildcard within the action name. Expand against the service's
		// real action list — catches patterns like "s3:Frobni*" that look
		// plausible but match nothing.
		if !svc.matchesAny(name) {
			return fmt.Sprintf("Statement[%d]: action pattern %q matches no actions in service %q", stmtIndex, action, prefix), nil
		}
		return "", nil
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
	allowedPrefixes := make(map[string]struct{})
	keyTypes := make(map[string]string)
	for _, a := range actions {
		if a == "*" {
			return nil, nil // can't narrow which keys are valid
		}
		prefix, name, ok := splitAction(a)
		if !ok {
			continue // checkOne already flags malformed actions
		}
		if strings.ContainsAny(prefix, "*?") {
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
		var keys, prefixes map[string]struct{}
		if strings.ContainsAny(name, "*?") {
			keys = svc.allKeys
			prefixes = svc.allKeyPrefixes
		} else if perAction, has := svc.keysByAction[strings.ToLower(name)]; has {
			keys = perAction
			prefixes = svc.keyPrefixesByAction[strings.ToLower(name)]
		} else {
			keys = svc.allKeys
			prefixes = svc.allKeyPrefixes
		}
		maps.Copy(allowed, keys)
		maps.Copy(allowedPrefixes, prefixes)
		// Merge type info too. Same key declared by multiple services should
		// have the same type; last write wins if they disagree (unlikely).
		maps.Copy(keyTypes, svc.keyTypes)
	}

	// AssumeRoleWithWebIdentity lets a user-registered OIDC provider
	// contribute "<provider-hostname>:<keyname>" condition keys. The
	// provider URL isn't known statically, so the service reference
	// only lists the AWS-preregistered providers (accounts.google.com,
	// cognito-identity.amazonaws.com, …). If the statement targets
	// AssumeRoleWithWebIdentity — directly or via a wildcard pattern
	// like "sts:AssumeRoleWith*" or "sts:*" — accept any hostname-
	// prefixed key as a dynamic OIDC provider key instead of flagging
	// it as unknown.
	allowsOIDCKeys := statementCoversAction(actions, "sts", "AssumeRoleWithWebIdentity")

	var issues []string
	for opName, op := range cond {
		operands, ok := op.(map[string]any)
		if !ok {
			continue
		}
		expectedType, opKnown := operatorExpectedType(opName)
		for key := range operands {
			lk := strings.ToLower(key)
			if strings.HasPrefix(lk, "aws:") {
				continue // AWS-global condition keys are always allowed
			}
			// Two acceptance paths: a direct hit in the exact-match set, or
			// (failing that) a hit against one of the catalog-declared
			// placeholder prefixes — keys like kms:EncryptionContext:<user>
			// or s3:ExistingObjectTag/<user>. The type for a prefix match
			// is looked up under the prefix itself (keyTypes is indexed by
			// the canonical form addConditionKey chose at catalog parse time).
			var actualType string
			if _, ok := allowed[lk]; ok {
				actualType = keyTypes[lk]
			} else if p := matchPlaceholderPrefix(lk, allowedPrefixes); p != "" {
				actualType = keyTypes[p]
			} else {
				if allowsOIDCKeys && isOIDCConditionKey(key) {
					continue
				}
				issues = append(issues, fmt.Sprintf(
					"Statement[%d]: condition key %q (under %s) is not valid for the statement's actions",
					stmtIdx, key, opName))
				continue
			}
			// Key passed the per-action check; if we know its declared type
			// and the operator's expected type, confirm they match. Missing
			// either side (unknown operator or untyped key) means we can't
			// judge — skip silently.
			if !opKnown || expectedType == "" || actualType == "" {
				continue
			}
			if actualType != expectedType {
				issues = append(issues, fmt.Sprintf(
					"Statement[%d]: operator %s expects a %s key, but %q is declared as %s",
					stmtIdx, opName, expectedType, key, actualType))
			}
		}
	}
	return issues, nil
}

// matchPlaceholderPrefix reports which (if any) declared placeholder prefix
// the user-supplied condition key instantiates. The match requires at least
// one character past the prefix — an empty tail like "kms:EncryptionContext:"
// alone has no instantiated value and is still flagged as an unknown key,
// keeping the validator strict against malformed structural shapes.
//
// A tail that *itself* starts with "${" is rejected too. This catches the
// common docs-paste typo where a user copies "kms:EncryptionContext:${EncryptionContextKey}"
// verbatim into their policy: IAM does not expand "${...}" in condition
// keys, so the literal template would never match anything at evaluation
// time. The leading-only check is deliberate — a tail that contains "${"
// further in (e.g. an opaque tag value with a literal "${" substring) is
// still accepted, since only the leading position is a clear copy-paste
// signal.
func matchPlaceholderPrefix(key string, prefixes map[string]struct{}) string {
	for p := range prefixes {
		if len(key) > len(p) && strings.HasPrefix(key, p) {
			if strings.HasPrefix(key[len(p):], "${") {
				continue
			}
			return p
		}
	}
	return ""
}

// operatorExpectedType returns the catalog-style type that the given IAM
// condition operator expects, plus a flag indicating whether we recognized
// the operator at all. AWS allows two prefix modifiers (ForAllValues:,
// ForAnyValue:) and one suffix (IfExists); we strip them before lookup.
// The Null operator is special — it works on any type and returns ("", true)
// so the caller can skip type validation without treating it as unknown.
func operatorExpectedType(op string) (string, bool) {
	op = strings.TrimPrefix(op, "ForAllValues:")
	op = strings.TrimPrefix(op, "ForAnyValue:")
	op = strings.TrimSuffix(op, "IfExists")
	if op == "Null" {
		return "", true // any type accepted
	}
	t, ok := opTypeTable[op]
	return t, ok
}

// opTypeTable maps each IAM condition operator (modifiers already stripped)
// to the catalog "Types" value it expects. See the AWS IAM user guide,
// "Condition operators" for the canonical list. Operators not in this
// table are treated as unknown — the type check skips rather than
// false-positive on AWS additions we haven't seen yet.
var opTypeTable = map[string]string{
	"StringEquals":              "String",
	"StringNotEquals":           "String",
	"StringEqualsIgnoreCase":    "String",
	"StringNotEqualsIgnoreCase": "String",
	"StringLike":                "String",
	"StringNotLike":             "String",
	"NumericEquals":             "Numeric",
	"NumericNotEquals":          "Numeric",
	"NumericLessThan":           "Numeric",
	"NumericLessThanEquals":     "Numeric",
	"NumericGreaterThan":        "Numeric",
	"NumericGreaterThanEquals":  "Numeric",
	"DateEquals":                "Date",
	"DateNotEquals":             "Date",
	"DateLessThan":              "Date",
	"DateLessThanEquals":        "Date",
	"DateGreaterThan":           "Date",
	"DateGreaterThanEquals":     "Date",
	"Bool":                      "Bool",
	"BinaryEquals":              "Binary",
	"IpAddress":                 "IPAddress",
	"NotIpAddress":              "IPAddress",
	"ArnEquals":                 "ARN",
	"ArnNotEquals":              "ARN",
	"ArnLike":                   "ARN",
	"ArnNotLike":                "ARN",
}

// checkResources validates the Action × Resource cross-product in two
// directions:
//
//  1. Resource-side: each Resource ARN must match at least one of the ARN
//     templates declared by some action in the statement. Catches the
//     classic "wrong shape" mistake — e.g. a bucket ARN given to a
//     statement whose only action is s3:GetObject (object-only).
//
//  2. Action-side: each Action must have at least one Resource in the
//     statement that matches its ARN templates. Catches the mirror
//     mistake — a statement listing s3:ListBucket alongside s3:GetObject
//     but supplying only an object ARN, leaving ListBucket orphaned.
//
// A bare "*" Resource short-circuits direction 2 entirely (it covers every
// action). Wildcards on the Action side skip in the same pattern as
// checkConditions: wildcard service prefix or bare "*" Action skips the
// whole check; wildcard action name falls back to the service-wide union
// of ARN formats. NotResource statements skip entirely — the listed
// exclusions are the wrong domain to validate against.
//
// Returns (issues, err) where err is ErrUnavailable.
func checkResources(ctx context.Context, c *Catalog, stmt map[string]any, stmtIdx int) ([]string, error) {
	resources := appendStringOrList(nil, stmt["Resource"])
	if len(resources) == 0 {
		return nil, nil
	}
	actions := appendStringOrList(nil, stmt["Action"])
	if len(actions) == 0 {
		return nil, nil
	}

	// Per-action pattern tracking lets us answer both directions:
	// direction 1 unions everything; direction 2 needs each action's set
	// separately so an orphaned action can be named in the error.
	type actionEntry struct {
		token    string // original Action token, used for error messages
		patterns []*regexp.Regexp
		// skipDir2 marks actions that contribute to direction 1 (so the
		// resource still has *something* to match against) but must not
		// drive direction 2. Set for non-wildcard action names that the
		// catalog doesn't actually expose: checkOne already reports them
		// as unknown, and "action %q has no resource that matches its ARN
		// format" would mislead — the action has no real ARN format here.
		skipDir2 bool
	}
	var perAction []actionEntry
	// De-duplicate by lowercased action token. IAM actions are case-
	// insensitive, so ["s3:ListBucket", "s3:listbucket"] (or the same
	// spelling twice) address the same action — without this guard direction
	// 2 would emit one redundant "has no resource" line per duplicate.
	seenAction := make(map[string]struct{})
	resolvedAny := false
	for _, a := range actions {
		if a == "*" {
			return nil, nil
		}
		prefix, name, ok := splitAction(a)
		if !ok {
			continue
		}
		if strings.ContainsAny(prefix, "*?") {
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
		resolvedAny = true
		key := strings.ToLower(a)
		if _, dup := seenAction[key]; dup {
			continue
		}
		seenAction[key] = struct{}{}
		var pats []*regexp.Regexp
		skipDir2 := false
		if strings.ContainsAny(name, "*?") {
			pats = svc.allArns
			// A wildcard that matches no real action (e.g. "s3:Frobni*")
			// is already flagged by checkOne. Excluding it from direction
			// 2 mirrors the unknown-action carve-out below: with no real
			// expansion there's no meaningful "ARN format" to complain
			// about. Wildcards that DO match at least one action stay in
			// direction 2 — their allArns view is a legitimate constraint.
			if !svc.matchesAny(name) {
				skipDir2 = true
			}
		} else if pa, has := svc.arnsByAction[strings.ToLower(name)]; has && len(pa) > 0 {
			pats = pa
		} else {
			// Two cases share this fallback to the service-wide ARN union:
			//
			//   1. The action is unknown (typo). checkOne reports the
			//      action separately; we use allArns so the unknown
			//      action doesn't also drag a misleading "resource
			//      doesn't match" error along with it. The action is also
			//      excluded from direction 2 — a non-existent action has
			//      no "ARN format" to complain about.
			//
			//   2. The action is known but the service reference lists
			//      it with no Resources (e.g. iam:ListUsers,
			//      iam:ListVirtualMFADevices). IAM evaluates these
			//      service-level actions against the account scope, and
			//      the AWS-documented "let users self-manage" pattern
			//      pairs them with a concrete IAM-shaped Resource
			//      ("arn:aws:iam::ACCOUNT:user/"). Validate against
			//      allArns rather than the empty per-action set, and
			//      direction 2 still applies (a wrong-service ARN is
			//      a real mistake worth surfacing).
			pats = svc.allArns
			if !svc.HasAction(name) {
				skipDir2 = true
			}
		}
		perAction = append(perAction, actionEntry{token: a, patterns: pats, skipDir2: skipDir2})
	}
	if !resolvedAny {
		// Every action was malformed or referenced an unknown service. The
		// ARN itself may well be valid for the *intended* action; flagging
		// it would just be a misleading second error. checkOne already
		// reports the action-side problems.
		return nil, nil
	}

	// Both directions need only "did at least one match happen?" answers,
	// so two 1D bitmaps (resource-side, action-side) are enough — no full
	// R×A matrix. The inner regex work is skipped for pairs where both
	// bits are already set, which lets the worst case decay toward the old
	// pooled-patterns loop in policies that are mostly well-formed.
	resourceMatched := make([]bool, len(resources))
	actionCovered := make([]bool, len(perAction))
	for i, r := range resources {
		if r == "*" {
			// Bare "*" satisfies direction 1 for itself and covers every
			// action for direction 2 in one shot.
			resourceMatched[i] = true
			for j := range actionCovered {
				actionCovered[j] = true
			}
			continue
		}
		rm := newResourceMatcher(r)
		for j, ae := range perAction {
			if resourceMatched[i] && actionCovered[j] {
				continue // no new information possible from this pair
			}
			if slices.ContainsFunc(ae.patterns, func(p *regexp.Regexp) bool {
				return rm.match(p)
			}) {
				resourceMatched[i] = true
				actionCovered[j] = true
			}
		}
	}

	var issues []string

	// Direction 1: every non-star Resource has at least one action it fits.
	for i, r := range resources {
		if r == "*" || resourceMatched[i] {
			continue
		}
		issues = append(issues, fmt.Sprintf(
			"Statement[%d]: resource %q does not match any ARN format for the statement's actions",
			stmtIdx, r))
	}

	// Direction 2: every Action has at least one Resource it fits. Actions
	// whose pattern set is empty (only possible with a service catalog that
	// declares zero ARN formats — fake-test territory, not real AWS) or
	// whose name doesn't actually exist in the catalog (skipDir2) are
	// skipped to stay consistent with the "no info → don't double-flag"
	// philosophy used by checkOne and the unknown-service path above.
	for j, ae := range perAction {
		if len(ae.patterns) == 0 || ae.skipDir2 || actionCovered[j] {
			continue
		}
		issues = append(issues, fmt.Sprintf(
			"Statement[%d]: action %q has no resource that matches its ARN format",
			stmtIdx, ae.token))
	}

	return issues, nil
}

// isOIDCConditionKey reports whether `key` has the shape of a dynamic
// OIDC condition key — "<hostname>:<keyname>", where the hostname is an
// RFC-1123 LDH domain name (two or more labels of [A-Za-z0-9] with
// optional internal hyphens, separated by '.').
//
// The helper deliberately recognizes only the single-colon hostname form.
// Some IAM condition keys legitimately use multiple colons (KMS encryption
// context keys like "kms:EncryptionContext:aws:s3:arn", for instance), but
// those are catalog-listed and flow through the normal check. Restricting
// this carve-out to one colon keeps it from masking typos that happen to
// contain extra colons. The dot requirement (two labels minimum) is what
// separates an OIDC key from a regular catalog key like "s3:GetObject" or
// "sts:RoleSessionName"; the latter have no dot in the prefix and continue
// to flow through the strict catalog check.
func isOIDCConditionKey(key string) bool {
	if strings.Count(key, ":") != 1 {
		return false
	}
	colon := strings.IndexByte(key, ':')
	if colon == 0 || colon == len(key)-1 {
		return false
	}
	return isLDHHostname(key[:colon])
}

// isLDHHostname reports whether host is a valid RFC-1123 LDH domain name
// with at least two labels. Each label must be 1–63 chars long, contain
// only [A-Za-z0-9-], and may not start or end with a hyphen. Empty labels
// (consecutive dots) and leading/trailing dots are rejected. The empty
// string falls through naturally — strings.Split("", ".") returns [""]
// which has length 1 and fails the label-count guard.
func isLDHHostname(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isLDHLabel(label) {
			return false
		}
	}
	return true
}

func isLDHLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// statementCoversAction reports whether any of the given action tokens
// resolves (directly or via an IAM wildcard pattern) to the action
// "<service>:<name>". Lets carve-outs like the OIDC condition-key
// allowance trigger uniformly for the literal action and for the
// wildcard forms ("sts:*", "sts:AssumeRoleWith*") that checkOne accepts.
func statementCoversAction(actions []string, service, name string) bool {
	target := strings.ToLower(name)
	for _, a := range actions {
		prefix, n, ok := splitAction(a)
		if !ok || !strings.EqualFold(prefix, service) {
			continue
		}
		if strings.EqualFold(n, name) {
			return true
		}
		if strings.ContainsAny(n, "*?") && compileActionPattern(n).MatchString(target) {
			return true
		}
	}
	return false
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
