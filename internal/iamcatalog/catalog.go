// Package iamcatalog fetches AWS service reference JSON on demand
// (https://servicereference.us-east-1.amazonaws.com) and caches the result in
// memory for the lifetime of the process. Within a single `terraform plan`
// the provider process is long-lived, so each service is fetched at most once.
//
// Errors surface as sentinels (ErrUnknownService, ErrUnavailable) and callers
// decide how to handle them. The strict validator in this package surfaces
// both as hard errors; other callers could choose to skip silently. Do not
// bake an "always skip on ErrUnavailable" assumption into this API.
package iamcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultEndpoint = "https://servicereference.us-east-1.amazonaws.com"
	defaultTimeout  = 3 * time.Second
	// maxResponseBytes caps each JSON response. The largest legitimate service
	// (ec2) is ~800 KB today; 16 MB is generous headroom while still blunting
	// a hostile or misconfigured endpoint set via IAMENCODE_SERVICEREF_ENDPOINT.
	maxResponseBytes = 16 << 20
	// maxFetchAttempts bounds the total tries a single getJSON call makes
	// against the endpoint when the failure looks transient (HTTP 429/5xx or
	// a network error). Once exhausted, the failure surfaces as ErrUnavailable
	// and Lookup caches it, so the retry budget is paid at most once per
	// service per process.
	maxFetchAttempts = 3
)

// retryBaseDelay is the backoff before the second attempt; it doubles for
// each further retry (base, 2*base, ...). A var, not a const, so tests can
// shrink it instead of sleeping for real.
var retryBaseDelay = 500 * time.Millisecond

var (
	// ErrUnknownService: the prefix is not present in the AWS service index,
	// almost always a typo. Callers decide whether to surface it as an error
	// or absorb it (e.g. CheckPolicy reports it from checkOne but continues
	// the per-statement loop so other checks still report their findings).
	ErrUnknownService = errors.New("unknown AWS service prefix")

	// ErrUnavailable: the catalog could not be fetched (network down, timeout,
	// HTTP 4xx/5xx, malformed response). Transient failures are retried with
	// backoff inside getJSON before this surfaces. It is a sentinel; handling
	// is up to the caller. CheckPolicy surfaces it as a hard error rather than passing
	// a policy it could not verify, but a future caller could choose to skip
	// catalog-based checks on ErrUnavailable instead. Do not assume one
	// behavior here.
	ErrUnavailable = errors.New("AWS service reference unavailable")
)

// Service is the trimmed view we keep in memory per service prefix.
// Only fields the validator actually consults are retained.
type Service struct {
	Name    string
	actions map[string]struct{} // lowercased action names

	// allKeys is the union of every exact-match condition key the service
	// declares (service-level ConditionKeys plus every action's
	// ActionConditionKeys, lowercased). Used as the permissive fallback when
	// the active action is a wildcard.
	allKeys map[string]struct{} // lowercased

	// keysByAction maps lowercased action name to the set of allowed
	// exact-match condition keys for that action. A lookup miss means "no
	// per-action restriction known," and callers should fall back to allKeys.
	keysByAction map[string]map[string]struct{} // both lowercased

	// allKeyPrefixes / keyPrefixesByAction are the placeholder-tail analogues
	// of allKeys / keysByAction. AWS expresses keys like
	// "kms:EncryptionContext:${EncryptionContextKey}" or
	// "s3:ExistingObjectTag/${key}" as a fixed prefix, a ':' or '/' separator,
	// then a placeholder. The catalog stores the lowercased prefix (with the
	// trailing separator kept), and the validator accepts any user key that
	// begins with one of those prefixes plus at least one more character. See
	// splitPlaceholderKey for the parsing rules.
	allKeyPrefixes      map[string]struct{}            // lowercased, trailing ':' or '/' kept
	keyPrefixesByAction map[string]map[string]struct{} // action name to prefix set

	// arnsByAction maps lowercased action name to the ARN-format regexes
	// accepted for that action. An entry is always present for every known
	// action; the slice may be empty.
	//
	// An empty slice in the service-reference data ("Resources": null or
	// missing) is ambiguous, because AWS uses the same null/missing shape for
	// two distinct semantics:
	//
	//   - service-level actions (iam:ListUsers, iam:ListVirtualMFADevices,
	//     and so on) that AWS's own documentation pairs with concrete
	//     service-shaped ARNs;
	//   - truly resourceless actions (sts:GetCallerIdentity,
	//     sts:GetSessionToken, and so on) where only Resource = "*" is
	//     meaningful.
	//
	// The feed gives no signal to tell these apart, so checkResources falls
	// back to allArns for both. The trade-off is a known false negative on the
	// truly-resourceless case (a concrete ARN slips past) in exchange for not
	// rejecting AWS-documented service-level policies.
	arnsByAction map[string][]*regexp.Regexp

	// allArns is the union of every ARN format the service declares, used as
	// the fallback when the action name is a wildcard (e.g. "s3:*") and the
	// resource types cannot be narrowed.
	allArns []*regexp.Regexp

	// keyTypes maps lowercased condition key name to its normalized type (one
	// of "String", "Numeric", "Bool", "Date", "ARN", "IPAddress", "Binary").
	// AWS reports "ArrayOfX" for multi-value keys; we collapse those to "X"
	// since the operator check ignores cardinality. A missing entry means the
	// type is unknown, and the caller should skip type validation for that key.
	keyTypes map[string]string
}

// HasAction reports whether the service exposes the given action.
// Comparison is case-insensitive; AWS evaluates IAM actions that way.
func (s *Service) HasAction(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.actions[strings.ToLower(name)]
	return ok
}

// matchesAny reports whether at least one real action in the service matches
// the IAM glob pattern ("*" for zero-or-more chars, "?" for exactly one).
// Internal helper; the caller in check.go guarantees s != nil (the value
// returned by a successful Lookup), so there is no defensive guard.
func (s *Service) matchesAny(pattern string) bool {
	re := compileActionPattern(pattern)
	for action := range s.actions {
		if re.MatchString(action) {
			return true
		}
	}
	return false
}

// compileActionPattern turns an IAM glob ("Get*", "GetObject?", "List*Bucket*")
// into an anchored regex against lowercased action names. AWS IAM patterns
// support only "*" (any run, including empty) and "?" (exactly one char);
// every other rune is QuoteMeta'd. The resulting expression is always a
// valid regex by construction, so MustCompile is safe here.
func compileActionPattern(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for _, c := range strings.ToLower(p) {
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String())
}

// Catalog is safe for concurrent use. Construct with New.
type Catalog struct {
	endpoint string
	client   *http.Client

	indexOnce sync.Once
	index     map[string]string // service prefix to per-service JSON URL
	indexErr  error

	services sync.Map // prefix to serviceEntry
	sf       singleflight.Group
}

type serviceEntry struct {
	svc *Service
	err error
}

func New(endpoint string) *Catalog {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Catalog{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: defaultTimeout},
	}
}

// Lookup returns the cached service entry for prefix, fetching on first use.
// Concurrent calls for the same prefix are coalesced via singleflight, so a
// burst of policy validations triggers at most one HTTP request per service.
//
// The caller's ctx is intentionally not threaded into the HTTP fetch: under
// singleflight, the first caller to enter owns the in-flight request, so if
// its ctx were canceled mid-flight every coalesced caller would see the same
// failure AND it would be cached for the rest of the process. http.Client's
// own Timeout bounds the work.
func (c *Catalog) Lookup(_ context.Context, prefix string) (*Service, error) {
	key := strings.ToLower(prefix)
	if v, ok := c.services.Load(key); ok {
		e := v.(serviceEntry)
		return e.svc, e.err
	}
	// The closure intentionally always returns (entry, nil); real failures are
	// wrapped into serviceEntry.err and surfaced after sf.Do unwraps, so we
	// discard sf.Do's error half. Keep returning nil here; if a future change
	// surfaces a real error from the closure, also update the call site to
	// propagate it instead of relying on this contract.
	v, _, _ := c.sf.Do(key, func() (any, error) {
		// Re-check inside the singleflight in case another caller already finished.
		if v, ok := c.services.Load(key); ok {
			return v, nil
		}
		svc, err := c.fetchService(context.Background(), key)
		e := serviceEntry{svc: svc, err: err}
		c.services.Store(key, e)
		return e, nil
	})
	e := v.(serviceEntry)
	return e.svc, e.err
}

func (c *Catalog) loadIndex(ctx context.Context) (map[string]string, error) {
	c.indexOnce.Do(func() {
		c.index, c.indexErr = c.fetchIndex(ctx)
	})
	return c.index, c.indexErr
}

func (c *Catalog) fetchIndex(ctx context.Context) (map[string]string, error) {
	var entries []struct {
		Service string `json:"service"`
		URL     string `json:"url"`
	}
	if err := c.getJSON(ctx, c.endpoint+"/", &entries); err != nil {
		return nil, fmt.Errorf("%w: index: %v", ErrUnavailable, err)
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		m[strings.ToLower(e.Service)] = e.URL
	}
	return m, nil
}

func (c *Catalog) fetchService(ctx context.Context, prefix string) (*Service, error) {
	index, err := c.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	url, ok := index[prefix]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownService, prefix)
	}
	var raw struct {
		Name    string `json:"Name"`
		Actions []struct {
			Name                string   `json:"Name"`
			ActionConditionKeys []string `json:"ActionConditionKeys"`
			// Resources lists the resource types this action operates on.
			// AWS exposes ConditionKeys at this level: keys valid for this
			// (action, resource type) pair. For example ec2:AuthorizedService
			// is only listed under ec2:CreateNetworkInterfacePermission's
			// network-interface resource, never as an ActionConditionKey. The
			// catalog must merge these into the per-action allowed set, or
			// strict mode will reject valid policies.
			Resources []struct {
				Name          string   `json:"Name"`
				ConditionKeys []string `json:"ConditionKeys"`
			} `json:"Resources"`
		} `json:"Actions"`
		ConditionKeys []struct {
			Name  string   `json:"Name"`
			Types []string `json:"Types"`
		} `json:"ConditionKeys"`
		Resources []struct {
			Name          string   `json:"Name"`
			ARNFormats    []string `json:"ARNFormats"`
			ConditionKeys []string `json:"ConditionKeys"`
		} `json:"Resources"`
	}
	if err := c.getJSON(ctx, url, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, prefix, err)
	}
	actions := make(map[string]struct{}, len(raw.Actions))
	keysByAction := make(map[string]map[string]struct{}, len(raw.Actions))
	keyPrefixesByAction := make(map[string]map[string]struct{}, len(raw.Actions))
	allKeys := make(map[string]struct{}, len(raw.ConditionKeys))
	allKeyPrefixes := make(map[string]struct{})
	keyTypes := make(map[string]string, len(raw.ConditionKeys))
	for _, ck := range raw.ConditionKeys {
		addConditionKey(ck.Name, nil, nil, allKeys, allKeyPrefixes)
		if len(ck.Types) > 0 {
			keyTypes[canonicalKeyName(ck.Name)] = strings.TrimPrefix(ck.Types[0], "ArrayOf")
		}
	}

	// Compile each resource type's ARN templates once per service. Also
	// snapshot each resource type's ConditionKeys so the per-action loop
	// below can merge them in (those keys are valid wherever an action
	// targets the resource, and many keys appear only here, never as
	// service-level or per-action keys).
	//
	// siblings collects every ARN format across the service so each
	// template can know whether a longer template extends it with "/<X>".
	// That's the signal compileARNTemplate uses to keep S3's bucket
	// placeholder bounded ("...:::${BucketName}" stays bucket-only because
	// the object template adds "/${ObjectName}") while still letting
	// CloudWatch Logs log-group's placeholder span "/" (the log-stream
	// template extends with ":log-stream:", a ":" not a "/").
	patternsByType := make(map[string][]*regexp.Regexp, len(raw.Resources))
	keysByResource := make(map[string][]string, len(raw.Resources))
	allArns := make([]*regexp.Regexp, 0)
	var siblings []string
	for _, r := range raw.Resources {
		siblings = append(siblings, r.ARNFormats...)
	}
	for _, r := range raw.Resources {
		patterns := make([]*regexp.Regexp, 0, len(r.ARNFormats))
		for _, tmpl := range r.ARNFormats {
			if re := compileARNTemplate(tmpl, siblings); re != nil {
				patterns = append(patterns, re)
				allArns = append(allArns, re)
			}
		}
		lr := strings.ToLower(r.Name)
		patternsByType[lr] = patterns
		// Roll the top-level resource keys into the service-wide allKeys /
		// allKeyPrefixes fallback too, so the wildcard-action path (s3:*)
		// still sees them even if no concrete action references the resource.
		keysByResource[lr] = r.ConditionKeys
		for _, k := range r.ConditionKeys {
			addConditionKey(k, nil, nil, allKeys, allKeyPrefixes)
		}
	}

	arnsByAction := make(map[string][]*regexp.Regexp, len(raw.Actions))
	for _, a := range raw.Actions {
		la := strings.ToLower(a.Name)
		actions[la] = struct{}{}
		// Always record entries, even empty ones. An empty set means "this
		// action takes no service-specific condition keys" (only aws:*
		// globals); skipping the empty case would let the check fall back to
		// service-wide keys and admit unrelated keys.
		set := make(map[string]struct{}, len(a.ActionConditionKeys))
		prefixSet := make(map[string]struct{})
		for _, k := range a.ActionConditionKeys {
			addConditionKey(k, set, prefixSet, allKeys, allKeyPrefixes)
		}
		// Many keys are valid only at the resource level. Two sources to
		// merge in for each resource the action targets:
		//   - Actions[].Resources[].ConditionKeys: the keys AWS lists as
		//     valid for this specific (action, resource) pair.
		//   - Resources[].ConditionKeys (top-level): the resource type's
		//     full key list. Some services declare per-action subsets;
		//     others declare only the top-level list and leave the action
		//     entry's ConditionKeys empty. Union both so we cover both.
		for _, r := range a.Resources {
			for _, k := range r.ConditionKeys {
				addConditionKey(k, set, prefixSet, allKeys, allKeyPrefixes)
			}
			for _, k := range keysByResource[strings.ToLower(r.Name)] {
				addConditionKey(k, set, prefixSet, allKeys, allKeyPrefixes)
			}
		}
		keysByAction[la] = set
		keyPrefixesByAction[la] = prefixSet

		// Same treatment for ARN patterns: always populate (possibly empty).
		// Actions like sts:GetCallerIdentity have no Resources declaration;
		// we want an empty slice rather than "missing" so callers can tell
		// "this action is resourceless" from "we don't know."
		ps := make([]*regexp.Regexp, 0)
		for _, r := range a.Resources {
			ps = append(ps, patternsByType[strings.ToLower(r.Name)]...)
		}
		arnsByAction[la] = ps
	}
	return &Service{
		Name:                raw.Name,
		actions:             actions,
		allKeys:             allKeys,
		keysByAction:        keysByAction,
		allKeyPrefixes:      allKeyPrefixes,
		keyPrefixesByAction: keyPrefixesByAction,
		arnsByAction:        arnsByAction,
		allArns:             allArns,
		keyTypes:            keyTypes,
	}, nil
}

// splitPlaceholderKey parses an AWS-style placeholder-tail condition key
// name into its fixed-prefix portion. AWS writes these keys as
//
//	kms:EncryptionContext:${EncryptionContextKey}
//	s3:ExistingObjectTag/${key}
//
// as a literal prefix, a ':' or '/' separator, and a "${...}" placeholder.
// Returns (prefix, true) for those shapes (the trailing separator is kept on
// the prefix so HasPrefix matches a user key cleanly), or ("", false)
// otherwise. The separator allowlist is narrow: any other character before
// the placeholder is treated as an exact-match key, so typo'd keys that
// contain a stray "${" are not swallowed.
func splitPlaceholderKey(name string) (string, bool) {
	if !strings.HasSuffix(name, "}") {
		return "", false
	}
	open := strings.LastIndex(name, "${")
	if open <= 0 {
		return "", false
	}
	sep := name[open-1]
	if sep != ':' && sep != '/' {
		return "", false
	}
	return name[:open], true
}

// canonicalKeyName returns the lookup form that addConditionKey would store
// for `name`: the stripped lowercased prefix for placeholder-tail keys, the
// lowercased name otherwise. Used to index sibling maps (e.g. keyTypes) so
// they agree with whichever set addConditionKey populated.
func canonicalKeyName(name string) string {
	lk := strings.ToLower(name)
	if p, ok := splitPlaceholderKey(lk); ok {
		return p
	}
	return lk
}

// addConditionKey classifies a condition-key name and records it under the
// matching set. Placeholder-tail keys (see splitPlaceholderKey) land in the
// prefix maps; everything else lands in the exact maps. intoExact and
// intoPrefixes accept the per-action sets; pass nil at call sites that only
// contribute to the service-wide allKeys / allKeyPrefixes (e.g. the top-level
// Resources[].ConditionKeys loop, where there is no specific action to
// attribute the key to).
func addConditionKey(name string, intoExact, intoPrefixes, allKeys, allKeyPrefixes map[string]struct{}) {
	lk := strings.ToLower(name)
	if p, ok := splitPlaceholderKey(lk); ok {
		allKeyPrefixes[p] = struct{}{}
		if intoPrefixes != nil {
			intoPrefixes[p] = struct{}{}
		}
		return
	}
	allKeys[lk] = struct{}{}
	if intoExact != nil {
		intoExact[lk] = struct{}{}
	}
}

// compileARNTemplate turns an AWS service-reference ARN format like
//
//	arn:${Partition}:s3:::${BucketName}/${ObjectName}
//
// into an anchored regex. `siblings` is the full list of ARN formats
// declared by the same service so the compiler can decide whether a
// template's last placeholder should be bounded or greedy. See the rules
// in arnPlaceholderPattern for the per-placeholder logic.
//
// A nil return means the template was malformed and should be ignored.
func compileARNTemplate(tmpl string, siblings []string) *regexp.Regexp {
	var placeholders [][2]int
	for i := 0; i < len(tmpl); {
		if i+1 < len(tmpl) && tmpl[i] == '$' && tmpl[i+1] == '{' {
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				return nil
			}
			placeholders = append(placeholders, [2]int{i, i + end + 1})
			i += end + 1
			continue
		}
		i++
	}
	lastIdx := -1
	if len(placeholders) > 0 {
		lastIdx = len(placeholders) - 1
	}

	var b strings.Builder
	b.WriteByte('^')
	cursor := 0
	for idx, p := range placeholders {
		b.WriteString(regexp.QuoteMeta(tmpl[cursor:p[0]]))
		b.WriteString(arnPlaceholderPattern(tmpl, p, idx, lastIdx, siblings))
		cursor = p[1]
	}
	b.WriteString(regexp.QuoteMeta(tmpl[cursor:]))
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// arnPlaceholderPattern returns the regex fragment that should occupy a
// single placeholder position in the compiled template. Most rules return
// a bare character class ("[^:]*", "[^:/]*", ".*"), but rules 3a and 4
// return composite fragments ("[^:]*(?::[^:]+)?" and "[^:]*(?::[*?])*"
// respectively) that pair a bounded segment with an optional tail; treat
// the return value as an arbitrary regex fragment rather than a pure
// character class.
//
// The rules, applied in order:
//
//  1. Non-last placeholder followed by '/' in the same template -> "[^:/]*".
//     The literal '/' delimits the next segment, so the placeholder must stop
//     there. Example: ${BucketName} in ":::${BucketName}/${ObjectName}".
//
//  2. Last placeholder with '/' anywhere in the preceding template text ->
//     ".*". The template is path-shaped and the trailing value can contain
//     '/'. Example: ${ObjectName} in ":::${B}/${O}", ${RoleNameWithPath} in
//     ":role/${RoleNameWithPath}".
//
//  3. Last placeholder where a sibling template extends this one's prefix
//     with "/<...>" -> "[^:/]*". This is the bucket-vs-object pair: S3
//     bucket's ${BucketName} stays bounded because the object template adds
//     "/${ObjectName}", so an ARN with '/' is really an object ARN and must
//     not satisfy the bucket-only resource.
//
//     3a. Last placeholder where a sibling colon-extends with ":${...}" (a
//     colon followed immediately by another placeholder, no literal in
//     between) -> "[^:]*(?::[^:]+)?". This is the "qualifier tail" shape:
//     lambda function/layer, lex bot, states stateMachine, and the like all
//     add a single ":${Version}" or ":${Alias}" sibling to a base resource
//     type. The catalog declares those as separate resource types and lists
//     the base action against only the base type, so a literal alias ARN like
//     "arn:aws:lambda:r:a:function:f:my-alias" would otherwise be rejected on
//     lambda:InvokeFunction. The trailing "(?::[^:]+)?" is a single optional
//     segment, so AWS's two-deep forms are not allowed (no
//     "function:f:alias:typo"). Sibling extensions with a literal between the
//     colon and the next placeholder ("...:log-group:${LG}:log-stream:${LS}")
//     do not trigger this rule; those are structural child resources, not
//     free-form qualifiers, and use rule 4.
//
//  4. Last placeholder otherwise -> "[^:]*(?::[*?])*". CloudWatch Logs
//     log-group ARNs land here: log group names contain '/'
//     ("/aws/codebuild/foo"), and the log-stream sibling extends with
//     ':log-stream:' (a literal between the colon and the next placeholder),
//     so neither rule 3 nor 3a triggers. The base class is "[^:]*" (allow
//     '/', forbid ':') so concrete child-resource ARNs like
//     "...:group:foo:sub:bar" do not satisfy a short-only action's template.
//     The trailing "(?::[*?])*" group accepts IAM wildcard tails like ":*" or
//     ":?:*"; the canonical CodeBuild policy
//     ("...:log-group:/aws/codebuild/proj:*") relies on this to refer to "the
//     group plus any sub-resource."
//
//  5. Default (non-last placeholder, not followed by '/') -> "[^:]*". Allows
//     '/' (needed for ${LogGroupName} appearing mid-template in
//     "...:log-group:${LogGroupName}:log-stream:..." where the real value is
//     "/aws/codebuild/foo") while still respecting the ':' ARN separator.
func arnPlaceholderPattern(tmpl string, p [2]int, idx, lastIdx int, siblings []string) string {
	if idx < lastIdx {
		if p[1] < len(tmpl) && tmpl[p[1]] == '/' {
			return "[^:/]*"
		}
		return "[^:]*"
	}
	if strings.ContainsRune(tmpl[:p[0]], '/') {
		return ".*"
	}
	for _, s := range siblings {
		if s == tmpl {
			continue
		}
		if len(s) > p[1] && s[:p[1]] == tmpl[:p[1]] && s[p[1]] == '/' {
			return "[^:/]*"
		}
	}
	for _, s := range siblings {
		if s == tmpl {
			continue
		}
		// Rule 3a: a sibling colon-extends with ":${...}", so allow a single
		// qualifier tail. The next two characters after the colon must be
		// "${", i.e. the placeholder begins immediately. Sibling extensions
		// with a literal between (":log-stream:${LS}") do not match here.
		if len(s) >= p[1]+3 && s[:p[1]] == tmpl[:p[1]] &&
			s[p[1]] == ':' && s[p[1]+1] == '$' && s[p[1]+2] == '{' {
			return "[^:]*(?::[^:]+)?"
		}
	}
	return "[^:]*(?::[*?])*"
}

// getJSON fetches url and decodes the JSON response into out. Transient
// failures (network errors and HTTP 429/5xx responses) are retried up to
// maxFetchAttempts total attempts with exponential backoff. Anything else --
// another 4xx status, a request that cannot be built, a body that decodes
// wrong -- fails immediately: those reflect a real mismatch, not a blip, and
// retrying would only stall the plan. Decoding into out happens at most once
// (only on a 200), so a retried call never leaves out partially filled.
func (c *Catalog) getJSON(ctx context.Context, url string, out any) error {
	for attempt := 1; ; attempt++ {
		retryable, err := c.getJSONOnce(ctx, url, out)
		if err == nil || !retryable || attempt == maxFetchAttempts {
			return err
		}
		// time.After without Stop is fine here: since Go 1.23 an
		// unreferenced timer is collectible before it fires.
		select {
		case <-ctx.Done():
			// Join rather than pick one: the fetch error says why the retry
			// was pending, ctx.Err() says why it stopped; both stay visible
			// to errors.Is.
			return errors.Join(err, ctx.Err())
		case <-time.After(retryBaseDelay << (attempt - 1)):
		}
	}
}

func (c *Catalog) getJSONOnce(ctx context.Context, url string, out any) (retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, body)
		return isRetryableStatus(resp.StatusCode), fmt.Errorf("http %d", resp.StatusCode)
	}
	return false, json.NewDecoder(body).Decode(out)
}

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}
