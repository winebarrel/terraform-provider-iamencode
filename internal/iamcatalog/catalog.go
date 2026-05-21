// Package iamcatalog fetches AWS service reference JSON on demand
// (https://servicereference.us-east-1.amazonaws.com) and caches the result in
// memory for the lifetime of the process. Within a single `terraform plan`
// the provider process is long-lived, so each service is fetched at most once.
//
// Errors surface as sentinels (ErrUnknownService, ErrUnavailable) and callers
// pick the policy. The strict validator in this package surfaces both as hard
// errors; other callers could choose to skip silently. Don't bake an "always
// skip on ErrUnavailable" assumption into the API surface here.
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
)

var (
	// ErrUnknownService — the prefix is not present in the AWS service index.
	// Almost always a typo. Callers decide whether to surface it as an error
	// or absorb it (e.g. CheckPolicy reports it from checkOne but continues
	// the per-statement loop so other checks still report their findings).
	ErrUnknownService = errors.New("unknown AWS service prefix")

	// ErrUnavailable — the catalog could not be fetched (network down,
	// timeout, HTTP 4xx/5xx, malformed response). It's a sentinel; the policy
	// is up to the caller. CheckPolicy surfaces it as a hard error — strict
	// mode shouldn't silently pass a policy it couldn't actually verify —
	// but a future caller could legitimately choose to skip catalog-based
	// checks on ErrUnavailable instead. Don't assume one behavior here.
	ErrUnavailable = errors.New("AWS service reference unavailable")
)

// Service is the trimmed view we keep in memory per service prefix.
// Only fields the validator actually consults are retained.
type Service struct {
	Name    string
	actions map[string]struct{} // lowercased action names

	// allKeys is the union of every condition key the service declares
	// (service-level ConditionKeys plus every action's ActionConditionKeys).
	// Used as the permissive fallback when the active action is a wildcard.
	allKeys map[string]struct{} // lowercased

	// keysByAction maps lowercased action name → set of allowed condition keys
	// for that specific action. A lookup miss means "no per-action restriction
	// known," and callers should fall back to allKeys.
	keysByAction map[string]map[string]struct{} // both lowercased

	// arnsByAction maps lowercased action name → ARN-format regexes accepted
	// for that action. An entry is always present for every known action;
	// the slice may be empty.
	//
	// An empty slice in the service-reference data ("Resources": null or
	// missing) is genuinely ambiguous — AWS uses the same null/missing
	// shape for two distinct semantics:
	//
	//   - service-level actions (iam:ListUsers, iam:ListVirtualMFADevices,
	//     …) that AWS's own documentation pairs with concrete service-
	//     shaped ARNs;
	//   - truly resourceless actions (sts:GetCallerIdentity,
	//     sts:GetSessionToken, …) where only Resource = "*" is meaningful.
	//
	// The service-reference feed gives no signal to tell these apart, so
	// checkResources falls back to allArns for both. The trade-off is a
	// known false negative on the truly-resourceless case (a concrete ARN
	// would slip past) in exchange for not rejecting AWS-documented
	// service-level policies.
	arnsByAction map[string][]*regexp.Regexp

	// allArns is the union of every ARN format the service declares — used
	// as the fallback when the action name is a wildcard (e.g. "s3:*") and
	// we therefore can't narrow the resource types.
	allArns []*regexp.Regexp

	// keyTypes maps lowercased condition key name → its normalized type
	// (one of "String", "Numeric", "Bool", "Date", "ARN", "IPAddress",
	// "Binary"). AWS reports "ArrayOfX" for keys that take multi-value
	// values; we collapse those to "X" since the operator check doesn't
	// care about cardinality. A missing entry means we don't know the
	// type, and the caller should skip type validation for that key.
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
// the IAM glob pattern (which supports "*" for zero-or-more chars and "?" for
// exactly one). Internal helper; the caller in check.go guarantees s != nil
// (it's the value returned by a successful Lookup), so no defensive guard.
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
	index     map[string]string // service prefix → per-service JSON URL
	indexErr  error

	services sync.Map // prefix → serviceEntry
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
	// discard sf.Do's error half. Keep returning nil here — if a future change
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
			// AWS exposes ConditionKeys at this level: keys that are valid
			// for (this action, that resource type) — e.g. ec2:AuthorizedService
			// is only listed under ec2:CreateNetworkInterfacePermission's
			// network-interface resource, never as an ActionConditionKey. The
			// catalog must merge these into the per-action allowed set or
			// strict mode will reject perfectly valid policies.
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
	allKeys := make(map[string]struct{}, len(raw.ConditionKeys))
	keyTypes := make(map[string]string, len(raw.ConditionKeys))
	for _, ck := range raw.ConditionKeys {
		lk := strings.ToLower(ck.Name)
		allKeys[lk] = struct{}{}
		if len(ck.Types) > 0 {
			keyTypes[lk] = strings.TrimPrefix(ck.Types[0], "ArrayOf")
		}
	}

	// Compile each resource type's ARN templates once per service. Also
	// snapshot each resource type's ConditionKeys so the per-action loop
	// below can merge them in (those keys are valid wherever an action
	// targets the resource, and many keys appear ONLY here — never as
	// service-level or per-action keys).
	//
	// `siblings` collects every ARN format across the service so each
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
		// Roll the top-level resource keys into the service-wide allKeys
		// fallback too, so the wildcard-action path (s3:*) still sees them
		// even if no concrete action references the resource.
		keysByResource[lr] = r.ConditionKeys
		for _, k := range r.ConditionKeys {
			allKeys[strings.ToLower(k)] = struct{}{}
		}
	}

	arnsByAction := make(map[string][]*regexp.Regexp, len(raw.Actions))
	for _, a := range raw.Actions {
		la := strings.ToLower(a.Name)
		actions[la] = struct{}{}
		// Always record an entry — even an empty one. An empty set means
		// "this action takes no service-specific condition keys" (only
		// aws:* globals); if we skipped the empty case, the check would
		// silently fall back to service-wide keys and let unrelated keys
		// through.
		set := make(map[string]struct{}, len(a.ActionConditionKeys))
		for _, k := range a.ActionConditionKeys {
			lk := strings.ToLower(k)
			set[lk] = struct{}{}
			allKeys[lk] = struct{}{} // union into service-wide fallback
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
				lk := strings.ToLower(k)
				set[lk] = struct{}{}
				allKeys[lk] = struct{}{}
			}
			for _, k := range keysByResource[strings.ToLower(r.Name)] {
				lk := strings.ToLower(k)
				set[lk] = struct{}{}
				allKeys[lk] = struct{}{}
			}
		}
		keysByAction[la] = set

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
		Name:         raw.Name,
		actions:      actions,
		allKeys:      allKeys,
		keysByAction: keysByAction,
		arnsByAction: arnsByAction,
		allArns:      allArns,
		keyTypes:     keyTypes,
	}, nil
}

// compileARNTemplate turns an AWS service-reference ARN format like
//
//	arn:${Partition}:s3:::${BucketName}/${ObjectName}
//
// into an anchored regex. `siblings` is the full list of ARN formats
// declared by the same service so the compiler can decide whether a
// template's last placeholder should be bounded or greedy — see the
// rules in arnPlaceholderPattern for the per-placeholder logic.
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
//  1. Non-last placeholder followed by '/' in the same template → "[^:/]*".
//     The literal '/' is a delimiter for the next segment, so the
//     placeholder must stop there. Example: ${BucketName} in
//     ":::${BucketName}/${ObjectName}".
//
//  2. Last placeholder with '/' anywhere in the preceding template text
//     → ".*". The template is path-shaped and the trailing value can
//     legitimately contain '/'. Example: ${ObjectName} in ":::${B}/${O}",
//     ${RoleNameWithPath} in ":role/${RoleNameWithPath}".
//
//  3. Last placeholder where a sibling template extends this one's
//     prefix with "/<...>" → "[^:/]*". This is the bucket-vs-object
//     pair: S3 bucket's ${BucketName} stays bounded because the object
//     template adds "/${ObjectName}", so an ARN with '/' is really an
//     object ARN and shouldn't satisfy the bucket-only resource.
//
//     3a. Last placeholder where a sibling colon-extends with ":${...}"
//     (a colon followed immediately by another placeholder, no literal
//     in between) → "[^:]*(?::[^:]+)?". This is the "qualifier tail"
//     shape: AWS's lambda function/layer, lex bot, states stateMachine,
//     etc. all add a single ":${Version}" or ":${Alias}" sibling to a
//     base resource type. The catalog declares those as separate
//     resource types and lists the base action against only the base
//     type, so a literal alias ARN like
//     "arn:aws:lambda:r:a:function:f:my-alias" would otherwise be
//     rejected on lambda:InvokeFunction. The trailing "(?::[^:]+)?" is
//     a single optional segment, so AWS's two-deep forms aren't
//     accidentally allowed (no "function:f:alias:typo"). Sibling
//     extensions with a literal between the colon and the next
//     placeholder ("...:log-group:${LG}:log-stream:${LS}") do not
//     trigger this rule — those are structural child resources, not
//     free-form qualifiers, and continue to use rule 4.
//
//  4. Last placeholder otherwise → "[^:]*(?::[*?])*". CloudWatch Logs
//     log-group ARNs land here: log group names contain '/'
//     ("/aws/codebuild/foo"), and the log-stream sibling extends with
//     ':log-stream:' (a literal between the colon and the next
//     placeholder), so neither rule 3 nor 3a triggers. The base class
//     is "[^:]*" (allow '/', forbid ':') so concrete child-resource
//     ARNs like "...:group:foo:sub:bar" don't accidentally satisfy a
//     short-only action's template. The trailing "(?::[*?])*" group
//     additionally accepts IAM wildcard tails like ":*" or ":?:*" —
//     the canonical CodeBuild policy ("...:log-group:/aws/codebuild/proj:*") relies
//     on this to refer to "the group plus any sub-resource."
//
//  5. Default (non-last placeholder, not followed by '/') → "[^:]*".
//     Allows '/' (needed for ${LogGroupName} appearing mid-template in
//     "...:log-group:${LogGroupName}:log-stream:..." where the real
//     value is "/aws/codebuild/foo") while still respecting the ':'
//     ARN separator.
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
		// Rule 3a: a sibling colon-extends with ":${...}" → allow a single
		// qualifier tail. The next two characters after the colon must be
		// "${", i.e. the placeholder begins immediately. Sibling extensions
		// with a literal between (":log-stream:${LS}") don't match here.
		if len(s) >= p[1]+3 && s[:p[1]] == tmpl[:p[1]] &&
			s[p[1]] == ':' && s[p[1]+1] == '$' && s[p[1]+2] == '{' {
			return "[^:]*(?::[^:]+)?"
		}
	}
	return "[^:]*(?::[*?])*"
}

func (c *Catalog) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	body := io.LimitReader(resp.Body, maxResponseBytes)
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, body)
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(body).Decode(out)
}
