// Package iamcatalog fetches AWS service reference JSON on demand
// (https://servicereference.us-east-1.amazonaws.com) and caches the result in
// memory for the lifetime of the process. Within a single `terraform plan`
// the provider process is long-lived, so each service is fetched at most once.
//
// Failures degrade gracefully: a network error returns ErrUnavailable so the
// caller can skip catalog-based checks rather than fail the whole plan.
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
	// The caller should treat this as a validation failure (likely a typo).
	ErrUnknownService = errors.New("unknown AWS service prefix")

	// ErrUnavailable — the catalog could not be fetched (network down, timeout,
	// HTTP error). The caller should treat this as "skip catalog validation"
	// rather than fail; the embedded schema still ran.
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
	// for that action. An entry is always present for every known action
	// (possibly empty, meaning "this action doesn't operate on a resource").
	arnsByAction map[string][]*regexp.Regexp

	// allArns is the union of every ARN format the service declares — used
	// as the fallback when the action name is a wildcard (e.g. "s3:*") and
	// we therefore can't narrow the resource types.
	allArns []*regexp.Regexp
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
			Resources           []struct {
				Name string `json:"Name"`
			} `json:"Resources"`
		} `json:"Actions"`
		ConditionKeys []struct {
			Name string `json:"Name"`
		} `json:"ConditionKeys"`
		Resources []struct {
			Name       string   `json:"Name"`
			ARNFormats []string `json:"ARNFormats"`
		} `json:"Resources"`
	}
	if err := c.getJSON(ctx, url, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, prefix, err)
	}
	actions := make(map[string]struct{}, len(raw.Actions))
	keysByAction := make(map[string]map[string]struct{}, len(raw.Actions))
	allKeys := make(map[string]struct{}, len(raw.ConditionKeys))
	for _, ck := range raw.ConditionKeys {
		allKeys[strings.ToLower(ck.Name)] = struct{}{}
	}

	// Compile each resource type's ARN templates once per service.
	patternsByType := make(map[string][]*regexp.Regexp, len(raw.Resources))
	allArns := make([]*regexp.Regexp, 0)
	for _, r := range raw.Resources {
		patterns := make([]*regexp.Regexp, 0, len(r.ARNFormats))
		for _, tmpl := range r.ARNFormats {
			if re := compileARNTemplate(tmpl); re != nil {
				patterns = append(patterns, re)
				allArns = append(allArns, re)
			}
		}
		patternsByType[strings.ToLower(r.Name)] = patterns
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
	}, nil
}

// compileARNTemplate turns an AWS service-reference ARN format like
//
//	arn:${Partition}:s3:::${BucketName}/${ObjectName}
//
// into an anchored regex. Placeholders become [^:]* — IAM ARN segments are
// colon-separated and the placeholders never span them in AWS's templates,
// so this matches every legitimate ARN we've seen without resorting to
// full URI-style parsing. A nil return means the template was malformed
// and should be ignored.
func compileARNTemplate(tmpl string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(tmpl); {
		if i+1 < len(tmpl) && tmpl[i] == '$' && tmpl[i+1] == '{' {
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				return nil
			}
			b.WriteString("[^:]*")
			i += end + 1
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(tmpl[i])))
		i++
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
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
