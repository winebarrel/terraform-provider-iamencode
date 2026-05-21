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
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultEndpoint = "https://servicereference.us-east-1.amazonaws.com"
	defaultTimeout  = 3 * time.Second
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
func (c *Catalog) Lookup(ctx context.Context, prefix string) (*Service, error) {
	key := strings.ToLower(prefix)
	if v, ok := c.services.Load(key); ok {
		e := v.(serviceEntry)
		return e.svc, e.err
	}
	v, _, _ := c.sf.Do(key, func() (any, error) {
		// Re-check inside the singleflight in case another caller already finished.
		if v, ok := c.services.Load(key); ok {
			return v, nil
		}
		svc, err := c.fetchService(ctx, key)
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
			Name string `json:"Name"`
		} `json:"Actions"`
	}
	if err := c.getJSON(ctx, url, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, prefix, err)
	}
	actions := make(map[string]struct{}, len(raw.Actions))
	for _, a := range raw.Actions {
		actions[strings.ToLower(a.Name)] = struct{}{}
	}
	return &Service{Name: raw.Name, actions: actions}, nil
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
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
