package iamcatalog

import (
	"context"
	"time"
)

// Exported for external (_test package) tests. Only compiled at test time,
// so the package's public API stays unchanged.

var (
	IamWildcardToRegex  = iamWildcardToRegex
	RegexIntersects     = regexIntersects
	AcceptedRanges      = acceptedRanges
	MatchesARN          = matchesARN
	CompileARNTemplate  = compileARNTemplate
	SplitPlaceholderKey = splitPlaceholderKey
	SplitAction         = splitAction
	IsOIDCConditionKey  = isOIDCConditionKey
)

const (
	MaxResourceLen   = maxResourceLen
	MaxResponseBytes = maxResponseBytes
	MaxFetchAttempts = maxFetchAttempts
)

// SetRetryBaseDelay overrides the retry backoff base so tests exercising the
// retry path do not sleep for real. Returns a func that restores the old value.
func SetRetryBaseDelay(d time.Duration) (restore func()) {
	old := retryBaseDelay
	retryBaseDelay = d
	return func() { retryBaseDelay = old }
}

// GetJSON exposes the retrying fetcher directly. Lookup always feeds it
// context.Background(), so driving ctx cancellation during the backoff wait
// is only possible through this seam.
func (c *Catalog) GetJSON(ctx context.Context, url string, out any) error {
	return c.getJSON(ctx, url, out)
}

// Endpoint exposes the unexported endpoint field so external tests can
// verify normalization of the constructor argument.
func (c *Catalog) Endpoint() string { return c.endpoint }
