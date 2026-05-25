package iamcatalog

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
)

// Endpoint exposes the unexported endpoint field so external tests can
// verify normalization of the constructor argument.
func (c *Catalog) Endpoint() string { return c.endpoint }
