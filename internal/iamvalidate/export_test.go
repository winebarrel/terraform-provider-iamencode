package iamvalidate

// Exported for external (_test package) tests. Only compiled at test time, so
// production callers don't see these symbols and the package's public API
// stays unchanged.

var (
	FormatEnumMessage = formatEnumMessage
	ClosestEnumString = closestEnumString
	DidYouMean        = didYouMean
	FindEnumCause     = findEnumCause
	Levenshtein       = levenshtein
	FormatPath        = formatPath
	IsArrayIndex      = isArrayIndex
	KindMessage       = kindMessage
	ValueString       = valueString
	IsGrouping        = isGrouping
	RenderJSON        = renderJSON
	PathKey           = pathKey
	FormatError       = formatError
	Compile           = compile
	MustCompile       = mustCompile
)

// Accessors so external tests can read fields/call methods on the unexported
// renderedJSON / valueLoc types without breaking encapsulation in production.
func (r *renderedJSON) Lines() []string { return r.lines }
func (r *renderedJSON) Snippet(path []string, asKey bool) string {
	return r.snippet(path, asKey)
}
func (r *renderedJSON) LocAt(key string) (line, endLine, width int, ok bool) {
	loc, exists := r.locs[key]
	if !exists {
		return 0, 0, 0, false
	}
	return loc.line, loc.endLine, loc.width, true
}
