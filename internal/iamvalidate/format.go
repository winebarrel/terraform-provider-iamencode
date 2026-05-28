package iamvalidate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// Beyond this many enum values we stop listing them inline and lean on the
// "did you mean" suggestion. Dumping the full conditionOperator enum (~150
// entries) drowns out the actual problem.
const enumDisplayLimit = 8

// formatError renders a ValidationError as a compile-error-style message:
// the failing instance path, a snippet of the input rendered as JSON with
// line numbers, and a caret pointing at the offending value.
func formatError(v any, ve *jsonschema.ValidationError) string {
	rendered := renderJSON(v)
	leaves := collectLeaves(ve, nil)

	seen := map[string]bool{}
	var blocks []string
	for _, leaf := range leaves {
		path := formatPath(leaf.path)
		msg := leafMessage(leaf.err)
		key := path + "\x00" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		blocks = append(blocks, formatLeaf(rendered, leaf, path, msg))
	}
	return "\n" + strings.Join(blocks, "\n\n")
}

// resolvedLeaf is a ValidationError paired with the InstanceLocation to
// report. The path is computed during traversal because some leaves (most
// notably kind.PropertyNames) reset their own InstanceLocation to empty: the
// library treats the property name as the instance, so we stitch the parent
// location and the property name together.
type resolvedLeaf struct {
	path  []string
	err   *jsonschema.ValidationError
	asKey bool // true when path points at an object key, not its value
}

// collectLeaves descends the error tree. For grouping nodes (oneOf/anyOf/allOf
// and the like) it keeps only the cause(s) whose subtree reaches the deepest
// InstanceLocation: that branch almost always matches the user's intended
// shape and skips noise like "got array, want object" for an array the schema
// also allows. parentPath threads the last non-empty InstanceLocation down so
// propertyNames leaves can resolve to a usable path.
func collectLeaves(e *jsonschema.ValidationError, parentPath []string) []*resolvedLeaf {
	effective := parentPath
	if len(e.InstanceLocation) > 0 {
		effective = e.InstanceLocation
	}
	if pn, ok := e.ErrorKind.(*kind.PropertyNames); ok {
		leafPath := append(append([]string(nil), effective...), pn.Property)
		return []*resolvedLeaf{{path: leafPath, err: e, asKey: true}}
	}
	if len(e.Causes) == 0 {
		return []*resolvedLeaf{{path: effective, err: e}}
	}
	causes := e.Causes
	if isGrouping(e.ErrorKind) {
		best := -1
		for _, c := range causes {
			if d := maxDepth(c); d > best {
				best = d
			}
		}
		var filtered []*jsonschema.ValidationError
		for _, c := range causes {
			if maxDepth(c) == best {
				filtered = append(filtered, c)
			}
		}
		causes = filtered
	}
	var out []*resolvedLeaf
	for _, c := range causes {
		out = append(out, collectLeaves(c, effective)...)
	}
	return out
}

func maxDepth(e *jsonschema.ValidationError) int {
	d := len(e.InstanceLocation)
	for _, c := range e.Causes {
		if cd := maxDepth(c); cd > d {
			d = cd
		}
	}
	return d
}

func isGrouping(k jsonschema.ErrorKind) bool {
	switch k.(type) {
	case *kind.OneOf, *kind.AnyOf, *kind.AllOf, *kind.Group, *kind.Schema, *kind.Reference, *kind.Not:
		return true
	}
	return false
}

func formatLeaf(r *renderedJSON, leaf *resolvedLeaf, pathStr, msg string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %s: %s", pathStr, msg)
	if snippet := r.snippet(leaf.path, leaf.asKey); snippet != "" {
		sb.WriteByte('\n')
		sb.WriteString(snippet)
	}
	return sb.String()
}

func formatPath(tokens []string) string {
	if len(tokens) == 0 {
		return "(root)"
	}
	var sb strings.Builder
	for i, t := range tokens {
		if isArrayIndex(t) {
			sb.WriteByte('[')
			sb.WriteString(t)
			sb.WriteByte(']')
			continue
		}
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(t)
	}
	return sb.String()
}

func isArrayIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// leafMessage renders the human-readable message for a leaf. PropertyNames is
// special-cased because we want to fold a "did you mean" hint sourced from
// the inner Enum cause into a single line.
func leafMessage(e *jsonschema.ValidationError) string {
	if pn, ok := e.ErrorKind.(*kind.PropertyNames); ok {
		msg := fmt.Sprintf("invalid property name %q", pn.Property)
		if hint := didYouMean(pn.Property, e); hint != "" {
			msg += ": " + hint
		}
		return msg
	}
	return kindMessage(e.ErrorKind)
}

func kindMessage(k jsonschema.ErrorKind) string {
	switch x := k.(type) {
	case *kind.Type:
		return fmt.Sprintf("got %s, want %s", x.Got, strings.Join(x.Want, " or "))
	case *kind.Enum:
		return formatEnumMessage(x)
	case *kind.Const:
		return fmt.Sprintf("value must be %s (got %s)", valueString(x.Want), valueString(x.Got))
	case *kind.Required:
		if len(x.Missing) == 1 {
			return fmt.Sprintf("missing required property %q", x.Missing[0])
		}
		quoted := make([]string, len(x.Missing))
		for i, m := range x.Missing {
			quoted[i] = strconv.Quote(m)
		}
		return fmt.Sprintf("missing required properties %s", strings.Join(quoted, ", "))
	case *kind.AdditionalProperties:
		quoted := make([]string, len(x.Properties))
		for i, p := range x.Properties {
			quoted[i] = strconv.Quote(p)
		}
		return fmt.Sprintf("unknown properties %s", strings.Join(quoted, ", "))
	case *kind.MinItems:
		return fmt.Sprintf("array must have at least %d item(s) (got %d)", x.Want, x.Got)
	case *kind.MaxItems:
		return fmt.Sprintf("array must have at most %d item(s) (got %d)", x.Want, x.Got)
	case *kind.MinProperties:
		return fmt.Sprintf("object must have at least %d property/properties (got %d)", x.Want, x.Got)
	case *kind.MaxProperties:
		return fmt.Sprintf("object must have at most %d property/properties (got %d)", x.Want, x.Got)
	case *kind.Pattern:
		return fmt.Sprintf("%q does not match pattern %q", x.Got, x.Want)
	case *kind.PropertyNames:
		return fmt.Sprintf("invalid property name %q", x.Property)
	case *kind.Not:
		return "value is not allowed here"
	case *kind.OneOf:
		if len(x.Subschemas) >= 2 {
			return fmt.Sprintf("value matched multiple allowed variants (%d and %d)", x.Subschemas[0], x.Subschemas[1])
		}
		return "value does not match any allowed variant"
	case *kind.AnyOf:
		return "value does not match any allowed variant"
	case *kind.AllOf:
		return "value does not match all required schemas"
	}
	return "validation failed"
}

// formatEnumMessage prints the enum violation. Short lists are enumerated
// inline; long ones are truncated and accompanied by a suggestion when the
// got value is close to one of the allowed strings.
func formatEnumMessage(x *kind.Enum) string {
	want := make([]string, len(x.Want))
	for i, w := range x.Want {
		want[i] = valueString(w)
	}
	got := valueString(x.Got)
	if len(want) <= enumDisplayLimit {
		return fmt.Sprintf("value must be one of %s (got %s)", strings.Join(want, ", "), got)
	}
	shown := strings.Join(want[:enumDisplayLimit], ", ")
	msg := fmt.Sprintf("value must be one of %s, and %d more (got %s)", shown, len(want)-enumDisplayLimit, got)
	if gs, ok := x.Got.(string); ok {
		if best := closestEnumString(gs, x.Want); best != "" {
			msg += fmt.Sprintf(": did you mean %q?", best)
		}
	}
	return msg
}

// didYouMean walks the cause chain looking for an enum and, if found, picks
// the closest allowed string to the offending value.
func didYouMean(got string, e *jsonschema.ValidationError) string {
	en := findEnumCause(e)
	if en == nil {
		return ""
	}
	if best := closestEnumString(got, en.Want); best != "" {
		return fmt.Sprintf("did you mean %q?", best)
	}
	return ""
}

func findEnumCause(e *jsonschema.ValidationError) *kind.Enum {
	if en, ok := e.ErrorKind.(*kind.Enum); ok {
		return en
	}
	for _, c := range e.Causes {
		if en := findEnumCause(c); en != nil {
			return en
		}
	}
	return nil
}

// closestEnumString returns the option closest to got by Levenshtein distance.
// Returns "" when nothing in want is within a length-relative threshold, since
// suggesting a wildly different string is more confusing than helpful.
func closestEnumString(got string, want []any) string {
	best := ""
	bestDist := -1
	for _, w := range want {
		ws, ok := w.(string)
		if !ok {
			continue
		}
		d := levenshtein(got, ws)
		if bestDist == -1 || d < bestDist {
			best, bestDist = ws, d
		}
	}
	if best == "" {
		return ""
	}
	threshold := utf8.RuneCountInString(got)/3 + 1
	if bestDist > threshold {
		return ""
	}
	return best
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = minInt(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func minInt(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func valueString(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case json.Number:
		return string(x)
	}
	return fmt.Sprintf("%v", v)
}

// --- JSON renderer that records line/column for every value position ---

type valueLoc struct {
	line     int // 1-indexed line of the value's first token
	col      int // 1-indexed column of the value's first character
	width    int // visual width of the value's first token (0 for multi-line)
	endLine  int // 1-indexed line of the value's last character
	endWidth int // visual width of the value's last line
}

type renderedJSON struct {
	lines   []string
	locs    map[string]valueLoc
	keyLocs map[string]valueLoc // location of the object key (the quoted name itself)
}

func renderJSON(v any) *renderedJSON {
	r := &renderedJSON{locs: map[string]valueLoc{}, keyLocs: map[string]valueLoc{}}
	var sb strings.Builder
	r.writeValue(&sb, v, 0, nil)
	r.lines = strings.Split(sb.String(), "\n")
	return r
}

func pathKey(p []string) string {
	return strings.Join(p, "\x00")
}

func (r *renderedJSON) cursor(sb *strings.Builder) (line, col int) {
	s := sb.String()
	line = strings.Count(s, "\n") + 1
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		col = len(s) - i
	} else {
		col = len(s) + 1
	}
	return
}

func (r *renderedJSON) writeValue(sb *strings.Builder, v any, indent int, path []string) {
	startLine, startCol := r.cursor(sb)
	width := 0
	switch x := v.(type) {
	case map[string]any:
		r.writeObject(sb, x, indent, path)
	case []any:
		r.writeArray(sb, x, indent, path)
	case string:
		s := strconv.Quote(x)
		width = len(s)
		sb.WriteString(s)
	case bool:
		s := strconv.FormatBool(x)
		width = len(s)
		sb.WriteString(s)
	case float64:
		s := strconv.FormatFloat(x, 'g', -1, 64)
		width = len(s)
		sb.WriteString(s)
	case json.Number:
		width = len(x)
		sb.WriteString(string(x))
	case nil:
		sb.WriteString("null")
		width = 4
	default:
		b, _ := json.Marshal(v)
		sb.Write(b)
		width = len(b)
	}
	endLine, endCol := r.cursor(sb)
	r.locs[pathKey(path)] = valueLoc{
		line:     startLine,
		col:      startCol,
		width:    width,
		endLine:  endLine,
		endWidth: endCol - 1,
	}
}

func (r *renderedJSON) writeObject(sb *strings.Builder, m map[string]any, indent int, path []string) {
	if len(m) == 0 {
		sb.WriteString("{}")
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb.WriteString("{\n")
	for i, k := range keys {
		sb.WriteString(strings.Repeat("  ", indent+1))
		keyLine, keyCol := r.cursor(sb)
		quotedKey := strconv.Quote(k)
		sb.WriteString(quotedKey)
		sub := make([]string, len(path)+1)
		copy(sub, path)
		sub[len(path)] = k
		r.keyLocs[pathKey(sub)] = valueLoc{
			line:     keyLine,
			col:      keyCol,
			width:    len(quotedKey),
			endLine:  keyLine,
			endWidth: keyCol + len(quotedKey) - 1,
		}
		sb.WriteString(": ")
		r.writeValue(sb, m[k], indent+1, sub)
		if i < len(keys)-1 {
			sb.WriteByte(',')
		}
		sb.WriteByte('\n')
	}
	sb.WriteString(strings.Repeat("  ", indent))
	sb.WriteByte('}')
}

func (r *renderedJSON) writeArray(sb *strings.Builder, arr []any, indent int, path []string) {
	if len(arr) == 0 {
		sb.WriteString("[]")
		return
	}
	sb.WriteString("[\n")
	for i, v := range arr {
		sb.WriteString(strings.Repeat("  ", indent+1))
		sub := make([]string, len(path)+1)
		copy(sub, path)
		sub[len(path)] = strconv.Itoa(i)
		r.writeValue(sb, v, indent+1, sub)
		if i < len(arr)-1 {
			sb.WriteByte(',')
		}
		sb.WriteByte('\n')
	}
	sb.WriteString(strings.Repeat("  ", indent))
	sb.WriteByte(']')
}

// snippet builds a compile-error-style code frame around the given path.
// When asKey is true, the location targets the property *name* (the quoted
// key) rather than its value, so the caret lands under the bad key. Returns
// "" if the path can't be located.
func (r *renderedJSON) snippet(path []string, asKey bool) string {
	var loc valueLoc
	var ok bool
	if asKey {
		loc, ok = r.keyLocs[pathKey(path)]
	}
	if !ok {
		loc, ok = r.locs[pathKey(path)]
	}
	if !ok {
		return ""
	}

	// Line numbers are deliberately omitted: we render the JSON ourselves
	// (sorted keys, fixed indent) so any number we print refers to our
	// internal render, not the user's source. The ">" marker plus caret are
	// enough to point at the failure without misleading the reader.
	const context = 2
	start := max(loc.line-context, 1)
	end := min(loc.endLine+context, len(r.lines))

	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := " "
		if i >= loc.line && i <= loc.endLine {
			marker = ">"
		}
		fmt.Fprintf(&sb, "  %s | %s\n", marker, r.lines[i-1])
		// Caret line only for single-line values. Prefix width must match the
		// content line's "  {marker} | " layout exactly.
		if i == loc.line && loc.endLine == loc.line && loc.width > 0 {
			fmt.Fprintf(&sb, "    | %s%s\n",
				strings.Repeat(" ", loc.col-1),
				strings.Repeat("^", loc.width),
			)
		}
	}
	return sb.String()
}
