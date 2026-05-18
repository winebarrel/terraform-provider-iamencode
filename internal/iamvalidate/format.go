package iamvalidate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// formatError renders a ValidationError as a compile-error-style message:
// the failing instance path, a snippet of the input rendered as JSON with
// line numbers, and a caret pointing at the offending value.
func formatError(v any, ve *jsonschema.ValidationError) string {
	rendered := renderJSON(v)
	leaves := collectLeaves(ve)

	seen := map[string]bool{}
	var blocks []string
	for _, leaf := range leaves {
		path := formatPath(leaf.InstanceLocation)
		msg := kindMessage(leaf.ErrorKind)
		key := path + "\x00" + msg
		if seen[key] {
			continue
		}
		seen[key] = true
		blocks = append(blocks, formatLeaf(rendered, leaf.InstanceLocation, path, msg))
	}
	return "\n" + strings.Join(blocks, "\n\n")
}

// collectLeaves descends the error tree. For grouping nodes (oneOf/anyOf/allOf
// and friends) it keeps only the cause(s) whose subtree reaches the deepest
// InstanceLocation — that branch almost always matches the user's intended
// shape and skips noise like "got array, want object" for an array that the
// schema also allows.
func collectLeaves(e *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(e.Causes) == 0 {
		return []*jsonschema.ValidationError{e}
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
	var out []*jsonschema.ValidationError
	for _, c := range causes {
		out = append(out, collectLeaves(c)...)
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

func formatLeaf(r *renderedJSON, path []string, pathStr, msg string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %s: %s", pathStr, msg)
	if snippet := r.snippet(path); snippet != "" {
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

func kindMessage(k jsonschema.ErrorKind) string {
	switch x := k.(type) {
	case *kind.Type:
		return fmt.Sprintf("got %s, want %s", x.Got, strings.Join(x.Want, " or "))
	case *kind.Enum:
		want := make([]string, len(x.Want))
		for i, w := range x.Want {
			want[i] = valueString(w)
		}
		return fmt.Sprintf("value must be one of %s (got %s)", strings.Join(want, ", "), valueString(x.Got))
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
	lines []string
	locs  map[string]valueLoc
}

func renderJSON(v any) *renderedJSON {
	r := &renderedJSON{locs: map[string]valueLoc{}}
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
		sb.WriteString(strconv.Quote(k))
		sb.WriteString(": ")
		sub := make([]string, len(path)+1)
		copy(sub, path)
		sub[len(path)] = k
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
// Returns "" if the path can't be located.
func (r *renderedJSON) snippet(path []string) string {
	loc, ok := r.locs[pathKey(path)]
	if !ok {
		return ""
	}

	const context = 2
	start := max(loc.line-context, 1)
	end := min(loc.endLine+context, len(r.lines))
	gutter := len(strconv.Itoa(end))

	var sb strings.Builder
	for i := start; i <= end; i++ {
		marker := " "
		if i >= loc.line && i <= loc.endLine {
			marker = ">"
		}
		fmt.Fprintf(&sb, "  %s %*d | %s\n", marker, gutter, i, r.lines[i-1])
		// Caret line only for single-line values. Prefix width must match the
		// content line's "  {marker} {gutter} | " layout exactly.
		if i == loc.line && loc.endLine == loc.line && loc.width > 0 {
			fmt.Fprintf(&sb, "    %s | %s%s\n",
				strings.Repeat(" ", gutter),
				strings.Repeat(" ", loc.col-1),
				strings.Repeat("^", loc.width),
			)
		}
	}
	return sb.String()
}
