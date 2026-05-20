package iamvalidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_InvalidEffect_Snippet(t *testing.T) {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Effect":   "Allowx",
				"Action":   []any{"s3:GetObject"},
				"Resource": "arn:aws:s3:::my-bucket/*",
			},
		},
	}
	err := Validate(policy)
	require.Error(t, err)

	out := err.Error()
	assert.Contains(t, out, "Statement[0].Effect: value must be one of \"Allow\", \"Deny\" (got \"Allowx\")")
	assert.Contains(t, out, `"Effect": "Allowx"`)
	assert.Regexp(t, `>\s+\d+ \| .*"Effect": "Allowx"`, out)
	assert.Contains(t, out, "^^^^^^^^") // 8 carets matching "Allowx" with surrounding quotes

	// noisy "got array, want object" branch from the Statement oneOf is dropped.
	assert.NotContains(t, out, "got array, want object")

	// wrapped error still unwraps to the original ValidationError.
	var ve *jsonschema.ValidationError
	assert.True(t, errors.As(err, &ve))
}

func TestValidate_MissingVersion(t *testing.T) {
	policy := map[string]any{
		"Statement": []any{
			map[string]any{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
		},
	}
	err := Validate(policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `(root): missing required property "Version"`)
}

func TestValidate_MissingRequired_PointsAtObject_AllLinesMarked(t *testing.T) {
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Action":   "s3:*",
				"Resource": "*",
			},
		},
	}
	err := Validate(policy)
	require.Error(t, err)

	out := err.Error()
	assert.Contains(t, out, `Statement[0]: missing required property "Effect"`)

	// The failing value is a multi-line object — every line of the object
	// (the opening "{", the property lines, and the closing "}") gets a ">"
	// marker, and no caret line should appear.
	gutters := 0
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, ">") && strings.Contains(line, " | ") {
			gutters++
		}
	}
	assert.GreaterOrEqual(t, gutters, 4, "expected > marker on every line of the failing object")
	assert.NotContains(t, out, "^^^") // no caret for multi-line values
}

func TestValidate_CaretAlignedWithValue(t *testing.T) {
	// The caret line's "|" must align with the content line's "|", and the
	// first "^" must sit directly under the first character of the offending
	// value in the rendered JSON.
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect":   "Allowx",
				"Action":   "s3:*",
				"Resource": "*",
			},
		},
	}
	out := Validate(policy).Error()

	lines := strings.Split(out, "\n")
	contentIdx, caretIdx := -1, -1
	for i, l := range lines {
		if contentIdx == -1 && strings.Contains(l, `"Effect": "Allowx"`) {
			contentIdx = i
		}
		if caretIdx == -1 && strings.Contains(l, "^^^^^^^^") {
			caretIdx = i
		}
	}
	require.NotEqual(t, -1, contentIdx, "content line not found in output: %q", out)
	require.NotEqual(t, -1, caretIdx, "caret line not found in output: %q", out)
	require.Equal(t, contentIdx+1, caretIdx, "caret line should follow the content line")

	content, caret := lines[contentIdx], lines[caretIdx]
	assert.Equal(t,
		strings.Index(content, "|"),
		strings.Index(caret, "|"),
		"pipe must align between content and caret lines",
	)
	assert.Equal(t,
		strings.Index(content, `"Allowx"`),
		strings.Index(caret, "^"),
		"first caret must sit under the first char of the value",
	)
}

func TestSnippet_GutterWidthAlignment(t *testing.T) {
	// The gutter is %*d sized — when the rendered JSON crosses 10 or 100
	// lines, both the content and caret prefixes must grow together so the
	// "|" column stays put.
	cases := []struct {
		name       string
		itemCount  int
		wantGutter int
	}{
		{"single digit", 1, 1},
		{"two digits", 12, 2},   // ~50 rendered lines
		{"three digits", 30, 3}, // ~120 rendered lines
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stmts := make([]any, c.itemCount)
			for i := range stmts {
				stmts[i] = map[string]any{
					"Effect":   "Allow",
					"Action":   "s3:*",
					"Resource": "*",
				}
			}
			// Inject one bad statement at the END so the error path lands
			// deep in the rendered JSON, forcing a wide gutter.
			stmts[len(stmts)-1] = map[string]any{
				"Effect":   "Bogus",
				"Action":   "s3:*",
				"Resource": "*",
			}
			out := Validate(map[string]any{"Statement": stmts}).Error()

			var content, caret string
			for line := range strings.SplitSeq(out, "\n") {
				if strings.Contains(line, `"Bogus"`) && strings.Contains(line, "|") {
					content = line
				}
				if strings.Contains(line, "^") && strings.Contains(line, "|") {
					caret = line
				}
			}
			require.NotEmpty(t, content)
			require.NotEmpty(t, caret)

			cPipe := strings.Index(content, "|")
			kPipe := strings.Index(caret, "|")
			assert.Equal(t, cPipe, kPipe,
				"gutter %d-digit: pipe must align\n  content: %q\n  caret:   %q",
				c.wantGutter, content, caret)

			// The first caret should still land under the first char of the value.
			assert.Equal(t,
				strings.Index(content, `"Bogus"`),
				strings.Index(caret, "^"),
				"gutter %d-digit: caret must sit under the value\n  content: %q\n  caret:   %q",
				c.wantGutter, content, caret)
		})
	}
}

func TestValidate_StringWithEmbeddedNewline_StillSingleLineInSnippet(t *testing.T) {
	// A string value containing an embedded \n becomes a single line in the
	// rendered JSON (Go's strconv.Quote escapes it). The caret should match
	// the *escaped* width, not the raw width.
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect":   "line1\nline2", // not "Allow"/"Deny" → enum violation
				"Action":   "s3:*",
				"Resource": "*",
			},
		},
	}
	err := Validate(policy)
	require.Error(t, err)

	out := err.Error()
	assert.Contains(t, out, `Statement[0].Effect`)
	// The rendered line shows the escape sequence, not a literal newline.
	assert.Contains(t, out, `"line1\nline2"`)
	// Caret length = len(`"line1\nline2"`) = 14.
	assert.Contains(t, out, strings.Repeat("^", 14))
}

func TestValidate_ConditionValue_Caret(t *testing.T) {
	// Exercises a deeply nested path; the failing value is a string passing
	// through the conditionValue oneOf branch.
	policy := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect":   "Allow",
				"Action":   "s3:*",
				"Resource": "*",
				"Condition": map[string]any{
					"NotAnOperator": map[string]any{
						"s3:prefix": "home/",
					},
				},
			},
		},
	}
	err := Validate(policy)
	require.Error(t, err)

	out := err.Error()
	// Either path-name failure or propertyNames failure — both name the bad operator.
	assert.Contains(t, out, "NotAnOperator")
}

// Regression: a typo'd condition operator used to render as `(root): value must
// be one of ...` with the entire ~150-entry conditionOperator enum dumped
// inline. The fix resolves the path through the parent of the propertyNames
// node, drops the enum dump, and offers a Levenshtein-based suggestion.
func TestValidate_BadConditionOperator_PropertyNamesPath(t *testing.T) {
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Effect":   "Allow",
				"Action":   "s3:ListBucket",
				"Resource": "*",
				"Condition": map[string]any{
					"StringEqualsx": map[string]any{
						"s3:prefix": "home/",
					},
				},
			},
		},
	}
	out := Validate(policy).Error()

	assert.Contains(t, out, `Statement[0].Condition.StringEqualsx: invalid property name "StringEqualsx"`)
	assert.Contains(t, out, `did you mean "StringEquals"?`)
	// Path must not collapse to (root) anymore.
	assert.NotContains(t, out, "(root):")
	// The full enum list must NOT be dumped (sample two entries that used to appear).
	assert.NotContains(t, out, `"ForAllValues:NumericLessThanEquals"`)
	assert.NotContains(t, out, `"ForAnyValue:ArnNotLike"`)
	// Caret should sit under the quoted key, width 15 (`"StringEqualsx"`).
	assert.Contains(t, out, strings.Repeat("^", 15))
}

// Long enum lists (here: the conditionOperator enum reached via a different
// path) get truncated rather than dumped wholesale.
func TestFormatEnumMessage_TruncatesLongEnum(t *testing.T) {
	want := make([]any, 30)
	for i := range want {
		want[i] = fmt.Sprintf("opt%02d", i)
	}
	msg := formatEnumMessage(&kind.Enum{Got: "opt03x", Want: want})
	assert.Contains(t, msg, "and 22 more")    // 30 - 8 displayed
	assert.Contains(t, msg, `(got "opt03x")`) // got value preserved
	assert.Contains(t, msg, `did you mean "opt03"?`)
}

func TestClosestEnumString_RejectsFarMatches(t *testing.T) {
	// Wildly different inputs should produce no suggestion (avoids confusing
	// hints like "did you mean 'Null'?" for arbitrary strings).
	want := []any{"StringEquals", "NumericEquals", "Bool"}
	assert.Equal(t, "", closestEnumString("xxxxxxxxxx", want))
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
		{"abc", "abc", 0},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, levenshtein(c.a, c.b), "levenshtein(%q,%q)", c.a, c.b)
	}
}

func TestFormatPath(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "(root)"},
		{[]string{"Statement"}, "Statement"},
		{[]string{"Statement", "0"}, "Statement[0]"},
		{[]string{"Statement", "0", "Effect"}, "Statement[0].Effect"},
		{[]string{"Condition", "StringEquals", "s3:prefix", "0"}, "Condition.StringEquals.s3:prefix[0]"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, formatPath(c.in), "path: %v", c.in)
	}
}

func TestIsArrayIndex(t *testing.T) {
	cases := map[string]bool{
		"":    false, // empty string is not an index
		"0":   true,
		"123": true,
		"abc": false,
		"1a":  false,
		"-1":  false,
		"0.5": false,
	}
	for in, want := range cases {
		assert.Equal(t, want, isArrayIndex(in), "input: %q", in)
	}
}

func TestKindMessage_AllBranches(t *testing.T) {
	cases := []struct {
		name string
		kind jsonschema.ErrorKind
		want string
	}{
		{"Type", &kind.Type{Got: "number", Want: []string{"string"}}, "got number, want string"},
		{"Type multi-want", &kind.Type{Got: "object", Want: []string{"string", "array"}}, "got object, want string or array"},
		{"Enum", &kind.Enum{Got: "ALLOW", Want: []any{"Allow", "Deny"}}, `value must be one of "Allow", "Deny" (got "ALLOW")`},
		{"Const", &kind.Const{Got: "x", Want: "*"}, `value must be "*" (got "x")`},
		{"Required single", &kind.Required{Missing: []string{"Effect"}}, `missing required property "Effect"`},
		{"Required multi", &kind.Required{Missing: []string{"a", "b"}}, `missing required properties "a", "b"`},
		{"AdditionalProperties", &kind.AdditionalProperties{Properties: []string{"foo"}}, `unknown properties "foo"`},
		{"MinItems", &kind.MinItems{Got: 0, Want: 1}, "array must have at least 1 item(s) (got 0)"},
		{"MaxItems", &kind.MaxItems{Got: 5, Want: 3}, "array must have at most 3 item(s) (got 5)"},
		{"MinProperties", &kind.MinProperties{Got: 0, Want: 1}, "object must have at least 1 property/properties (got 0)"},
		{"MaxProperties", &kind.MaxProperties{Got: 5, Want: 3}, "object must have at most 3 property/properties (got 5)"},
		{"Pattern", &kind.Pattern{Got: "x y", Want: "^x$"}, `"x y" does not match pattern "^x$"`},
		{"PropertyNames", &kind.PropertyNames{Property: "Bad"}, `invalid property name "Bad"`},
		{"Not", &kind.Not{}, "value is not allowed here"},
		{"OneOf no match", &kind.OneOf{}, "value does not match any allowed variant"},
		{"OneOf many match", &kind.OneOf{Subschemas: []int{0, 1}}, "value matched multiple allowed variants (0 and 1)"},
		{"AnyOf", &kind.AnyOf{}, "value does not match any allowed variant"},
		{"AllOf", &kind.AllOf{}, "value does not match all required schemas"},
		{"unhandled", &kind.UniqueItems{}, "validation failed"}, // fallthrough branch
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, kindMessage(c.kind))
		})
	}
}

func TestValueString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"hello", `"hello"`},
		{nil, "null"},
		{true, "true"},
		{false, "false"},
		{1.5, "1.5"},
		{json.Number("42"), "42"},
		{[]int{1, 2}, "[1 2]"}, // default branch
	}
	for _, c := range cases {
		assert.Equal(t, c.want, valueString(c.in))
	}
}

func TestIsGrouping(t *testing.T) {
	groupings := []jsonschema.ErrorKind{
		&kind.OneOf{}, &kind.AnyOf{}, &kind.AllOf{}, &kind.Group{},
		&kind.Schema{}, &kind.Reference{}, &kind.Not{},
	}
	for _, k := range groupings {
		assert.True(t, isGrouping(k), "expected grouping: %T", k)
	}
	leaves := []jsonschema.ErrorKind{
		&kind.Type{}, &kind.Enum{}, &kind.Required{}, &kind.Pattern{},
	}
	for _, k := range leaves {
		assert.False(t, isGrouping(k), "expected non-grouping: %T", k)
	}
}

func TestRenderJSON_LocatesNestedPath(t *testing.T) {
	v := map[string]any{
		"Statement": []any{
			map[string]any{
				"Effect": "Allowx",
				"Action": []any{"s3:GetObject"},
			},
		},
	}
	r := renderJSON(v)

	loc, ok := r.locs[pathKey([]string{"Statement", "0", "Effect"})]
	require.True(t, ok)
	assert.Equal(t, loc.line, loc.endLine, "single-line value")
	assert.Equal(t, 8, loc.width, `"Allowx" is 8 chars including quotes`)

	require.Less(t, loc.line, len(r.lines)+1)
	assert.Contains(t, r.lines[loc.line-1], `"Effect": "Allowx"`)
}

func TestRenderJSON_EmptyContainers(t *testing.T) {
	r := renderJSON(map[string]any{
		"obj": map[string]any{},
		"arr": []any{},
	})
	out := strings.Join(r.lines, "\n")
	assert.Contains(t, out, `"obj": {}`)
	assert.Contains(t, out, `"arr": []`)
}

func TestRenderJSON_MultiElementArray(t *testing.T) {
	// Exercises the comma branch in writeArray.
	r := renderJSON(map[string]any{
		"items": []any{"a", "b", "c"},
	})
	out := strings.Join(r.lines, "\n")
	assert.Contains(t, out, `"a",`)
	assert.Contains(t, out, `"b",`)
	assert.Contains(t, out, `"c"`)
}

func TestRenderJSON_AllPrimitiveTypes(t *testing.T) {
	v := map[string]any{
		"s":   "x",
		"b":   true,
		"n":   1.5,
		"jn":  json.Number("42"),
		"z":   nil,
		"odd": []int{1, 2}, // hits the default branch via json.Marshal
	}
	r := renderJSON(v)
	out := strings.Join(r.lines, "\n")
	assert.Contains(t, out, `"s": "x"`)
	assert.Contains(t, out, `"b": true`)
	assert.Contains(t, out, `"n": 1.5`)
	assert.Contains(t, out, `"jn": 42`)
	assert.Contains(t, out, `"z": null`)
	assert.Contains(t, out, `"odd": [1,2]`)
}

func TestSnippet_UnknownPath_ReturnsEmpty(t *testing.T) {
	r := renderJSON(map[string]any{"Statement": []any{}})
	assert.Empty(t, r.snippet([]string{"DoesNotExist"}, false))
}

func TestFormatError_DedupesIdenticalLeaves(t *testing.T) {
	// Two different oneOf branches converge on the same path+message; we
	// should print the message exactly once.
	leaf := &jsonschema.ValidationError{
		InstanceLocation: []string{"x"},
		ErrorKind:        &kind.Type{Got: "number", Want: []string{"string"}},
	}
	root := &jsonschema.ValidationError{
		InstanceLocation: []string{"x"},
		ErrorKind:        &kind.OneOf{},
		Causes:           []*jsonschema.ValidationError{leaf, leaf},
	}
	out := formatError(map[string]any{"x": 1.0}, root)
	occurrences := strings.Count(out, "got number, want string")
	assert.Equal(t, 1, occurrences, "duplicate leaves should be collapsed")
}

func TestFormatError_RootPath(t *testing.T) {
	// A leaf with an empty InstanceLocation should render as "(root)".
	root := &jsonschema.ValidationError{
		InstanceLocation: nil,
		ErrorKind:        &kind.Required{Missing: []string{"Statement"}},
	}
	out := formatError(map[string]any{}, root)
	assert.Contains(t, out, `(root): missing required property "Statement"`)
}
