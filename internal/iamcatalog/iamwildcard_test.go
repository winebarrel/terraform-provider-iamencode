package iamcatalog

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIamWildcardToRegex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"foo", "^foo$"},
		{"a*b", "^a.*b$"},
		{"a?b", "^a.b$"},
		{"arn:aws:svc:*:*:*", `^arn:aws:svc:.*:.*:.*$`},
		// Regex metacharacters in literals get escaped so they don't get
		// re-interpreted when we hand the result back to regexp/syntax.
		{"a.b+c", `^a\.b\+c$`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, iamWildcardToRegex(tc.in))
		})
	}
}

func TestRegexIntersects_MalformedFailsClosed(t *testing.T) {
	// Unparseable regex sources should propagate as "no intersection
	// proven" rather than panic. The validator drops the pattern silently
	// if compilation fails (it should never happen in normal flow — both
	// sides come from us — but the helper is exported within the package
	// and the defensive return is worth covering).
	assert.False(t, regexIntersects("[unterminated", "^a$"))
	assert.False(t, regexIntersects("^a$", "[unterminated"))
}

func TestAcceptedRanges(t *testing.T) {
	cases := []struct {
		name  string
		op    syntax.InstOp
		runes []rune
		want  [][2]rune
	}{
		{"any", syntax.InstRuneAny, nil, [][2]rune{{0, 0x10ffff}}},
		{"any-not-nl", syntax.InstRuneAnyNotNL, nil, [][2]rune{{0, '\n' - 1}, {'\n' + 1, 0x10ffff}}},
		{"single", syntax.InstRune1, []rune{'a'}, [][2]rune{{'a', 'a'}}},
		{"range", syntax.InstRune, []rune{'a', 'c', 'x', 'z'}, [][2]rune{{'a', 'c'}, {'x', 'z'}}},
		// Non-char-consuming ops must yield nil — the BFS uses this as a
		// signal that the instruction isn't a real character transition.
		{"match", syntax.InstMatch, nil, nil},
		{"nop", syntax.InstNop, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := acceptedRanges(syntax.Inst{Op: tc.op, Rune: tc.runes})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMatchesARN_OverlongValueFailsClosed(t *testing.T) {
	// Even if a runaway wildcarded ARN string would have intersected the
	// template, matchesARN must bail out before paying for the BFS.
	// "fails closed" here means "returns false." The template here
	// requires a ":sub:" literal that the value lacks, so strict match
	// fails and we'd otherwise enter the BFS fallback.
	tmpl := regexp.MustCompile(`^arn:[^:]*:svc:[^:]*:[^:]*:group:[^:]*:sub:.*$`)
	value := "arn:aws:svc:r:a:group:" + strings.Repeat("*", maxResourceLen+1)
	assert.False(t, matchesARN(tmpl, value))
}

func TestRegexIntersects(t *testing.T) {
	// Each case picks two regex sources and asserts whether they share any
	// matching string. Both anchored ^...$ to mirror the shape the rest of
	// the catalog uses.
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{
			name: "identical literal",
			a:    `^foo$`,
			b:    `^foo$`,
			want: true,
		},
		{
			name: "disjoint literals",
			a:    `^foo$`,
			b:    `^bar$`,
			want: false,
		},
		{
			name: "literal vs any-suffix wildcard",
			a:    `^arn:aws:svc:r:a:group:.*$`,
			b:    `^arn:aws:svc:[^:]*:[^:]*:group:[^:]*$`,
			want: true,
		},
		{
			name: "user '*' spans literal anchor in template",
			// The user pattern's ".*" tail must be allowed to absorb the
			// ":sub:<name>" segment the template demands. This is the
			// shape of the CloudWatch-Logs log-stream case.
			a:    `^arn:aws:svc:r:a:group:/path/to/foo:.*$`,
			b:    `^arn:aws:svc:[^:]*:[^:]*:group:[^:]*:sub:[^:]*$`,
			want: true,
		},
		{
			name: "user '*' covers multiple template segments",
			// "arn:aws:svc:*:*:*" — three trailing wildcards must be
			// allowed to span the template's ":group:<name>" segments.
			a:    `^arn:aws:svc:.*:.*:.*$`,
			b:    `^arn:aws:svc:[^:]*:[^:]*:group:[^:]*$`,
			want: true,
		},
		{
			name: "different service prefix never intersects",
			a:    `^arn:aws:OTHER:.*:.*:.*$`,
			b:    `^arn:[^:]*:svc:[^:]*:[^:]*:group:[^:]*$`,
			want: false,
		},
		{
			name: "bounded template rejects '/' in user wildcard segment",
			// The template's "[^:/]*" segment must not be satisfied by
			// the user's "X/Y" expansion — that '/' is a hard separator.
			a:    `^arn:aws:svc:::foo/bar$`,
			b:    `^arn:[^:]*:svc:::[^:/]*$`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, regexIntersects(tc.a, tc.b))
		})
	}
}
