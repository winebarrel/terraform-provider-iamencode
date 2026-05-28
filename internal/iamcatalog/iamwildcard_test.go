package iamcatalog_test

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
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
			assert.Equal(t, tc.want, iamcatalog.IamWildcardToRegex(tc.in))
		})
	}
}

func TestRegexIntersects_MalformedFailsClosed(t *testing.T) {
	// Unparseable regex sources should propagate as "no intersection
	// proven" rather than panic. The validator drops the pattern silently
	// if compilation fails. It should never happen in normal flow since
	// both sides come from us, but the helper guards against it and the
	// defensive return is worth covering.
	assert.False(t, iamcatalog.RegexIntersects("[unterminated", "^a$"))
	assert.False(t, iamcatalog.RegexIntersects("^a$", "[unterminated"))
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
		// Non-char-consuming ops must yield nil; the BFS uses this as a
		// signal that the instruction isn't a real character transition.
		{"match", syntax.InstMatch, nil, nil},
		{"nop", syntax.InstNop, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iamcatalog.AcceptedRanges(syntax.Inst{Op: tc.op, Rune: tc.runes})
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
	value := "arn:aws:svc:r:a:group:" + strings.Repeat("*", iamcatalog.MaxResourceLen+1)
	assert.False(t, iamcatalog.MatchesARN(tmpl, value))
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
			// "arn:aws:svc:*:*:*": three trailing wildcards must be
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
			// the user's "X/Y" expansion; '/' is a hard separator.
			a:    `^arn:aws:svc:::foo/bar$`,
			b:    `^arn:[^:]*:svc:::[^:/]*$`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, iamcatalog.RegexIntersects(tc.a, tc.b))
		})
	}
}
