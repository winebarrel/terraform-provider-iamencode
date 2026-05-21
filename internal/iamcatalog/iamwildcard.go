package iamcatalog

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// matchesARN reports whether `value` is accepted by the compiled ARN
// `template`. When strict regex matching fails and the value carries IAM
// wildcards ('*' / '?'), it falls back to an IAM-aware check that treats
// the value itself as a pattern and asks whether any concrete ARN
// satisfies BOTH the user pattern and the template.
//
// This second pass is what lets policies like
//
//	"arn:aws:logs:*:*:*"
//	"arn:aws:logs:r:a:log-group:/aws/lambda/foo:*"
//
// pass the validator: the user's '*' is meant to span literal anchors
// like ':log-group:' or ':log-stream:' the same way IAM expands it at
// evaluation time, but the strict regex match treats '*' as a single
// character and so falsely rejects them.
func matchesARN(template *regexp.Regexp, value string) bool {
	if template.MatchString(value) {
		return true
	}
	if !strings.ContainsAny(value, "*?") {
		return false
	}
	return regexIntersects(template.String(), iamWildcardToRegex(value))
}

// iamWildcardToRegex turns an IAM-wildcard string into an anchored regex
// source: '*' → ".*" (any chars, ':' and '/' included — IAM does not
// restrict the wildcard), '?' → "." (exactly one char), other runes
// QuoteMeta'd. The result is always a syntactically valid regex.
func iamWildcardToRegex(s string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range s {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return b.String()
}

// regexIntersects reports whether two regex source strings share any
// matching string — i.e. whether L(srcA) ∩ L(srcB) is non-empty. Returns
// false on parse/compile errors (treated as "cannot prove intersection").
func regexIntersects(srcA, srcB string) bool {
	pa, err := compileSyntaxProg(srcA)
	if err != nil {
		return false
	}
	pb, err := compileSyntaxProg(srcB)
	if err != nil {
		return false
	}
	return progsIntersect(pa, pb)
}

func compileSyntaxProg(src string) (*syntax.Prog, error) {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return syntax.Compile(re)
}

// pcPair is one state of the product NFA: a pair (pcA, pcB) of program
// counters into the two compiled syntax.Prog inputs.
type pcPair struct{ a, b uint32 }

// progsIntersect runs BFS over the product NFA. Returning true means some
// input string drives both programs to their accept (InstMatch) state at
// the same time; that string is a witness for L(pa) ∩ L(pb).
//
// InstEmptyWidth instructions (^, $, \b, \B) are treated as plain
// epsilons. The regexes the validator feeds in are always shaped
// "^...$", so the anchors fire at the right positions naturally — start
// when BFS begins, end when both sides have consumed their input — and
// approximating them as epsilon does not introduce false positives in
// practice.
func progsIntersect(pa, pb *syntax.Prog) bool {
	seen := make(map[pcPair]struct{})
	queue := []pcPair{{uint32(pa.Start), uint32(pb.Start)}}
	seen[queue[0]] = struct{}{}

	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		ia := pa.Inst[s.a]
		ib := pb.Inst[s.b]

		if ia.Op == syntax.InstMatch && ib.Op == syntax.InstMatch {
			return true
		}

		// Epsilon transitions can fire on either side independently.
		for _, n := range epsilonOuts(ia) {
			np := pcPair{n, s.b}
			if _, ok := seen[np]; !ok {
				seen[np] = struct{}{}
				queue = append(queue, np)
			}
		}
		for _, n := range epsilonOuts(ib) {
			np := pcPair{s.a, n}
			if _, ok := seen[np]; !ok {
				seen[np] = struct{}{}
				queue = append(queue, np)
			}
		}

		// Char-consuming step: both sides must accept a common rune.
		if isCharOp(ia.Op) && isCharOp(ib.Op) && runesOverlap(ia, ib) {
			np := pcPair{ia.Out, ib.Out}
			if _, ok := seen[np]; !ok {
				seen[np] = struct{}{}
				queue = append(queue, np)
			}
		}
	}
	return false
}

func epsilonOuts(i syntax.Inst) []uint32 {
	switch i.Op {
	case syntax.InstNop, syntax.InstCapture, syntax.InstEmptyWidth:
		return []uint32{i.Out}
	case syntax.InstAlt, syntax.InstAltMatch:
		return []uint32{i.Out, i.Arg}
	}
	return nil
}

func isCharOp(op syntax.InstOp) bool {
	switch op {
	case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return true
	}
	return false
}

// runesOverlap reports whether two char-consuming instructions accept at
// least one common rune.
func runesOverlap(ia, ib syntax.Inst) bool {
	for _, ra := range acceptedRanges(ia) {
		for _, rb := range acceptedRanges(ib) {
			if ra[0] <= rb[1] && rb[0] <= ra[1] {
				return true
			}
		}
	}
	return false
}

// acceptedRanges returns the inclusive rune ranges accepted by one
// char-consuming instruction. The shape of syntax.Inst.Rune varies by Op:
// InstRune1 stores the single rune in Rune[0]; InstRune stores
// alternating low/high boundaries (lo0, hi0, lo1, hi1, ...); the InstRune*
// "any" variants don't use Rune at all.
func acceptedRanges(i syntax.Inst) [][2]rune {
	switch i.Op {
	case syntax.InstRuneAny:
		return [][2]rune{{0, 0x10ffff}}
	case syntax.InstRuneAnyNotNL:
		return [][2]rune{{0, '\n' - 1}, {'\n' + 1, 0x10ffff}}
	case syntax.InstRune1:
		r := i.Rune[0]
		return [][2]rune{{r, r}}
	case syntax.InstRune:
		ranges := make([][2]rune, 0, len(i.Rune)/2)
		for j := 0; j+1 < len(i.Rune); j += 2 {
			ranges = append(ranges, [2]rune{i.Rune[j], i.Rune[j+1]})
		}
		return ranges
	}
	return nil
}
