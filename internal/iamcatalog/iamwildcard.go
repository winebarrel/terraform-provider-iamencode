package iamcatalog

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// maxResourceLen caps the user-supplied Resource value we feed into the
// intersection check. Production AWS resource ARNs sit comfortably under
// 2048 bytes (the IAM role-ARN cap and a common API limit); 4096 doubles
// that for slack, while still drawing a line short enough to keep the
// BFS bounded. Beyond this we return false (fail closed) without trying
// to compile or intersect.
const maxResourceLen = 4096

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
//
// The fallback is bounded — len(value) and the BFS visit count are both
// capped — and fails closed (returns false) when a limit is hit.
func matchesARN(template *regexp.Regexp, value string) bool {
	if template.MatchString(value) {
		return true
	}
	if !strings.ContainsAny(value, "*?") {
		return false
	}
	if len(value) > maxResourceLen {
		return false
	}
	return regexIntersects(template.String(), iamWildcardToRegex(value))
}

// iamWildcardToRegex turns an IAM-wildcard string into an anchored regex
// source: '*' → ".*" (any chars except newline, ':' and '/' included),
// '?' → "." (exactly one char, also newline-excluding), other runes
// QuoteMeta'd. Newline exclusion mirrors Go's default Perl flags — both
// sides of the intersection use the same convention, and real ARN values
// never contain newlines, so the omission is safe.
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
// matching string — i.e. whether L(tmplSrc) ∩ L(userSrc) is non-empty.
// Returns false on parse/compile errors (treated as "cannot prove
// intersection").
//
// Only the template side is memoized. Template sources repeat for every
// ARN tested in a service, so caching them turns the inner loop of
// checkResources into a hash lookup. User patterns are NOT cached: their
// source space is unbounded (configs can list arbitrarily many distinct
// wildcarded Resource values), and sync.Map has no eviction — caching
// them would let a config bloat process memory.
func regexIntersects(tmplSrc, userSrc string) bool {
	pa, err := cachedTemplateProg(tmplSrc)
	if err != nil {
		return false
	}
	pb, err := compileSyntaxProg(userSrc)
	if err != nil {
		return false
	}
	return progsIntersect(pa, pb)
}

// templateProgCache memoizes template regex source → *syntax.Prog.
// syntax.Prog is read-only after compile, so sharing a single instance
// across goroutines (and across the resources × patterns loop in
// checkResources) is safe.
var templateProgCache sync.Map // map[string]progCacheEntry

type progCacheEntry struct {
	prog *syntax.Prog
	err  error
}

func cachedTemplateProg(src string) (*syntax.Prog, error) {
	if v, ok := templateProgCache.Load(src); ok {
		e := v.(progCacheEntry)
		return e.prog, e.err
	}
	prog, err := compileSyntaxProg(src)
	templateProgCache.Store(src, progCacheEntry{prog: prog, err: err})
	return prog, err
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

// maxProductStates caps the size of the BFS visit set. The product state
// space is O(|progA|·|progB|); a malicious or accidentally large user
// pattern could in theory drive it far past anything we'd see in practice.
// When the cap is hit we bail out and return false (fail closed).
const maxProductStates = 100_000

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

	enqueue := func(np pcPair) {
		if _, ok := seen[np]; ok {
			return
		}
		seen[np] = struct{}{}
		queue = append(queue, np)
	}

	for len(queue) > 0 {
		if len(seen) >= maxProductStates {
			return false
		}
		s := queue[0]
		queue = queue[1:]
		ia := pa.Inst[s.a]
		ib := pb.Inst[s.b]

		if ia.Op == syntax.InstMatch && ib.Op == syntax.InstMatch {
			return true
		}

		// Epsilon transitions can fire on either side independently.
		// Inline the per-Op branching so we don't allocate a fresh
		// slice for each dequeued state.
		switch ia.Op {
		case syntax.InstNop, syntax.InstCapture, syntax.InstEmptyWidth:
			enqueue(pcPair{ia.Out, s.b})
		case syntax.InstAlt, syntax.InstAltMatch:
			enqueue(pcPair{ia.Out, s.b})
			enqueue(pcPair{ia.Arg, s.b})
		}
		switch ib.Op {
		case syntax.InstNop, syntax.InstCapture, syntax.InstEmptyWidth:
			enqueue(pcPair{s.a, ib.Out})
		case syntax.InstAlt, syntax.InstAltMatch:
			enqueue(pcPair{s.a, ib.Out})
			enqueue(pcPair{s.a, ib.Arg})
		}

		// Char-consuming step: both sides must accept a common rune.
		if isCharOp(ia.Op) && isCharOp(ib.Op) && runesOverlap(ia, ib) {
			enqueue(pcPair{ia.Out, ib.Out})
		}
	}
	return false
}

func isCharOp(op syntax.InstOp) bool {
	switch op {
	case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
		return true
	}
	return false
}

// runesOverlap reports whether two char-consuming instructions accept at
// least one common rune. Hot path inside the BFS — uses iterRanges to
// avoid the per-call slice allocations the previous "acceptedRanges
// returning [][2]rune" shape produced.
func runesOverlap(ia, ib syntax.Inst) bool {
	return iterRanges(ia, func(lo1, hi1 rune) bool {
		return iterRanges(ib, func(lo2, hi2 rune) bool {
			return lo1 <= hi2 && lo2 <= hi1
		})
	})
}

// iterRanges calls fn for each inclusive [lo, hi] rune range accepted by
// the instruction. Returns true as soon as fn returns true (used as the
// "stop, overlap found" signal). The shape of syntax.Inst.Rune varies by
// Op: InstRune1 stores the single rune in Rune[0]; InstRune stores
// alternating low/high boundaries (lo0, hi0, lo1, hi1, ...); the InstRune*
// "any" variants don't use Rune at all.
func iterRanges(i syntax.Inst, fn func(lo, hi rune) bool) bool {
	switch i.Op {
	case syntax.InstRuneAny:
		return fn(0, 0x10ffff)
	case syntax.InstRuneAnyNotNL:
		if fn(0, '\n'-1) {
			return true
		}
		return fn('\n'+1, 0x10ffff)
	case syntax.InstRune1:
		return fn(i.Rune[0], i.Rune[0])
	case syntax.InstRune:
		for j := 0; j+1 < len(i.Rune); j += 2 {
			if fn(i.Rune[j], i.Rune[j+1]) {
				return true
			}
		}
	}
	return false
}

// acceptedRanges is the test-friendly view of iterRanges — it returns
// the same ranges as a slice. Not used on the hot path; kept so the
// behavior of the underlying rune dispatch can be asserted directly.
func acceptedRanges(i syntax.Inst) [][2]rune {
	var ranges [][2]rune
	iterRanges(i, func(lo, hi rune) bool {
		ranges = append(ranges, [2]rune{lo, hi})
		return false
	})
	return ranges
}
