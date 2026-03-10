// Package identifier implements multi-algorithm hash identification.
// It analyses a hash string (length, character set, prefix patterns) and
// returns a ranked list of candidate algorithms.
package identifier

import (
	"sort"
	"strings"

	"github.com/02gur/HashMapper/internal/algorithms"
)

// Candidate is a possible algorithm match for a given hash.
type Candidate struct {
	Algorithm *algorithms.Algorithm
	// Score is a positive integer; higher means more confident.
	Score int
}

// Identify returns a ranked (highest-score first) list of algorithm candidates
// for the given hash string.  It never returns an error; an empty slice means
// no match was found.
func Identify(hash string) []Candidate {
	lower := strings.ToLower(strings.TrimSpace(hash))
	length := len(hash)

	var candidates []Candidate

	for _, alg := range algorithms.All {
		score := 0

		// ── Length match ────────────────────────────────────────────────
		if alg.HexLength > 0 {
			if length == alg.HexLength {
				score += 10
			} else {
				// Wrong length; skip unless it's a variable-length algorithm.
				continue
			}
		}

		// ── Pattern match ────────────────────────────────────────────────
		matched := false
		for _, pat := range alg.Patterns {
			if pat.MatchString(hash) {
				score += 20
				matched = true
				break
			}
			// Try lowercase too
			if pat.MatchString(lower) {
				score += 15
				matched = true
				break
			}
		}

		// Require at least one pattern match for all algorithms so that
		// non-hex / non-conforming strings don't get false positives on
		// length alone.
		if !matched {
			continue
		}

		// ── Character-set bonus ─────────────────────────────────────────
		if isHexString(lower) {
			switch alg.Category {
			case algorithms.CategoryMD, algorithms.CategorySHA1,
				algorithms.CategorySHA2, algorithms.CategorySHA3,
				algorithms.CategoryKeccak, algorithms.CategorySHAKE,
				algorithms.CategoryBLAKE, algorithms.CategoryRIPEMD,
				algorithms.CategoryCRC, algorithms.CategoryFNV,
				algorithms.CategoryAdler, algorithms.CategoryHMAC,
				algorithms.CategoryChained, algorithms.CategoryNTLM,
				algorithms.CategoryMySQL:
				score += 5
			}
		}

		if score > 0 {
			candidates = append(candidates, Candidate{Algorithm: alg, Score: score})
		}
	}

	// Sort by score descending, then by ID ascending for determinism.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Algorithm.ID < candidates[j].Algorithm.ID
	})

	return candidates
}

// IdentifyBest returns only the top-scoring candidates (ties are included).
func IdentifyBest(hash string) []Candidate {
	all := Identify(hash)
	if len(all) == 0 {
		return nil
	}
	best := all[0].Score
	var top []Candidate
	for _, c := range all {
		if c.Score < best {
			break
		}
		top = append(top, c)
	}
	return top
}

// isHexString returns true if every character is a lowercase hex digit.
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}
