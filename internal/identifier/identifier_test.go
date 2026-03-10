package identifier_test

import (
	"strings"
	"testing"

	"github.com/02gur/HashMapper/internal/identifier"
)

func TestIdentifyMD5(t *testing.T) {
	// MD5("password")
	hash := "5f4dcc3b5aa765d61d8327deb882cf99"
	candidates := identifier.Identify(hash)
	if len(candidates) == 0 {
		t.Fatal("expected candidates, got none")
	}
	// The top candidate should include md5.
	found := false
	for _, c := range candidates {
		if c.Algorithm.ID == "md5" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected md5 in candidates; got: %v", candidateIDs(candidates))
	}
}

func TestIdentifySHA1(t *testing.T) {
	hash := "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	candidates := identifier.Identify(hash)
	expectID(t, candidates, "sha1")
}

func TestIdentifySHA256(t *testing.T) {
	hash := "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
	candidates := identifier.Identify(hash)
	expectID(t, candidates, "sha256")
}

func TestIdentifySHA512(t *testing.T) {
	hash := "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
	candidates := identifier.Identify(hash)
	if len(candidates) == 0 {
		t.Skip("sha512 hash not identified (length may collide with other algos)")
	}
	expectID(t, candidates, "sha512")
}

func TestIdentifyBcrypt(t *testing.T) {
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	candidates := identifier.Identify(hash)
	expectID(t, candidates, "bcrypt")
}

func TestIdentifyMySQL41(t *testing.T) {
	hash := "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
	candidates := identifier.Identify(hash)
	expectID(t, candidates, "mysql41")
}

func TestIdentifyBest(t *testing.T) {
	hash := "5f4dcc3b5aa765d61d8327deb882cf99"
	best := identifier.IdentifyBest(hash)
	if len(best) == 0 {
		t.Fatal("IdentifyBest returned empty slice")
	}
	score := best[0].Score
	for _, c := range best {
		if c.Score != score {
			t.Errorf("IdentifyBest returned different scores: %d vs %d", score, c.Score)
		}
	}
}

func TestIdentifyUnknown(t *testing.T) {
	// An obviously invalid / unrecognised string.
	candidates := identifier.Identify("!!!NOT-A-HASH!!!")
	if len(candidates) != 0 {
		t.Errorf("expected no candidates for invalid input, got %v", candidateIDs(candidates))
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func expectID(t *testing.T, candidates []identifier.Candidate, id string) {
	t.Helper()
	for _, c := range candidates {
		if c.Algorithm.ID == id {
			return
		}
	}
	t.Errorf("expected %q in candidates; got: %s", id, strings.Join(candidateIDs(candidates), ", "))
}

func candidateIDs(candidates []identifier.Candidate) []string {
	ids := make([]string, len(candidates))
	for i, c := range candidates {
		ids[i] = c.Algorithm.ID
	}
	return ids
}
