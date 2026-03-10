package algorithms_test

import (
	"testing"

	"github.com/02gur/HashMapper/internal/algorithms"
)

// TestRegistryHas70PlusAlgorithms verifies the registry meets the 70+ requirement.
func TestRegistryHas70PlusAlgorithms(t *testing.T) {
	n := len(algorithms.All)
	if n < 70 {
		t.Errorf("expected at least 70 algorithms, got %d", n)
	}
	t.Logf("registered algorithms: %d", n)
}

// TestAllAlgorithmsHaveIDs checks that every algorithm has a non-empty ID, Name, and Compute function.
func TestAllAlgorithmsHaveIDs(t *testing.T) {
	for _, alg := range algorithms.All {
		if alg.ID == "" {
			t.Errorf("algorithm with name %q has empty ID", alg.Name)
		}
		if alg.Name == "" {
			t.Errorf("algorithm %q has empty Name", alg.ID)
		}
		if alg.Compute == nil {
			t.Errorf("algorithm %q has nil Compute function", alg.ID)
		}
	}
}

// TestRegistryLookup verifies that Registry lookup by ID works.
func TestRegistryLookup(t *testing.T) {
	cases := []string{"md5", "sha1", "sha256", "sha512", "sha3_256", "bcrypt", "ntlm", "blake2b_512"}
	for _, id := range cases {
		alg, ok := algorithms.Registry[id]
		if !ok {
			t.Errorf("Registry[%q] not found", id)
			continue
		}
		if alg.ID != id {
			t.Errorf("Registry[%q].ID = %q", id, alg.ID)
		}
	}
}

// TestKnownHashes verifies a selection of algorithms against known test vectors.
func TestKnownHashes(t *testing.T) {
	vectors := []struct {
		id       string
		input    string
		expected string
	}{
		{"md5", "password", "5f4dcc3b5aa765d61d8327deb882cf99"},
		{"sha1", "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
		{"sha256", "password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
		{"sha512", "password", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"md5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
		{"sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
	}

	for _, v := range vectors {
		t.Run(v.id+"/"+v.input, func(t *testing.T) {
			alg, ok := algorithms.Registry[v.id]
			if !ok {
				t.Fatalf("algorithm %q not found", v.id)
			}
			got, err := alg.Compute([]byte(v.input), nil)
			if err != nil {
				t.Fatalf("Compute error: %v", err)
			}
			if got != v.expected {
				t.Errorf("got  %q\nwant %q", got, v.expected)
			}
		})
	}
}

// TestComputeDoesNotPanic runs every algorithm's Compute with a short input and key.
func TestComputeDoesNotPanic(t *testing.T) {
	for _, alg := range algorithms.All {
		alg := alg
		t.Run(alg.ID, func(t *testing.T) {
			if alg.IsSlowHash {
				t.Skip("skipping slow hash in unit tests")
			}
			_, err := alg.Compute([]byte("test"), []byte("key"))
			if err != nil {
				t.Errorf("Compute returned unexpected error: %v", err)
			}
		})
	}
}
