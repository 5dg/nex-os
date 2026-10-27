package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

// Expected digests were independently calculated from the specified framing.
// Rust consumes this same file; changing serialization must not change semantics.
func TestExecutionDigestConformance(t *testing.T) {
	raw, e := os.ReadFile("execution-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Name    string          `json:"name"`
		Kind    string          `json:"kind"`
		Payload json.RawMessage `json:"payload"`
		Digest  string          `json:"digest"`
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	if len(vectors) < 6 {
		t.Fatal("missing contract vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			var value any
			switch v.Kind {
			case "export":
				var in Export
				if e := json.Unmarshal(v.Payload, &in); e != nil {
					t.Fatal(e)
				}
				value = in
			case "model":
				var in Generation
				if e := json.Unmarshal(v.Payload, &in); e != nil {
					t.Fatal(e)
				}
				value = in
			default:
				t.Fatal("unknown vector kind")
			}
			if got := ExecutionDigest(value); got != v.Digest {
				t.Fatalf("digest %s; expected %s", got, v.Digest)
			}
		})
	}
}
