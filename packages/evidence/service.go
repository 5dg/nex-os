package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/5dg/nex-os/packages/broker"
	"net/http"
	"os"
	"time"
)

func Handler(journal *Journal, controlKey, kernelKey []byte) http.Handler {
	return HandlerWithPeer(journal, controlKey, kernelKey, nil)
}

// peer checks verified transport identity in addition to the producer capability.
// Empty producer requests only liveness; it must not grant signing readiness.
func HandlerWithPeer(journal *Journal, controlKey, kernelKey []byte, peer func(*http.Request, string) error) http.Handler {
	mux := http.NewServeMux()
	for _, source := range []string{"control", "kernel"} {
		key := controlKey
		if source == "kernel" {
			key = kernelKey
		}
		mux.HandleFunc("POST /append/"+source, func(w http.ResponseWriter, r *http.Request) {
			if len(key) != 32 {
				http.Error(w, "identity configuration unavailable", 503)
				return
			}
			if peer != nil && peer(r, source) != nil {
				http.Error(w, "peer identity denied", 403)
				return
			}
			var event Event
			if !broker.ReadLimit(w, r, key, "evidence.append."+source, &event, 128*1024) {
				return
			}
			if peer != nil && (journal.custody == nil || journal.custody.Check() != nil) {
				http.Error(w, "single writer custody unavailable", 503)
				return
			}
			event.Producer = source
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			proof, e := journal.AppendContext(ctx, event, func() error {
				if peer != nil {
					return peer(r, source)
				}
				return nil
			})
			if e != nil {
				http.Error(w, "evidence unavailable or integrity failure", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(proof)
		})

		mux.HandleFunc("POST /challenge/"+source, func(w http.ResponseWriter, r *http.Request) {
			if peer != nil && peer(r, source) != nil {
				http.Error(w, "peer identity denied", 403)
				return
			}
			var in ChallengeRequest
			if !broker.ReadLimit(w, r, key, "evidence.challenge."+source, &in, 4096) {
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			proof, e := journal.ChallengeContext(ctx, source, in.Nonce, func() error {
				if peer != nil {
					return peer(r, source)
				}
				return nil
			})
			if e != nil {
				http.Error(w, "signing readiness unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(proof)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if peer != nil && peer(r, "") != nil {
			http.Error(w, "peer identity denied", 403)
			return
		}
		if peer != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		if _, e := Verify(journal.Directory, journal.Private.Public().(ed25519.PublicKey), nil); e != nil {
			http.Error(w, "integrity failure", 503)
			return
		}
		f, e := os.CreateTemp(journal.Directory, ".readiness-")
		if e != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		name := f.Name()
		e = f.Sync()
		f.Close()
		os.Remove(name)
		if e != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	return mux
}
