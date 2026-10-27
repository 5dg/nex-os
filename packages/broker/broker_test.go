package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCapabilitiesBindAudienceAndBody(t *testing.T) {
	key := make([]byte, 32)
	body := []byte(`{"operation_id":"op-123456"}`)
	token := Token(key, "export.execute", body)
	if e := Verify(key, "export.execute", token, body); e != nil {
		t.Fatal(e)
	}
	if Verify(key, "model.execute", token, body) == nil {
		t.Fatal("capability transferred across services")
	}
	if Verify(key, "export.execute", token, []byte(`{"operation_id":"other"}`)) == nil {
		t.Fatal("modified operation accepted")
	}
	wrong := make([]byte, 32)
	wrong[0] = 1
	if Verify(wrong, "export.execute", token, body) == nil {
		t.Fatal("wrong identity accepted")
	}
}
func TestReceiptRecoveryAndBinding(t *testing.T) {
	store := ReceiptStore{Directory: t.TempDir()}
	calls := 0
	fn := func() (any, error) { calls++; return map[string]string{"result": "delivered"}, nil }
	first, e := store.Do("operation-123", map[string]string{"destination": "a"}, fn)
	if e != nil {
		t.Fatal(e)
	}
	restarted := ReceiptStore{Directory: store.Directory}
	second, e := restarted.Do("operation-123", map[string]string{"destination": "a"}, fn)
	if e != nil || string(first) != string(second) || calls != 1 {
		t.Fatalf("duplicate execution: %d %v", calls, e)
	}
	if _, e = restarted.Do("operation-123", map[string]string{"destination": "b"}, fn); e == nil {
		t.Fatal("idempotency key transferred to another action")
	}
}
func TestUncertainOutcomeNeverBlindlyRetries(t *testing.T) {
	store := ReceiptStore{Directory: t.TempDir()}
	calls := 0
	fn := func() (any, error) { calls++; return nil, errors.New("interrupted after possible effect") }
	store.Do("operation-123", struct{}{}, fn)
	if _, e := store.Do("operation-123", struct{}{}, fn); !errors.Is(e, ErrUnknown) {
		t.Fatal("uncertain outcome was not preserved")
	}
	if calls != 1 {
		t.Fatal("uncertain side effect repeated")
	}
}

func TestPreExecutionFailureCanRetrySafely(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	effects := 0
	allowed := false
	authorize := func() error {
		if !allowed {
			return ErrNotStarted
		}
		return nil
	}
	effect := func() (any, error) { effects++; return "done", nil }
	digest := Hash([]byte("manifest"))
	if _, e := s.DoAuthorized("operation-123", digest, authorize, effect); !errors.Is(e, ErrNotStarted) {
		t.Fatal(e)
	}
	if _, e := s.Inspect("operation-123", digest); !errors.Is(e, ErrNotStarted) {
		t.Fatal(e)
	}
	if effects != 0 {
		t.Fatal("effect before authorization")
	}
	allowed = true
	if _, e := s.DoAuthorized("operation-123", digest, authorize, effect); e != nil {
		t.Fatal(e)
	}
	if effects != 1 {
		t.Fatal("effect count", effects)
	}
}
func TestConcurrentReceiptIsInProgress(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := s.Do("operation-123", struct{}{}, func() (any, error) { close(started); <-release; return "done", nil })
		done <- e
	}()
	<-started
	if _, e := s.Do("operation-123", struct{}{}, func() (any, error) { t.Error("duplicate effect"); return nil, nil }); !errors.Is(e, ErrInProgress) {
		t.Error(e)
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestInterruptedAndCorruptReceiptsRemainUnknown(t *testing.T) {
	for _, state := range []string{"prepared", "started", "corrupt", "legacy"} {
		t.Run(state, func(t *testing.T) {
			s := ReceiptStore{Directory: t.TempDir()}
			digest := Hash([]byte("manifest"))
			switch state {
			case "corrupt":
				os.WriteFile(filepath.Join(s.Directory, "operation-123.state"), []byte("{"), 0600)
			case "legacy":
				os.WriteFile(filepath.Join(s.Directory, "operation-123.pending"), []byte(digest), 0600)
			default:
				if e := s.publish("operation-123", receipt{Version: 2, Digest: digest, State: state}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := s.DoAuthorized("operation-123", digest, nil, func() (any, error) { t.Error("repeated unknown effect"); return nil, nil }); !errors.Is(e, ErrUnknown) {
				t.Fatal(e)
			}
		})
	}
}

// Child process fixtures exercise lost responses and OS-released locks using
// real process termination. No production failpoint or environment switch is
// present in ReceiptStore.
func TestReceiptCrashChild(t *testing.T) {
	mode := os.Getenv("NEX_RECEIPT_TEST_CHILD")
	if mode == "" {
		return
	}
	s := ReceiptStore{Directory: os.Getenv("NEX_RECEIPT_TEST_DIR")}
	digest := Hash([]byte("sealed manifest"))
	_, e := s.DoAuthorized("operation-crash", digest, func() error {
		if mode == "prepared" {
			os.Exit(71)
		}
		return nil
	}, func() (any, error) {
		if mode == "before_effect" {
			os.Exit(71)
		}
		f, e := os.OpenFile(filepath.Join(s.Directory, "effects"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteString("effect\n"); e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		f.Close()
		if mode == "after_effect" {
			os.Exit(71)
		}
		if mode == "result_encoding" {
			return crashMarshaler{}, nil
		}
		return map[string]string{"result": "completed"}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if mode == "completed_response_lost" {
		os.Exit(71)
	}
	t.Fatal("unknown child mode")
}

type crashMarshaler struct{}

func (crashMarshaler) MarshalJSON() ([]byte, error) { os.Exit(71); return nil, nil }

func TestProcessCrashRecoveryNeverRepeatsUncertainEffects(t *testing.T) {
	for _, mode := range []string{"prepared", "before_effect", "after_effect", "result_encoding", "completed_response_lost"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			command := exec.Command(os.Args[0], "-test.run=^TestReceiptCrashChild$")
			command.Env = append(os.Environ(), "NEX_RECEIPT_TEST_CHILD="+mode, "NEX_RECEIPT_TEST_DIR="+directory)
			output, e := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 71 {
				t.Fatalf("child did not reach crash boundary: %v %s", e, output)
			}
			s := ReceiptStore{Directory: directory}
			digest := Hash([]byte("sealed manifest"))
			calls := 0
			result, e := s.DoAuthorized("operation-crash", digest, func() error { calls++; return nil }, func() (any, error) { calls++; return "duplicate", nil })
			if mode == "completed_response_lost" {
				if e != nil || string(result) != `{"result":"completed"}` {
					t.Fatalf("durable result not recovered: %s %v", result, e)
				}
			} else if !errors.Is(e, ErrUnknown) {
				t.Fatalf("uncertain crash treated as retryable: %v", e)
			}
			if calls != 0 {
				t.Fatal("crashed operation authorized/executed again")
			}
			effects, e := os.ReadFile(filepath.Join(directory, "effects"))
			if mode == "prepared" || mode == "before_effect" {
				if !errors.Is(e, os.ErrNotExist) {
					t.Fatalf("unexpected effect: %s %v", effects, e)
				}
			} else if e != nil || string(effects) != "effect\n" {
				t.Fatalf("effect repeated or lost: %q %v", effects, e)
			}
		})
	}
}

func TestInspectRequiresDurableEvidence(t *testing.T) {
	for _, missingDirectory := range []bool{false, true} {
		t.Run(strconv.FormatBool(missingDirectory), func(t *testing.T) {
			path := t.TempDir()
			if missingDirectory {
				path = filepath.Join(path, "lost-volume")
			}
			s := ReceiptStore{Directory: path}
			if _, e := s.Inspect("operation-123", Hash([]byte("manifest"))); !errors.Is(e, ErrUnknown) {
				t.Fatal("missing receipt claimed no prior effect", e)
			}
			if missingDirectory {
				if _, e := os.Stat(path); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("inspection created replacement volume")
				}
			}
		})
	}
}

func TestMalformedVersionedReceiptsNeverPermitExecution(t *testing.T) {
	digest := Hash([]byte("manifest"))
	for _, raw := range []string{
		`{"request_digest":"` + digest + `"}`,
		`{"version":1,"request_digest":"` + digest + `","state":"not_started"}`,
		`{"version":3,"request_digest":"` + digest + `","state":"not_started"}`,
		`{"version":2,"request_digest":"` + digest + `","state":"other"}`,
		`{"version":2,"request_digest":"` + digest + `","state":"not_started","result":"unexpected"}`,
		`{"version":2,"request_digest":"` + digest + `","state":"completed","result":null}`,
	} {
		t.Run(Hash([]byte(raw))[:8], func(t *testing.T) {
			s := ReceiptStore{Directory: t.TempDir()}
			if e := os.WriteFile(filepath.Join(s.Directory, "operation-123.state"), []byte(raw), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := s.DoAuthorized("operation-123", digest, func() error { t.Error("malformed state reauthorized"); return nil }, func() (any, error) { t.Error("malformed state executed"); return "bad", nil }); !errors.Is(e, ErrUnknown) {
				t.Fatal(e)
			}
		})
	}
}

func TestLegacyCompletedReceiptSurvivesUpgrade(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	digest := Hash([]byte("v1 JSON payload"))
	raw := `{"request_digest":"` + digest + `","result":{"artifact_id":"old-artifact"}}`
	if e := os.WriteFile(filepath.Join(s.Directory, "operation-123.done"), []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	result, e := s.DoAuthorized("operation-123", digest, func() error { t.Error("v1 completed reauthorized"); return nil }, func() (any, error) { t.Error("v1 effect repeated"); return nil, nil })
	if e != nil || string(result) != `{"artifact_id":"old-artifact"}` {
		t.Fatal(string(result), e)
	}
}

func TestAtomicPublicationDoesNotPromoteOrphanTemporaryFile(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	digest := Hash([]byte("manifest"))
	if e := s.publish("operation-123", receipt{Version: 2, Digest: digest, State: "started"}); e != nil {
		t.Fatal(e)
	}
	// A process killed during completion write may leave a truncated temp file.
	// Only the final atomic rename is authoritative, never the temp filename.
	if e := os.WriteFile(filepath.Join(s.Directory, ".receipt-orphan"), []byte(`{"version":2,"state":"completed","result":`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DoAuthorized("operation-123", digest, nil, func() (any, error) { t.Error("partial completion repeated effect"); return nil, nil }); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	if _, e := s.Inspect("operation-123", digest); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
}

func TestMalformedOutcomeResponsesRemainUnknown(t *testing.T) {
	for _, body := range []string{`{"state":"not_started"}garbage`, `{"state":"not_started"}{}`, `{"state":"not_started","untrusted":true}`, `{"state":"other"}`, `{"state":"not_started"}` + strings.Repeat(" ", 1025)} {
		t.Run(Hash([]byte(body))[:8], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); w.Write([]byte(body)) }))
			defer server.Close()
			c := NewClient(server.URL, "test", make([]byte, 32))
			var out any
			if e := c.Call(context.Background(), struct{}{}, &out); !errors.Is(e, ErrUnknown) {
				t.Fatal("malformed response claimed known state", e)
			}
		})
	}
}

func TestReceiptCreatesDurableNestedDirectory(t *testing.T) {
	s := ReceiptStore{Directory: filepath.Join(t.TempDir(), "new", "nested", "receipts")}
	digest := Hash([]byte("manifest"))
	first, e := s.DoAuthorized("operation-123", digest, nil, func() (any, error) { return "done", nil })
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := s.Inspect("operation-123", digest)
	if e != nil || string(first) != string(recovered) {
		t.Fatal("nested receipt did not recover", e)
	}
}

func TestNullResultRemainsUnknownBeforeCompletion(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	digest := Hash([]byte("manifest"))
	calls := 0
	fn := func() (any, error) { calls++; return nil, nil }
	if _, e := s.DoAuthorized("operation-123", digest, nil, fn); !errors.Is(e, ErrUnknown) {
		t.Fatal("null result reported completed", e)
	}
	if _, e := s.Inspect("operation-123", digest); !errors.Is(e, ErrUnknown) {
		t.Fatal("null receipt inspect reported completed", e)
	}
	if _, e := s.DoAuthorized("operation-123", digest, nil, fn); !errors.Is(e, ErrUnknown) {
		t.Fatal("null result retried", e)
	}
	if calls != 1 {
		t.Fatal("null result repeated effect")
	}
}

func TestInaccessibleStorageNeverClaimsNotStarted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked-receipts")
	if e := os.WriteFile(path, []byte("storage unavailable"), 0600); e != nil {
		t.Fatal(e)
	}
	s := ReceiptStore{Directory: path}
	digest := Hash([]byte("manifest"))
	if _, e := s.Inspect("operation-123", digest); !errors.Is(e, ErrUnknown) {
		t.Fatal("unreadable storage claimed no effect", e)
	}
	if _, e := s.DoAuthorized("operation-123", digest, func() error { t.Error("unavailable storage authorized"); return nil }, func() (any, error) { t.Error("unavailable storage executed"); return nil, nil }); !errors.Is(e, ErrUnknown) {
		t.Fatal("storage failure claimed no effect", e)
	}
}

func TestAmbiguousAuthorizationFailureCannotRetry(t *testing.T) {
	s := ReceiptStore{Directory: t.TempDir()}
	digest := Hash([]byte("manifest"))
	effects := 0
	authorizations := 0
	authorize := func() error { authorizations++; return errors.New("authorization response lost") }
	effect := func() (any, error) { effects++; return "bad", nil }
	if _, e := s.DoAuthorized("operation-123", digest, authorize, effect); !errors.Is(e, ErrUnknown) {
		t.Fatal("ambiguous authorization claimed no effect", e)
	}
	if _, e := s.Inspect("operation-123", digest); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	if _, e := s.DoAuthorized("operation-123", digest, authorize, effect); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	if effects != 0 || authorizations != 1 {
		t.Fatalf("ambiguous authorization repeated: auth=%d effects=%d", authorizations, effects)
	}
}

func TestReadLimitIsReceiverSpecific(t *testing.T) {
	key := make([]byte, 32)
	body := []byte(`{"content":"` + strings.Repeat("a", 20000) + `"}`)
	for _, limit := range []int64{16384, 32768} {
		r := httptest.NewRequest("POST", "/execute", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Capability "+Token(key, "test", body))
		w := httptest.NewRecorder()
		var out struct {
			Content string `json:"content"`
		}
		if ok := ReadLimit(w, r, key, "test", &out, limit); ok != (limit == 32768) {
			t.Fatalf("limit %d accepted=%v", limit, ok)
		}
	}
	r := httptest.NewRequest("POST", "/execute", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Capability "+Token(key, "test", body))
	if Read(httptest.NewRecorder(), r, key, "test", &struct {
		Content string `json:"content"`
	}{}) {
		t.Fatal("default receiver limit widened")
	}
}

func TestBoundedResponseAcceptsEscapedSemanticResult(t *testing.T) {
	text := strings.Repeat("\x01", 12000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"text": text})
	}))
	defer server.Close()
	c := NewClient(server.URL, "test", make([]byte, 32))
	var out struct {
		Text string `json:"text"`
	}
	if e := c.Call(context.Background(), struct{}{}, &out); e != nil || out.Text != text {
		t.Fatal("valid escaped semantic result truncated", e)
	}
}
func TestOversizedOrTrailingResultIsUnknown(t *testing.T) {
	for _, body := range []string{`{"text":"` + strings.Repeat("x", 128*1024) + `"}`, `{"text":"done"}{}`, `{"text":"done"}garbage`} {
		t.Run(Hash([]byte(body))[:8], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			c := NewClient(server.URL, "test", make([]byte, 32))
			var out struct {
				Text string `json:"text"`
			}
			if e := c.Call(context.Background(), struct{}{}, &out); !errors.Is(e, ErrUnknown) {
				t.Fatal("invalid response accepted", e)
			}
		})
	}
}
