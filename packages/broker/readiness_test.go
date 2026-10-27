package broker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadinessClientRequiresFreshNonceProfileAndScope(t *testing.T) {
	key := make([]byte, 32)
	var mode atomic.Value
	mode.Store("valid")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/readyz" {
			t.Error("unexpected readiness path")
		}
		var in ReadinessRequest
		if !ReadLimit(w, r, key, "model.ready", &in, 4096) {
			return
		}
		if !ValidNonce(in.Nonce) {
			t.Error("invalid client nonce")
		}
		out := ReadinessResponse{Nonce: in.Nonce, Profile: "synthetic-qualification", Ready: true}
		switch mode.Load().(string) {
		case "nonce":
			out.Nonce = "replayed"
		case "profile":
			out.Profile = "development"
		case "not_ready":
			out.Ready = false
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	client := NewClient(server.URL+"/execute", "model.execute", key)
	client.HTTP = server.Client()
	if e := client.Readiness(context.Background(), "synthetic-qualification"); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"nonce", "profile", "not_ready"} {
		mode.Store(bad)
		if e := client.Readiness(context.Background(), "synthetic-qualification"); e == nil {
			t.Fatal("mismatched proofaccepted", mode)
		}
	}
	mode.Store("valid")
	wrong := make([]byte, 32)
	wrong[0] = 1
	client.Key = wrong
	if e := client.Readiness(context.Background(), "synthetic-qualification"); e == nil {
		t.Fatal("wrong receiver keyready")
	}
	before := calls.Load()
	client.Key = nil
	if e := client.Readiness(context.Background(), "synthetic-qualification"); e == nil || calls.Load() != before {
		t.Fatal("missing keymade readiness request")
	}
}
func TestReadinessCannotUsePlaintextOrShortCapabilityKey(t *testing.T) {
	client := NewClient("http://model:8082/execute", "model.execute", make([]byte, 32))
	if e := client.Readiness(context.Background(), "synthetic-qualification"); e == nil {
		t.Fatal("plaintextreadiness admitted")
	}
	body := []byte(`{}`)
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if Verify(key, "model.ready", Token(key, "model.ready", body), body) == nil {
			t.Fatal("invalid capabilitykeyaccepted")
		}
	}
}

type readinessTransport func(*http.Request) (*http.Response, error)

func (f readinessTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestReadinessProbeDeadlineAndCallerCancellationAreBounded(t *testing.T) {
	client := NewClient("https://model:8082/execute", "model.execute", make([]byte, 32))
	observed := time.Duration(0)
	client.HTTP = &http.Client{Transport: readinessTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("readiness has no deadline")
		}
		observed = time.Until(deadline)
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(`{"state":"unknown"}`)), Header: make(http.Header)}, nil
	})}
	if client.Readiness(context.Background(), "synthetic-qualification") == nil {
		t.Fatal("failed dependency reported ready")
	}
	if observed <= 0 || observed > 8*time.Second {
		t.Fatal("receiver probe exceeded budget", observed)
	}
	entered := make(chan struct{})
	finished := make(chan error, 1)
	client.HTTP = &http.Client{Transport: readinessTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { finished <- client.Readiness(ctx, "synthetic-qualification") }()
	<-entered
	cancel()
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("cancelled dependency reported ready")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled readiness remained blocked")
	}
}
