package policyedge

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPolicyRoutesAndBounds(t *testing.T) {
	calls := 0
	upstream := fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "http://127.0.0.1:8182"+r.URL.Path || r.Host != "127.0.0.1:8182" || r.Header.Get("Authorization") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Fatal("unsafe upstream request")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}, "Set-Cookie": []string{"secret=1"}}, Body: io.NopCloser(strings.NewReader(`{"result":{}}`))}, nil
	})
	h := Handler(upstream, func(*http.Request) error { return nil })
	for _, tc := range []struct {
		method, path, body, contentType string
		status                          int
	}{
		{"GET", "/v1/policies", "", "", 200},
		{"POST", "/v1/data/nex/authz/decision", `{"input":{}}`, "application/json", 200},
		{"PUT", "/v1/policies/guard", "", "", 403},
		{"DELETE", "/v1/policies/guard", "", "", 403},
		{"POST", "/v1/data/nex/authz/decision?x=1", "{}", "application/json", 403},
		{"POST", "/v1/data/nex/authz/decision", "{}", "text/plain", 415},
		{"POST", "/v1/data/nex/authz/decision", strings.Repeat("x", maxRequest+1), "application/json", 413},
	} {
		t.Run(tc.method+tc.path+tc.contentType, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Authorization", "forged")
			r.Header.Set("Forwarded", "forged")
			r.Header.Set("X-Forwarded-For", "forged")
			before := calls
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
			if tc.status != 200 && calls != before {
				t.Fatal("denied request reached OPA")
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Fatal("upstream cookie escaped")
			}
		})
	}
}

func TestNoResponseWhenIdentityExpiresDuringCallOrResponseIsOversized(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(map[bool]string{false: "identity", true: "body"}[oversized], func(t *testing.T) {
			checks := 0
			h := Handler(fakeTransport(func(*http.Request) (*http.Response, error) {
				body := "secret decision"
				if oversized {
					body = strings.Repeat("x", maxResponse+1)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			}), func(*http.Request) error {
				checks++
				if checks > 2 && !oversized {
					return errors.New("expired")
				}
				return nil
			})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/policies", nil))
			if w.Code != 503 || strings.Contains(w.Body.String(), "secret decision") {
				t.Fatal("unsafe result escaped", w.Code)
			}
		})
	}
}

func TestLoopbackTransportRejectsAnyOtherDestination(t *testing.T) {
	transport := LoopbackTransport()
	for _, destination := range []string{"example.com:8182", "127.0.0.2:8182", "127.0.0.1:80"} {
		if conn, err := transport.DialContext(t.Context(), "tcp", destination); err == nil {
			conn.Close()
			t.Fatal("foreign destination accepted", destination)
		}
	}
	if conn, err := transport.DialContext(t.Context(), "udp", "127.0.0.1:8182"); err == nil {
		conn.Close()
		t.Fatal("non-TCP destination accepted")
	}
}

func TestBoundedRejectsSaturationAndRecovers(t *testing.T) {
	entered := make(chan struct{}, 32)
	release := make(chan struct{})
	var workers sync.WaitGroup
	handler := Bounded(Handler(fakeTransport(func(*http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}), func(*http.Request) error { return nil }))
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/v1/policies", nil))
			if response.Code != http.StatusOK {
				t.Errorf("admitted request failed: %d", response.Code)
			}
		}()
	}
	for range 32 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			workers.Wait()
			t.Fatal("admitted requests did not reach upstream")
		}
	}
	overflow := httptest.NewRecorder()
	handler.ServeHTTP(overflow, httptest.NewRequest("GET", "/v1/policies", nil))
	if overflow.Code != http.StatusServiceUnavailable {
		close(release)
		workers.Wait()
		t.Fatal("saturation was not rejected", overflow.Code)
	}
	close(release)
	workers.Wait()
	after := httptest.NewRecorder()
	handler.ServeHTTP(after, httptest.NewRequest("GET", "/v1/policies", nil))
	if after.Code != http.StatusOK {
		t.Fatal("admission did not recover", after.Code)
	}
}
