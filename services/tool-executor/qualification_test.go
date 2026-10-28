package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type authority struct {
	auth, complete int
	onAuthorize    func()
}

func (a *authority) AuthorizeEffect(context.Context, string, string) error {
	a.auth++
	if a.onAuthorize != nil {
		a.onAuthorize()
	}
	return nil
}
func (a *authority) CompleteExecution(context.Context, string, string, any) error {
	a.complete++
	return nil
}
func (a *authority) Readiness(context.Context) error { return nil }
func exportRequest(t *testing.T, s *Service, in contracts.Export, path, audience string) *httptest.ResponseRecorder {
	t.Helper()
	body, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Capability "+broker.Token(s.Key, audience, body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func exportFixture(t *testing.T) (*Service, *authority, contracts.Export) {
	t.Helper()
	receipts, e := broker.OpenReceiptStore(filepath.Join(t.TempDir(), "receipts"), "export")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { receipts.Close() })
	a := &authority{}
	s := &Service{Key: make([]byte, 32), Receipts: receipts, Validate: a, Profile: "synthetic-qualification", PeerCheck: func(*http.Request) error { return nil }}
	return s, a, contracts.Export{ManifestVersion: 3, OperationID: "operation-123", TenantID: "tenant-a", DestinationID: "local-evidence", Content: "approved synthetic bytes", RequestDigest: "approved-binding"}
}
func TestQualifiedExportPreservesBytesAndStatusScope(t *testing.T) {
	s, a, in := exportFixture(t)
	if w := exportRequest(t, s, in, "/execute", "export.execute"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := exportRequest(t, s, in, "/status", "export.execute"); w.Code != 401 {
		t.Fatal("execute token became status", w.Code)
	}
	if w := exportRequest(t, s, in, "/status", "export.status"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.auth != 1 || a.complete != 2 {
		t.Fatal("status repeated authorization", a)
	}
	path := filepath.Join(s.Receipts.Directory, in.OperationID+".state")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var record map[string]any
	if e = json.Unmarshal(b, &record); e != nil {
		t.Fatal(e)
	}
	result := record["result"].(map[string]any)
	result["content"] = "corrupt artifact"
	b, _ = json.Marshal(record)
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if w := exportRequest(t, s, in, "/status", "export.status"); w.Code == 200 || a.complete != 2 {
		t.Fatal("corrupt artifact completed", w.Code, a.complete)
	}
}
func TestQualifiedExportRechecksPeerBeforeArtifact(t *testing.T) {
	s, a, in := exportFixture(t)
	expired := false
	s.PeerCheck = func(*http.Request) error {
		if expired {
			return errors.New("expired")
		}
		return nil
	}
	a.onAuthorize = func() { expired = true }
	if w := exportRequest(t, s, in, "/execute", "export.execute"); w.Code == 200 {
		t.Fatal("expired peer exported")
	}
	if a.auth != 1 || a.complete != 0 {
		t.Fatal(a)
	}
	if _, e := s.Receipts.Inspect(in.OperationID, contracts.ExecutionDigest(in)); !errors.Is(e, broker.ErrUnknown) {
		t.Fatal(e)
	}
	expired = false
	if w := exportRequest(t, s, in, "/execute", "export.execute"); w.Code == 200 || a.auth != 1 {
		t.Fatal("unknown artifact repeated", w.Code, a.auth)
	}
}

func TestExportReadinessHasSeparateCredentialScope(t *testing.T) {
	s, a, _ := exportFixture(t)
	call := func(key []byte, aud string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(broker.ReadinessRequest{Nonce: strings.Repeat("b", 64)})
		r := httptest.NewRequest("POST", "/readyz", bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Capability "+broker.Token(key, aud, b))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call(s.Key, "export.ready"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	bad := make([]byte, 32)
	bad[0] = 1
	if call(bad, "export.ready").Code == 200 || call(s.Key, "export.execute").Code == 200 || call(s.Key, "export.status").Code == 200 {
		t.Fatal("wrongexportreadycredentialaccepted")
	}
	if a.auth != 0 || a.complete != 0 {
		t.Fatal("readiness authorized aneffect")
	}
	s.Key = nil
	if call(nil, "export.ready").Code == 200 {
		t.Fatal("missing keyqualified")
	}
}
