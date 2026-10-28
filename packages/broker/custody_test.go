package broker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalCustodyRejectsAnotherWriterAndClosedEffects(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "receipts")
	store, e := OpenReceiptStore(directory, "model")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := OpenReceiptStore(directory, "model"); e == nil {
		t.Fatal("two local writers acquired same domain")
	}
	if e = store.Ready(); e != nil {
		t.Fatal(e)
	}
	if e = store.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = store.DoAuthorized("operation-123", Hash([]byte("op")), nil, func() (any, error) { t.Error("closed custody executed"); return "bad", nil }); !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
	next, e := OpenReceiptStore(directory, "model")
	if e != nil {
		t.Fatal("restart could not acquire custody", e)
	}
	defer next.Close()
}
func TestCustodyLossAfterAuthorizationCannotStartEffect(t *testing.T) {
	store, e := OpenReceiptStore(filepath.Join(t.TempDir(), "receipts"), "model")
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	_, e = store.DoAuthorized("operation-123", Hash([]byte("op")), func() error { return store.Close() }, func() (any, error) { t.Error("lost custody executed"); return "bad", nil })
	if !errors.Is(e, ErrUnknown) {
		t.Fatal(e)
	}
}
func TestCustodyRejectsPublicOrReplacedLock(t *testing.T) {
	directory := t.TempDir()
	if e := os.Chmod(directory, 0755); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenCustody(directory, "model"); e == nil {
		t.Fatal("public custody accepted")
	}
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	c, e := OpenCustody(directory, "model")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	path := filepath.Join(directory, ".custody.lock")
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if c.Check() == nil {
		t.Fatal("replaced custody lock accepted")
	}
}
func TestCustodyCreatesPrivateChildWithoutChangingSharedParent(t *testing.T) {
	parent := t.TempDir()
	// testing.TempDir uses 0777 subject to umask; a CI runner may expose 0755.
	// Require the same safe behavior regardless of this process's default umask.
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "receipts")
	store, err := OpenReceiptStore(directory, "model")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for path, want := range map[string]os.FileMode{parent: 0755, directory: 0700, filepath.Join(directory, ".custody.lock"): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("custody fixture permissions differ: want %04o, stat error %v", want, err)
		}
	}
	if err = store.Ready(); err != nil {
		t.Fatal("private child did not establish custody", err)
	}
}
func TestStatusClientNarrowsScopeAndPreservesTransport(t *testing.T) {
	c := NewClient("https://model:8082/execute", "model.execute", make([]byte, 32))
	status, e := c.StatusClient()
	if e != nil {
		t.Fatal(e)
	}
	if status.Audience != "model.status" || status.URL != "https://model:8082/status" || status.HTTP != c.HTTP || c.Audience != "model.execute" || c.URL != "https://model:8082/execute" {
		t.Fatal("status scope mutated or widened")
	}
	body := []byte(`{"operation_id":"op-123456"}`)
	token := Token(status.Key, status.Audience, body)
	if Verify(c.Key, c.Audience, token, body) == nil {
		t.Fatal("status capability became execute")
	}
}
func TestBrokerDoesNotFollowCredentialRedirect(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte(`{}`)) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client := NewClient(redirect.URL, "test", make([]byte, 32))
	var out any
	if client.Call(context.Background(), struct{}{}, &out) == nil || calls != 0 {
		t.Fatal("credential request followed redirect", calls)
	}
}
