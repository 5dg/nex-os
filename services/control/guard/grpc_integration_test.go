//go:build integration

package guard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/5dg/nex-os/policies"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func startKernel(t *testing.T, opa string) (*Client, string, []byte) {
	return startKernelEnv(t, opa, nil)
}
func startKernelEnv(t *testing.T, opa string, extra []string) (*Client, string, []byte) {
	t.Helper()
	binary := os.Getenv("NEX_TEST_GUARD_BINARY")
	if binary == "" {
		t.Fatal("NEX_TEST_GUARD_BINARY required; build the Rust kernel first")
	}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	keyPath := filepath.Join(t.TempDir(), "identity")
	if e := os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary)
	// Preserve proxy/CA/tool settings, but isolate test runtime configuration.
	runtimeKeys := map[string]bool{"APP_ENV": true, "GUARD_MODE": true, "GUARD_LISTEN_ADDR": true, "GUARD_KEY_FILE": true, "OPA_URL": true, "DATABASE_URL": true, "DATABASE_URL_FILE": true, "MODEL_GUARD_KEY_FILE": true, "EXPORT_GUARD_KEY_FILE": true, "EVIDENCE_URL": true, "EVIDENCE_KEY_FILE": true, "EVIDENCE_PUBLIC_FILE": true}
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !runtimeKeys[name] {
			command.Env = append(command.Env, item)
		}
	}
	command.Env = append(command.Env, "APP_ENV=development", "GUARD_LISTEN_ADDR="+address, "GUARD_KEY_FILE="+keyPath, "OPA_URL="+opa)
	diagnostic := &startupStderr{}
	command.Stderr = diagnostic
	mode := "evaluation"
	for _, item := range extra {
		if strings.HasPrefix(item, "DATABASE_URL=") {
			mode = "execution"
		}
	}
	command.Env = append(command.Env, "GUARD_MODE="+mode)
	command.Env = append(command.Env, extra...)
	if e = command.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); command.Wait() })
	client, e := NewRPC(address, key, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	// Wait for the TCP listener, independent of intentionally broken OPA fixtures.
	ready := false
	for i := 0; i < 100; i++ {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Rust Guard did not start: %s", diagnostic.Text())
	}
	return client, address, key
}
func TestRustGuardBoundary(t *testing.T) {
	c, address, _ := startKernel(t, "http://127.0.0.1:8181")
	ctx := context.Background()
	if e := c.Health(ctx); e != nil {
		t.Fatal(e)
	}
	input := Input{Actor: Actor{ID: "alice", TenantID: "a", Permissions: []string{"document.read", "document.export"}}, Resource: Resource{TenantID: "a", Kind: "document", Classification: "internal", ReaderIDs: []string{"alice"}}, Action: "document.read", DelegationValid: true, DelegationPermissions: []string{"document.read", "document.export"}, DataClassification: "public"}
	for _, test := range []struct {
		name, effect string
		change       func(*Input)
	}{
		{"allow", "allow", func(*Input) {}},
		{"cross tenant", "deny", func(i *Input) { i.Resource.TenantID = "b" }},
		{"revoked delegation", "deny", func(i *Input) { i.DelegationValid = false }},
		{"unknown action", "deny", func(i *Input) { i.Action = "shell.execute" }},
		{"restricted", "deny", func(i *Input) { i.Resource.Classification = "restricted" }},
		{"approval required", "require_approval", func(i *Input) { i.Action = "document.export" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := input
			test.change(&in)
			out, e := c.Evaluate(ctx, in)
			if e != nil || out.Effect != test.effect || out.PolicyDigest != Digest() {
				t.Fatalf("decision %v, error %v", out, e)
			}
		})
	}
	t.Run("wrong service identity", func(t *testing.T) {
		wrong, e := NewRPC(address, make([]byte, 32), true)
		if e != nil {
			t.Fatal(e)
		}
		defer wrong.Close()
		if _, e = wrong.Evaluate(ctx, input); e == nil {
			t.Fatal("untrusted service accepted")
		}
	})
	t.Run("production plaintext rejected", func(t *testing.T) {
		if _, e := NewRPC(address, make([]byte, 32), false); e == nil {
			t.Fatal("production plaintext accepted")
		}
	})
}
func TestRustGuardFailsClosed(t *testing.T) {
	t.Run("OPA unavailable", func(t *testing.T) {
		c, _, _ := startKernel(t, "http://127.0.0.1:1")
		if e := c.Health(context.Background()); e == nil {
			t.Fatal("OPA outage accepted")
		}
	})
	for _, test := range []struct{ name, source, result string }{{"source mismatch", "changed policy", `{"result":{"effect":"allow","reason_code":"OK","policy_version":"alpha-guard-v1"}}`}, {"invalid effect", string(policies.Source), `{"result":{"effect":"unrecognized","reason_code":"OK","policy_version":"alpha-guard-v1"}}`}, {"missing result", string(policies.Source), `{}`}} {
		t.Run(test.name, func(t *testing.T) {
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/policies" {
					json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]string{"raw": test.source}}})
				} else {
					fmt.Fprint(w, test.result)
				}
			}))
			defer fake.Close()
			c, _, _ := startKernel(t, fake.URL)
			if e := c.Health(context.Background()); e == nil {
				t.Fatal("invalid policy response accepted")
			}
		})
	}
}

// startupStderr retains bounded diagnostics after exec.Run has joined its
// stderr-copy goroutine. It never retains service key contents.
type startupStderr struct {
	mu   sync.Mutex
	data []byte
}

func (b *startupStderr) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := 4096 - len(b.data)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (b *startupStderr) Text() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

func TestExecutionStartupRejectsIncompleteProfiles(t *testing.T) {
	binary := os.Getenv("NEX_TEST_GUARD_BINARY")
	if binary == "" {
		t.Fatal("NEX_TEST_GUARD_BINARY required")
	}
	directory := t.TempDir()
	files := map[string]string{}
	keys := map[string][]byte{}
	write := func(name string, key []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if e := os.WriteFile(path, key, 0600); e != nil {
			t.Fatal(e)
		}
		files[name] = path
		return path
	}
	for _, name := range []string{"control", "model", "export", "writer"} {
		key := make([]byte, 32)
		if _, e := rand.Read(key); e != nil {
			t.Fatal(e)
		}
		keys[name] = key
		write(name, key)
	}
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	write("public", public)
	shortKey := write("short-key", make([]byte, 31))
	shortPublic := write("short-public", make([]byte, 31))
	weakPublic := write("weak-public", make([]byte, 32))
	base := []string{"APP_ENV=development", "GUARD_MODE=execution", "OPA_URL=http://127.0.0.1:8181", "GUARD_KEY_FILE=" + files["control"], "DATABASE_URL=postgres://unused:5432/configuration_probe?sslmode=disable", "MODEL_GUARD_KEY_FILE=" + files["model"], "EXPORT_GUARD_KEY_FILE=" + files["export"], "EVIDENCE_URL=http://127.0.0.1:1", "EVIDENCE_KEY_FILE=" + files["writer"], "EVIDENCE_PUBLIC_FILE=" + files["public"]}
	t.Run("complete profile starts", func(t *testing.T) {
		// Startup validates configuration without executing or connecting to the
		// placeholder database/signer. This positive control prevents the rejection
		// table from passing because its common configuration is already invalid.
		_, address, _ := startKernelEnv(t, "http://127.0.0.1:8181", base)
		c, e := NewRPC(address, keys["control"], true)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		d, e := c.Evaluate(ctx, Input{Action: "startup.probe"})
		if e != nil || d.Effect != "deny" {
			t.Fatalf("valid profile policy probe failed: %v %v", d, e)
		}
	})
	type startupCase struct {
		name, key, value string
		omit             bool
	}
	cases := []startupCase{}
	for _, key := range []string{"EVIDENCE_URL", "EVIDENCE_KEY_FILE", "EVIDENCE_PUBLIC_FILE", "DATABASE_URL", "MODEL_GUARD_KEY_FILE", "EXPORT_GUARD_KEY_FILE", "OPA_URL", "GUARD_KEY_FILE", "GUARD_MODE"} {
		cases = append(cases, startupCase{name: "omitted " + key, key: key, omit: true})
	}
	cases = append(cases, []startupCase{
		{name: "malformed signer URL", key: "EVIDENCE_URL", value: "not a URL"},
		{name: "unsupported signer scheme", key: "EVIDENCE_URL", value: "file:///tmp/evidence"},
		{name: "malformed signer key", key: "EVIDENCE_KEY_FILE", value: shortKey},
		{name: "missing signer key file", key: "EVIDENCE_KEY_FILE", value: filepath.Join(directory, "missing")},
		{name: "malformed signer public key", key: "EVIDENCE_PUBLIC_FILE", value: shortPublic},
		{name: "weak signer public key", key: "EVIDENCE_PUBLIC_FILE", value: weakPublic},
		{name: "empty state configuration", key: "DATABASE_URL", value: ""},
		{name: "malformed state configuration", key: "DATABASE_URL", value: "://invalid"},
		{name: "malformed policy URL", key: "OPA_URL", value: "not a URL"},
		{name: "unsupported policy scheme", key: "OPA_URL", value: "file:///tmp/policy"},
		{name: "unknown profile", key: "GUARD_MODE", value: "optional-signing"},
		{name: "evaluation profile with state", key: "GUARD_MODE", value: "evaluation"},
		{name: "malformed control identity", key: "GUARD_KEY_FILE", value: shortKey},
		{name: "malformed model identity", key: "MODEL_GUARD_KEY_FILE", value: shortKey},
		{name: "malformed export identity", key: "EXPORT_GUARD_KEY_FILE", value: shortKey},
		{name: "shared executor identities", key: "MODEL_GUARD_KEY_FILE", value: files["export"]},
		{name: "model shares control identity", key: "MODEL_GUARD_KEY_FILE", value: files["control"]},
		{name: "export shares control identity", key: "EXPORT_GUARD_KEY_FILE", value: files["control"]},
	}...)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary)
			diagnostic := &startupStderr{}
			command.Stderr = diagnostic
			for _, item := range base {
				if !strings.HasPrefix(item, test.key+"=") {
					command.Env = append(command.Env, item)
				}
			}
			if !test.omit {
				command.Env = append(command.Env, test.key+"="+test.value)
			}
			command.Env = append(command.Env, "GUARD_LISTEN_ADDR=127.0.0.1:0")
			e := command.Run()
			if e == nil || ctx.Err() != nil {
				t.Fatalf("invalid %s did not reject startup (error=%v timeout=%v stderr=%q)", test.key, e, ctx.Err(), diagnostic.Text())
			}
			if diagnostic.Text() == "" {
				t.Fatalf("startup failed without diagnostics: %v", e)
			}
		})
	}
	t.Run("evaluation cannot execute", func(t *testing.T) {
		c, address, _ := startKernelEnv(t, "http://127.0.0.1:8181", []string{"GUARD_MODE=evaluation", "MODEL_GUARD_KEY_FILE=" + files["model"], "EXPORT_GUARD_KEY_FILE=" + files["export"]})
		executor, e := NewRPC(address, keys["model"], true)
		if e != nil {
			t.Fatal(e)
		}
		defer executor.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if allowed, e := executor.AuthorizeExecution(ctx, "operation-123", strings.Repeat("0", 64)); allowed || e == nil {
			t.Fatalf("evaluation granted execution: %v %v", allowed, e)
		}
		if _, _, e := c.PrepareExecution(ctx, "job-123456", "operation-123"); e == nil {
			t.Fatal("evaluation prepared an operation")
		}
	})
}
