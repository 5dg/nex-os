package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
)

func cursorFixture(now time.Time) historyCursor {
	return historyCursor{Version: 2, Tenant: "tenant-a", Actor: "alice", Job: "job-a", Snapshot: "100:110:101,102", SnapshotXID: "109", ThroughTime: now, ThroughID: "z", AfterTime: now.Add(-time.Second), AfterID: "a", Expires: now.Add(historyCursorLifetime).Unix()}
}

func TestConfiguredHistoryCursorKeyAcrossReplicas(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	key := bytes.Repeat([]byte{0x57}, 32)
	a, b, rotated := &Server{}, &Server{}, &Server{}
	if err := a.SetHistoryCursorKey(key); err != nil {
		t.Fatal(err)
	}
	if err := b.SetHistoryCursorKey(key); err != nil {
		t.Fatal(err)
	}
	if err := rotated.SetHistoryCursorKey(bytes.Repeat([]byte{0x31}, 32)); err != nil {
		t.Fatal(err)
	}
	// Mutating a caller's buffer after initialization must not change the key.
	key[0] ^= 0xff
	c := cursorFixture(now)
	token, err := a.encodeHistoryCursor(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now); err != nil {
		t.Fatalf("shared key rejected: %v", err)
	}
	if _, err = rotated.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now); err == nil {
		t.Fatal("rotated key accepted prior cursor")
	}
	if _, err = b.decodeHistoryCursor(token, c.Tenant, "another-actor", c.Job, now); err == nil {
		t.Fatal("shared key bypassed actor scope")
	}
	if _, err = b.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now.Add(historyCursorLifetime)); err == nil {
		t.Fatal("shared key bypassed cursor expiry")
	}
	if err = b.SetHistoryCursorKey(key); err == nil {
		t.Fatal("initialized signer accepted replacement key")
	}
}

func TestHistoryCursorKeyConfigurationFailsClosed(t *testing.T) {
	s := &Server{}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 32), make([]byte, 33)} {
		if err := s.SetHistoryCursorKey(key); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if err := s.SetHistoryCursorKey(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := (&Server{}).SetHistoryCursorKey(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatal(err)
	}
	ephemeral := &Server{}
	_ = ephemeral.historyMAC([]byte("initialize"))
	if err := ephemeral.SetHistoryCursorKey(bytes.Repeat([]byte{0x01}, 32)); err == nil {
		t.Fatal("initialized ephemeral signer accepted replacement key")
	}
}

func TestHistoryCursorScopeIntegrityAndLifetime(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	s := &Server{}
	c := cursorFixture(now)
	token, err := s.encodeHistoryCursor(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := s.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now)
	if err != nil || decoded.Snapshot != c.Snapshot || decoded.ThroughID != c.ThroughID {
		t.Fatalf("valid cursor: %+v %v", decoded, err)
	}
	for name, args := range map[string][3]string{"tenant": {"tenant-b", c.Actor, c.Job}, "actor": {c.Tenant, "bob", c.Job}, "job": {c.Tenant, c.Actor, "job-b"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.decodeHistoryCursor(token, args[0], args[1], args[2], now); err == nil {
				t.Fatal("cross-scope cursor accepted")
			}
		})
	}
	if _, err := s.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now.Add(historyCursorLifetime)); err == nil {
		t.Fatal("expired cursor accepted")
	}
	if _, err := (&Server{}).decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now); err == nil {
		t.Fatal("cursor survived restart secret")
	}
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[0])
	changed := strings.Replace(string(payload), "job-a", "job-b", 1)
	for _, bad := range []string{"", token + ".", strings.Repeat("a", historyCursorBytes+1), base64.RawURLEncoding.EncodeToString([]byte(changed)) + "." + parts[1], parts[0] + ".AA"} {
		if _, err := s.decodeHistoryCursor(bad, c.Tenant, c.Actor, c.Job, now); err == nil {
			t.Fatal("malformed or tampered cursor accepted")
		}
	}
	c.AfterTime = c.ThroughTime.Add(time.Second)
	bad, _ := s.encodeHistoryCursor(c)
	if _, err := s.decodeHistoryCursor(bad, c.Tenant, c.Actor, c.Job, now); err == nil {
		t.Fatal("out-of-snapshot boundary accepted")
	}
	c = cursorFixture(now)
	c.Snapshot = strings.Repeat("1,", historyCursorBytes)
	if _, err := s.encodeHistoryCursor(c); err == nil {
		t.Fatal("unbounded cursor emitted")
	}
}

func TestHistoryCursorSecretConcurrentInitialization(t *testing.T) {
	s := &Server{}
	now := time.Now().UTC()
	c := cursorFixture(now)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			token, err := s.encodeHistoryCursor(c)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := s.decodeHistoryCursor(token, c.Tenant, c.Actor, c.Job, now); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestHistoryQueryRequiresExplicitBoundedMode(t *testing.T) {
	for _, tt := range []struct {
		query  string
		paged  bool
		cursor string
		valid  bool
	}{
		{"", false, "", true}, {"?page=1", true, "", true}, {"?page=1&cursor=a.b", true, "a.b", true},
		{"?cursor=a.b", false, "", false}, {"?page=1&page=1", false, "", false}, {"?page=0", false, "", false}, {"?page=1&cursor=", false, "", false}, {"?limit=100000", false, "", false}, {"?page=%zz", false, "", false},
	} {
		t.Run(tt.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/jobs/job-a/events"+tt.query, nil)
			p, c, err := historyOptions(r)
			if (err == nil) != tt.valid || (tt.valid && (p != tt.paged || c != tt.cursor)) {
				t.Fatalf("got %v %q %v", p, c, err)
			}
		})
	}
}

func TestHistoryEventRetainsOriginalSignedRepresentation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	journal := &evidence.Journal{Directory: t.TempDir(), Private: private}
	at := time.Unix(1800000000, 123456000).UTC()
	detail := json.RawMessage(`{"unicode":"雪 < &","count":1.20,"outcome":"allowed"}`)
	input := evidence.Event{ID: "event-a", TenantID: "tenant-a", ActorID: "alice", JobID: "job-a", ResourceID: "document-a", DelegationID: "delegation-a", Action: "document.read", Timestamp: at.UnixMicro(), Producer: "control", Detail: detail}
	proof, err := journal.Append(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(proof)
	j := storedJob{ReviewJob: contracts.ReviewJob{ID: input.JobID, TenantID: input.TenantID}}
	out := historyEvent(public, j, input.ID, input.Action, detail, at, input.ActorID, input.DelegationID, input.ResourceID, raw)
	if out["integrity_verified"] != true || string(out["detail"].(json.RawMessage)) != string(detail) || string(out["integrity_reference"].(json.RawMessage)) != string(raw) || out["timestamp_us"] != input.Timestamp {
		t.Fatalf("original event/proof changed: %+v", out)
	}
	mutated := historyEvent(public, j, input.ID, input.Action, json.RawMessage(`{"outcome":"changed"}`), at, input.ActorID, input.DelegationID, input.ResourceID, raw)
	if mutated["integrity_verified"] != false {
		t.Fatal("changed signed content accepted")
	}
}
