//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/services/control/auth"
	"github.com/5dg/nex-os/services/control/devseed"
	"github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/services/control/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

type historyWireEvent struct {
	ID         string          `json:"event_id"`
	Tenant     string          `json:"tenant_id"`
	Actor      string          `json:"actor_id"`
	Job        string          `json:"job_id"`
	Resource   string          `json:"resource_id"`
	Delegation string          `json:"delegation_id"`
	Action     string          `json:"action"`
	Detail     json.RawMessage `json:"detail"`
	Timestamp  int64           `json:"timestamp_us"`
	Proof      evidence.Proof  `json:"integrity_reference"`
	Verified   bool            `json:"integrity_verified"`
	Producer   string          `json:"producer"`
}

type historyWirePage struct {
	Events []historyWireEvent `json:"events"`
	Cursor string             `json:"next_cursor"`
}

// This fixture uses real PostgreSQL, OPA decisions, signed audit events and HTTP
// authorization. Its issuer/signer are private development fixtures. API-created
// jobs remain queued: no worker, receiver or protected completion is fabricated.
func TestHistoryPaginationIntegration(t *testing.T) {
	ctx := context.Background()
	database, policyURL := os.Getenv("NEX_TEST_DATABASE_URL"), os.Getenv("NEX_TEST_OPA_URL")
	if database == "" || policyURL == "" {
		t.Fatal("NEX_TEST_DATABASE_URL and NEX_TEST_OPA_URL required")
	}
	admin, err := pgxpool.New(ctx, database)
	if err != nil {
		t.Fatal("history fixture database configuration unavailable")
	}
	defer admin.Close()
	schema := "history_" + strings.ToLower(rand.Text())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("history fixture schema cleanup failed")
		}
	}()
	config, err := pgxpool.ParseConfig(database)
	if err != nil {
		t.Fatal("history fixture database configuration invalid")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "3000"
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	t.Run("historical sequence JSON cannot break PostgreSQL traversal", func(t *testing.T) {
		for _, tc := range []struct {
			raw  string
			want int64
		}{
			{`null`, 0}, {`{}`, 0}, {`{"sequence":null}`, 0}, {`{"sequence":"12"}`, 0},
			{`{"sequence":-1}`, 0}, {`{"sequence":0}`, 0}, {`{"sequence":1.5}`, 0},
			{`{"sequence":9223372036854775808}`, 0}, {`{"sequence":9999999999999999999999999999}`, 0},
			{`{"sequence":12}`, 12}, {`{"sequence":9223372036854775807}`, 9223372036854775807},
		} {
			var got int64
			if err := db.QueryRow(ctx, "SELECT "+historySequenceSQL+" FROM (SELECT $1::jsonb AS integrity_reference) fixture", tc.raw).Scan(&got); err != nil {
				t.Fatalf("historical sequence query failed for %s: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("historical sequence %s mapped to %d, want %d", tc.raw, got, tc.want)
			}
		}
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		enc := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "history", "use": "sig", "alg": "RS256", "n": enc.EncodeToString(key.N.Bytes()), "e": enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	defer issuer.Close()
	if err = devseed.Seed(ctx, db, issuer.URL); err != nil {
		t.Fatal(err)
	}
	if err = devseed.SeedWorkflow(ctx, db, issuer.URL); err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.New(ctx, issuer.URL, "history-api")
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	for _, subject := range []string{"alice", "carol", "bob"} {
		claims, _ := json.Marshal(map[string]any{"iss": issuer.URL, "sub": subject, "aud": "history-api", "exp": time.Now().Add(5 * time.Minute).Unix()})
		enc := base64.RawURLEncoding
		body := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"history"}`)) + "." + enc.EncodeToString(claims)
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		tokens[subject] = body + "." + enc.EncodeToString(signature)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writerKey := make([]byte, 32)
	if _, err = rand.Read(writerKey); err != nil {
		t.Fatal(err)
	}
	journal, err := evidence.OpenJournal(filepath.Join(t.TempDir(), "journal"), private)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	signer := httptest.NewServer(evidence.Handler(journal, writerKey, make([]byte, 32)))
	defer signer.Close()
	s := &Server{DB: db, Auth: verifier, Policy: guard.New(policyURL), Environment: "development", EvidenceRPC: broker.NewClient(signer.URL+"/append/control", "evidence.append.control", writerKey), EvidencePublic: public}
	cursorKey := make([]byte, 32)
	if _, err = rand.Read(cursorKey); err != nil {
		t.Fatal(err)
	}
	rotatedKey := make([]byte, 32)
	if _, err = rand.Read(rotatedKey); err != nil {
		t.Fatal(err)
	}
	if err = s.SetHistoryCursorKeys(cursorKey, rotatedKey); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	newReplica := func(key, previous []byte) *httptest.Server {
		t.Helper()
		replica := &Server{DB: db, Auth: verifier, Policy: guard.New(policyURL), Environment: "development", EvidenceRPC: broker.NewClient(signer.URL+"/append/control", "evidence.append.control", writerKey), EvidencePublic: public}
		if err := replica.SetHistoryCursorKeys(key, previous); err != nil {
			t.Fatal(err)
		}
		return httptest.NewServer(replica.Handler())
	}
	second := newReplica(rotatedKey, cursorKey)
	defer second.Close()
	rotated := newReplica(rotatedKey, nil)
	defer rotated.Close()
	requestTo := func(destination *httptest.Server, subject, method, path string, body any, want int) []byte {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, method, destination.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+tokens[subject])
		response, err := destination.Client().Do(r)
		if err != nil {
			t.Fatal("history API request unavailable")
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("history API status %d, want %d: %s", response.StatusCode, want, raw)
		}
		return raw
	}
	request := func(subject, method, path string, body any, want int) []byte {
		t.Helper()
		return requestTo(server, subject, method, path, body, want)
	}
	create := func() string {
		t.Helper()
		raw := request("alice", "POST", "/v1/jobs", contracts.CreateJob{DelegationID: "delegation-alice", DocumentID: "review-alice", Question: "Synthetic history qualification", IdempotencyKey: rand.Text()}, 202)
		var job contracts.ReviewJob
		if json.Unmarshal(raw, &job) != nil || job.ID == "" || job.State != "queued" {
			t.Fatal("real queued history job required")
		}
		return job.ID
	}
	job, otherJob := create(), create()
	path := "/v1/jobs/" + job
	for range 192 {
		request("alice", "GET", path, nil, 200)
	}

	// A real signed audit-only transaction starts before the snapshot and commits
	// afterward with an older timestamp. It must never leak into continuation pages.
	late, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer late.Rollback(ctx)
	lateID := rand.Text()
	if _, err = late.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,delegation_id,resource_id,action,decision,job_id,created_at) VALUES($1,'tenant-a','alice','delegation-alice','review-alice','history.fixture','{"outcome":"late synthetic audit"}',$2,clock_timestamp()-interval '30 seconds')`, lateID, job); err != nil {
		t.Fatal(err)
	}
	if err = s.anchor(ctx, late, lateID); err != nil {
		t.Fatal(err)
	}
	page := func(cursor string) historyWirePage {
		t.Helper()
		query := "?page=1"
		if cursor != "" {
			query += "&cursor=" + url.QueryEscape(cursor)
		}
		raw := request("alice", "GET", path+"/events"+query, nil, 200)
		if len(raw) > 96*1024 {
			t.Fatal("history page exceeded 96KiB")
		}
		var value historyWirePage
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if len(value.Events) > 32 {
			t.Fatal("history page exceeded 32 items")
		}
		for _, event := range value.Events {
			if !event.Verified || event.Job != job || event.Tenant != "tenant-a" || !evidence.VerifyEvent(public, event.Proof, evidence.Event{ID: event.ID, TenantID: event.Tenant, ActorID: event.Actor, JobID: event.Job, ResourceID: event.Resource, DelegationID: event.Delegation, Action: event.Action, Detail: event.Detail, Timestamp: event.Timestamp, Producer: event.Producer}) {
				t.Fatal("history returned an invalid or out-of-scope signed event")
			}
		}
		return value
	}
	var countBefore int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1`, job).Scan(&countBefore); err != nil {
		t.Fatal(err)
	}
	firstPage := page("")
	if firstPage.Cursor == "" {
		t.Fatal("fixture did not require continuation")
	}
	var expected []string
	rows, err := db.Query(ctx, `SELECT id FROM audit_events WHERE job_id=$1 ORDER BY (integrity_reference->>'sequence')::bigint,created_at,id`, job)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(expected) != countBefore+1 {
		t.Fatal("first page must commit exactly its own authorized read audit")
	}
	if err = late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	all, cursor := firstPage.Events, firstPage.Cursor
	pages := 1
	seen := map[string]bool{cursor: true}
	for cursor != "" {
		if pages > 32 {
			t.Fatal("history traversal did not terminate")
		}
		next := page(cursor)
		all, cursor = append(all, next.Events...), next.Cursor
		if cursor != "" && seen[cursor] {
			t.Fatal("history cursor repeated")
		}
		seen[cursor] = true
		pages++
	}
	actual := make([]string, len(all))
	for i, event := range all {
		actual[i] = event.ID
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("snapshot lost, reordered or admitted a late event/page-read audit")
	}
	large, err := json.Marshal(all)
	if err != nil || len(large) <= 128*1024 {
		t.Fatal("signed history fixture did not exceed the BFF whole-response limit")
	}
	var currentCount int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE job_id=$1`, job).Scan(&currentCount); err != nil {
		t.Fatal(err)
	}
	if currentCount != len(expected)+pages {
		t.Fatal("continuation reads or the late event were not durably audited")
	}
	// Replaying a valid continuation returns identical signed bytes despite new
	// read events. A new snapshot must eventually include the committed late audit.
	replayed := page(firstPage.Cursor)
	if !reflect.DeepEqual(replayed.Events, all[len(firstPage.Events):len(firstPage.Events)+len(replayed.Events)]) {
		t.Fatal("cursor replay changed immutable snapshot bytes")
	}
	query := path + "/events?page=1&cursor=" + url.QueryEscape(firstPage.Cursor)
	rawReplica := requestTo(second, "alice", "GET", query, nil, 200)
	var replicaPage historyWirePage
	if json.Unmarshal(rawReplica, &replicaPage) != nil || !reflect.DeepEqual(replicaPage.Events, replayed.Events) {
		t.Fatal("replica continuation changed the signed snapshot")
	}
	newFirst := requestTo(second, "alice", "GET", path+"/events?page=1", nil, 200)
	var newPage historyWirePage
	if json.Unmarshal(newFirst, &newPage) != nil || newPage.Cursor == "" {
		t.Fatal("new-key replica must issue a continuation")
	}
	newContinuation := requestTo(server, "alice", "GET", path+"/events?page=1&cursor="+url.QueryEscape(newPage.Cursor), nil, 200)
	var newNext historyWirePage
	if json.Unmarshal(newContinuation, &newNext) != nil || len(newNext.Events) == 0 {
		t.Fatal("prepared old-key replica rejected the new-key continuation")
	}
	rawRotated := requestTo(rotated, "alice", "GET", query, nil, 400)
	var denied struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(rawRotated, &denied) != nil || denied.Code != "INVALID_HISTORY_CURSOR" {
		t.Fatal("replica with a different key accepted cursor")
	}
	fresh := page("")
	freshIDs := []string{}
	for freshPages := 0; ; freshPages++ {
		if freshPages > 32 {
			t.Fatal("fresh history traversal did not terminate")
		}
		for _, event := range fresh.Events {
			freshIDs = append(freshIDs, event.ID)
		}
		if fresh.Cursor == "" {
			break
		}
		fresh = page(fresh.Cursor)
	}
	lateOccurrences := 0
	for _, id := range freshIDs {
		if id == lateID {
			lateOccurrences++
		}
	}
	if lateOccurrences != 1 {
		t.Fatal("fresh complete snapshot must contain the committed older-timestamp event exactly once")
	}
	assertCode := func(subject, target, cursor, code string, want int) {
		t.Helper()
		raw := request(subject, "GET", target+"?page=1&cursor="+url.QueryEscape(cursor), nil, want)
		var value struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(raw, &value) != nil || value.Code != code {
			t.Fatalf("expected typed history denial %s", code)
		}
	}
	t.Run("cursor tamper and scope", func(t *testing.T) {
		assertCode("alice", path+"/events", firstPage.Cursor+"x", "INVALID_HISTORY_CURSOR", 400)
		assertCode("alice", "/v1/jobs/"+otherJob+"/events", firstPage.Cursor, "INVALID_HISTORY_CURSOR", 400)
		assertCode("carol", path+"/events", firstPage.Cursor, "DENIED_BY_POLICY", 403)
		assertCode("bob", path+"/events", firstPage.Cursor, "DENIED_BY_POLICY", 403)
		expired, err := s.decodeHistoryCursor(firstPage.Cursor, "tenant-a", "alice", job, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		expired.Expires = time.Now().Add(-time.Second).Unix()
		token, err := s.encodeHistoryCursor(expired)
		if err != nil {
			t.Fatal(err)
		}
		assertCode("alice", path+"/events", token, "INVALID_HISTORY_CURSOR", 400)
	})
	t.Run("same token rechecks permission and delegation", func(t *testing.T) {
		if _, err := db.Exec(ctx, `UPDATE users SET permissions=array_remove(permissions,'document.read') WHERE id='alice'`); err != nil {
			t.Fatal(err)
		}
		assertCode("alice", path+"/events", firstPage.Cursor, "DENIED_BY_POLICY", 403)
		raw := requestTo(second, "alice", "GET", query, nil, 403)
		var denied struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(raw, &denied) != nil || denied.Code != "DENIED_BY_POLICY" {
			t.Fatal("shared cursor key bypassed current permission on another replica")
		}
		if _, err := db.Exec(ctx, `UPDATE users SET permissions=array_append(permissions,'document.read') WHERE id='alice'`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `UPDATE delegations SET revoked_at=clock_timestamp() WHERE id='delegation-alice'`); err != nil {
			t.Fatal(err)
		}
		assertCode("alice", path+"/events", firstPage.Cursor, "DENIED_BY_POLICY", 403)
		if _, err := db.Exec(ctx, `UPDATE delegations SET revoked_at=NULL WHERE id='delegation-alice'`); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy refuses oversized history without truncation", func(t *testing.T) {
		raw := request("alice", "GET", path+"/events", nil, 400)
		var value struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(raw, &value) != nil || value.Code != "HISTORY_PAGINATION_REQUIRED" {
			t.Fatal("oversized legacy history did not return typed pagination requirement")
		}
	})
	t.Run("earlier transaction timestamp cannot reorder a later signed append", func(t *testing.T) {
		// This exercises the production component writer and the actual HTTP read
		// boundary. It is not a claim of a full held-HTTP-request fault scenario.
		lookup, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := loadJob(ctx, lookup, otherJob)
		if err != nil {
			_ = lookup.Rollback(ctx)
			t.Fatal(err)
		}
		if err = lookup.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		early, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer early.Rollback(ctx)
		var began time.Time
		if err = early.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&began); err != nil {
			t.Fatal(err)
		}
		read := func() historyWirePage {
			raw := request("alice", "GET", "/v1/jobs/"+otherJob+"/events?page=1", nil, 200)
			var value historyWirePage
			if json.Unmarshal(raw, &value) != nil || len(value.Events) == 0 || value.Cursor != "" {
				t.Fatal("small complete real history snapshot required")
			}
			return value
		}
		before := read()
		last := before.Events[len(before.Events)-1]
		if !began.Before(time.UnixMicro(last.Timestamp)) {
			t.Fatal("fixture did not establish an earlier transaction timestamp")
		}
		if err = s.record(ctx, early, loaded, "history.fixture", "earlier transaction, later signed append"); err != nil {
			t.Fatal(err)
		}
		if err = early.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		after := read()
		if len(after.Events) != len(before.Events)+2 || !reflect.DeepEqual(after.Events[:len(before.Events)], before.Events) {
			t.Fatal("later signed append reordered or replaced existing exact history prefix")
		}
		appended := after.Events[len(before.Events)]
		if appended.Action != "history.fixture" || appended.Timestamp >= last.Timestamp || appended.Proof.Sequence <= last.Proof.Sequence {
			t.Fatal("expected older timestamp with newer signed sequence after the retained prefix")
		}
		for _, event := range after.Events {
			if !event.Verified || !evidence.VerifyEvent(public, event.Proof, evidence.Event{ID: event.ID, TenantID: event.Tenant, ActorID: event.Actor, JobID: event.Job, ResourceID: event.Resource, DelegationID: event.Delegation, Action: event.Action, Detail: event.Detail, Timestamp: event.Timestamp, Producer: event.Producer}) {
				t.Fatal("refreshed event failed independent signed-content verification")
			}
		}
	})
	var effects int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM execution_operations WHERE job_id=$1`, job).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if effects != 0 {
		t.Fatal("history regression unexpectedly created protected execution state")
	}
	t.Logf("Signed history pagination: %d bytes, %d events, %d bounded pages; late commit excluded and independent signatures verified", len(large), len(all), pages)
}
