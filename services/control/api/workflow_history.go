package api

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/5dg/nex-os/packages/evidence"
	"github.com/jackc/pgx/v5"
)

const (
	historyPageItems      = 32
	historyPageBytes      = 96 * 1024
	historyCursorBytes    = 4096
	historyCursorLifetime = 15 * time.Minute
)

// Signing sequence is immutable and advances under the same-job lock. Unlike
// transaction-start timestamps it cannot place a later admitted write before a
// previously returned prefix. Unsigned/invalid-sequence historical records remain
// available at sequence zero, in their original timestamp/id order. Nested CASE
// guards numeric casts so malformed historical JSON never causes a SQL cast error.
const historySequenceSQL = `(CASE WHEN jsonb_typeof(integrity_reference->'sequence')='number' AND (integrity_reference->>'sequence') ~ '^[1-9][0-9]{0,18}$' THEN CASE WHEN (integrity_reference->>'sequence')::numeric<=9223372036854775807 THEN (integrity_reference->>'sequence')::bigint ELSE 0 END ELSE 0 END)`

// The transaction visibility snapshot is part of the cursor. A timestamp alone
// is not a stable snapshot: an older transaction can commit later with an earlier
// created_at. The snapshot excludes those late commits and subsequent page reads.
// SnapshotXID includes the first page's own authorization audit, which is not yet
// committed when pg_current_snapshot is taken. Audit rows are append-only.
type historyCursor struct {
	Version         int       `json:"v"`
	Tenant          string    `json:"tenant"`
	Actor           string    `json:"actor"`
	Job             string    `json:"job"`
	Snapshot        string    `json:"snapshot"`
	SnapshotXID     string    `json:"xid"`
	ThroughTime     time.Time `json:"through_time"`
	ThroughID       string    `json:"through_id"`
	ThroughSequence int64     `json:"through_sequence"`
	AfterTime       time.Time `json:"after_time"`
	AfterID         string    `json:"after_id"`
	AfterSequence   int64     `json:"after_sequence"`
	Expires         int64     `json:"expires"`
}

type historyPage struct {
	Events     []map[string]any `json:"events"`
	NextCursor string           `json:"next_cursor"`
}

var errHistoryCursor = errors.New("invalid or expired history cursor")

// SetHistoryCursorKey configures a separately provisioned 32-byte cursor key
// before this server handles requests. Replicas sharing the key can validate
// each other's cursors. Changing it invalidates existing cursors. The caller
// must provision a cryptographically random key, independent of evidence and
// service capability keys. Once the signer has been initialized it is immutable.
func (s *Server) SetHistoryCursorKey(key []byte) error {
	if len(key) != 32 || hmac.Equal(key, make([]byte, 32)) {
		return errors.New("nonzero 32-byte history cursor key required")
	}
	configured := false
	s.historySecretOnce.Do(func() {
		copy(s.historySecret[:], key)
		configured = true
	})
	if !configured {
		return errors.New("history cursor signer already initialized")
	}
	return nil
}

func (s *Server) historyMAC(payload []byte) []byte {
	// Without an explicitly provisioned shared key, use a process-local secret.
	// Cursors never grant access; each page still rechecks current authority.
	s.historySecretOnce.Do(func() { _, _ = rand.Read(s.historySecret[:]) })
	m := hmac.New(sha256.New, s.historySecret[:])
	_, _ = m.Write([]byte("nex-history-cursor-v2\x00"))
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

func (s *Server) encodeHistoryCursor(c historyCursor) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(s.historyMAC(payload))
	if len(encoded) > historyCursorBytes {
		return "", errors.New("history snapshot exceeds cursor limit")
	}
	return encoded, nil
}

func (s *Server) decodeHistoryCursor(encoded, tenant, actor, job string, now time.Time) (historyCursor, error) {
	var c historyCursor
	if len(encoded) == 0 || len(encoded) > historyCursorBytes {
		return c, errHistoryCursor
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return c, errHistoryCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return c, errHistoryCursor
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != parts[1] || !hmac.Equal(signature, s.historyMAC(payload)) {
		return c, errHistoryCursor
	}
	if json.Unmarshal(payload, &c) != nil || c.Version != 2 || c.Tenant != tenant || c.Actor != actor || c.Job != job || c.Expires <= now.Unix() || c.Expires > now.Add(historyCursorLifetime).Unix() || c.Snapshot == "" || c.SnapshotXID == "" || c.ThroughID == "" || c.AfterID == "" || c.AfterSequence < 0 || c.ThroughSequence < 0 || c.AfterSequence > c.ThroughSequence || (c.AfterSequence == c.ThroughSequence && (c.AfterTime.After(c.ThroughTime) || (c.AfterTime.Equal(c.ThroughTime) && c.AfterID > c.ThroughID))) {
		return historyCursor{}, errHistoryCursor
	}
	return c, nil
}

func historyOptions(r *http.Request) (bool, string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false, "", errHistoryCursor
	}
	for key, values := range q {
		if (key != "page" && key != "cursor") || len(values) != 1 {
			return false, "", errHistoryCursor
		}
	}
	paged := q.Get("page") == "1"
	if (q.Has("page") && !paged) || (q.Has("cursor") && (!paged || q.Get("cursor") == "")) {
		return false, "", errHistoryCursor
	}
	return paged, q.Get("cursor"), nil
}

func historyEvent(public []byte, j storedJob, id, action string, detail json.RawMessage, at time.Time, actor, delegation, resource string, rawProof json.RawMessage) map[string]any {
	var proof evidence.Proof
	verified := json.Unmarshal(rawProof, &proof) == nil && evidence.VerifyEvent(ed25519.PublicKey(public), proof, evidence.Event{ID: id, TenantID: j.TenantID, ActorID: actor, JobID: j.ID, Action: action, Detail: detail, ResourceID: resource, DelegationID: delegation, Timestamp: at.UnixMicro(), Producer: proof.Producer})
	return map[string]any{"event_id": id, "action": action, "detail": detail, "timestamp": at, "integrity_reference": rawProof, "integrity_verified": verified, "producer": proof.Producer, "tenant_id": j.TenantID, "actor_id": actor, "job_id": j.ID, "resource_id": resource, "delegation_id": delegation, "timestamp_us": at.UnixMicro()}
}

func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request) {
	paged, encoded, err := historyOptions(r)
	if err != nil {
		fail(w, 400, "INVALID_HISTORY_CURSOR", "Use page=1 and a valid cursor, or restart history from the first page")
		return
	}
	tx, a, ok := s.userTx(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	j, err := s.visibleJob(r.Context(), tx, a, r.PathValue("id"))
	if err != nil {
		workflowError(w, finishDenied(r.Context(), tx, err))
		return
	}
	var c historyCursor
	if encoded != "" {
		c, err = s.decodeHistoryCursor(encoded, a.TenantID, a.ID, j.ID, time.Now())
		if err != nil {
			fail(w, 400, "INVALID_HISTORY_CURSOR", "History expired or changed scope; refresh history from the first page")
			return
		}
	} else {
		c = historyCursor{Version: 2, Tenant: a.TenantID, Actor: a.ID, Job: j.ID, Expires: time.Now().Add(historyCursorLifetime).Unix()}
		err = tx.QueryRow(r.Context(), `SELECT pg_current_snapshot()::text,pg_current_xact_id()::text`).Scan(&c.Snapshot, &c.SnapshotXID)
		if err == nil {
			order := `created_at DESC,id DESC`
			if paged {
				order = historySequenceSQL + ` DESC,` + order
			}
			err = tx.QueryRow(r.Context(), `SELECT created_at,id,`+historySequenceSQL+` FROM audit_events WHERE tenant_id=$1 AND job_id=$2 AND (pg_visible_in_snapshot(xmin::text::xid8,$3::pg_snapshot) OR xmin::text::xid8=$4::xid8) ORDER BY `+order+` LIMIT 1`, a.TenantID, j.ID, c.Snapshot, c.SnapshotXID).Scan(&c.ThroughTime, &c.ThroughID, &c.ThroughSequence)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			if err = tx.Commit(r.Context()); err != nil {
				workflowError(w, err)
				return
			}
			if paged {
				respond(w, 200, historyPage{Events: []map[string]any{}})
			} else {
				respond(w, 200, []map[string]any{})
			}
			return
		}
		if err != nil {
			workflowError(w, err)
			return
		}
	}
	var after any
	if c.AfterID != "" {
		after = c.AfterTime
	}
	limit := historyPageItems + 1
	if !paged {
		limit = 1025
	} // Legacy arrays are bounded too, never silently truncated.
	query := `SELECT id,action,decision,created_at,actor_id,delegation_id,resource_id,integrity_reference,` + historySequenceSQL + ` FROM audit_events WHERE tenant_id=$1 AND job_id=$2 AND (pg_visible_in_snapshot(xmin::text::xid8,$3::pg_snapshot) OR xmin::text::xid8=$4::xid8) AND (created_at,id)<=($5,$6) AND ($7::timestamptz IS NULL OR (created_at,id)>($7,$8)) ORDER BY created_at,id LIMIT $9`
	args := []any{a.TenantID, j.ID, c.Snapshot, c.SnapshotXID, c.ThroughTime, c.ThroughID, after, c.AfterID, limit}
	if paged {
		query = `SELECT id,action,decision,created_at,actor_id,delegation_id,resource_id,integrity_reference,` + historySequenceSQL + ` FROM audit_events WHERE tenant_id=$1 AND job_id=$2 AND (pg_visible_in_snapshot(xmin::text::xid8,$3::pg_snapshot) OR xmin::text::xid8=$4::xid8) AND (` + historySequenceSQL + `,created_at,id)<=($5,$6,$7) AND ($8::timestamptz IS NULL OR (` + historySequenceSQL + `,created_at,id)>($9,$8,$10)) ORDER BY ` + historySequenceSQL + `,created_at,id LIMIT $11`
		args = []any{a.TenantID, j.ID, c.Snapshot, c.SnapshotXID, c.ThroughSequence, c.ThroughTime, c.ThroughID, after, c.AfterSequence, c.AfterID, limit}
	}
	rows, err := tx.Query(r.Context(), query, args...)
	if err != nil {
		workflowError(w, err)
		return
	}
	defer rows.Close()
	page := historyPage{Events: []map[string]any{}}
	for rows.Next() {
		var id, action, actor, delegation, resource string
		var detail, proof json.RawMessage
		var at time.Time
		var sequence int64
		if err = rows.Scan(&id, &action, &detail, &at, &actor, &delegation, &resource, &proof, &sequence); err != nil {
			workflowError(w, err)
			return
		}
		if !paged && len(page.Events) == limit-1 {
			fail(w, 400, "HISTORY_PAGINATION_REQUIRED", "History exceeds the bounded legacy response; use page=1")
			return
		}
		if paged && len(page.Events) == historyPageItems {
			break
		}
		event := historyEvent(s.EvidencePublic, j, id, action, detail, at, actor, delegation, resource, proof)
		if paged {
			next := c
			next.AfterTime, next.AfterID = at, id
			next.AfterSequence = sequence
			token, e := s.encodeHistoryCursor(next)
			if e != nil {
				workflowError(w, e)
				return
			}
			candidate := historyPage{Events: append(page.Events, event), NextCursor: token}
			body, e := json.Marshal(candidate)
			if e != nil {
				workflowError(w, e)
				return
			}
			if len(body)+1 > historyPageBytes {
				if len(page.Events) == 0 {
					fail(w, 413, "HISTORY_EVENT_TOO_LARGE", "One recorded event exceeds the bounded history response")
					return
				}
				break
			}
			page = candidate
		} else {
			page.Events = append(page.Events, event)
			body, e := json.Marshal(page.Events)
			if e != nil {
				workflowError(w, e)
				return
			}
			if len(body)+1 > historyPageBytes {
				fail(w, 400, "HISTORY_PAGINATION_REQUIRED", "History exceeds the bounded legacy response; use page=1")
				return
			}
		}
	}
	if err = rows.Err(); err != nil {
		workflowError(w, err)
		return
	}
	// ThroughID is the final ordered visible row, independent of any page reads
	// appended while traversing. A break resumes after the last emitted row.
	if len(page.Events) == 0 || page.Events[len(page.Events)-1]["event_id"] == c.ThroughID {
		page.NextCursor = ""
	}
	rows.Close()
	if err = tx.Commit(r.Context()); err != nil {
		workflowError(w, err)
		return
	}
	if paged {
		respond(w, 200, page)
	} else {
		respond(w, 200, page.Events)
	}
}
