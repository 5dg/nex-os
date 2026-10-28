//go:build integration

package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type committedDecisionFixture struct {
	db               *pgxpool.Pool
	entered, release chan struct{}
}

var committedDecisions sync.Map

func (g *callerGuardFixture) DecideApproval(ctx context.Context, in *pb.ApprovalRequest) (*pb.ExecutionResponse, error) {
	value, ok := committedDecisions.Load(g)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "private decision fixture absent")
	}
	f := value.(*committedDecisionFixture)
	// This is deliberately an owned Guard fixture, not a Rust authority proof.
	// Its committed row isolates the Go handler's post-dispatch classification.
	if _, err := f.db.Exec(ctx, `UPDATE approvals SET approved_at=clock_timestamp(),approver_id=$2 WHERE id=$1`, in.ApprovalId, in.ActorId); err != nil {
		return nil, status.Error(codes.Internal, "private decision commit failed")
	}
	f.entered <- struct{}{}
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.ExecutionResponse{Allowed: true, State: "approved"}, nil
}

func TestQualifiedOriginalWorkspaceExpiryAfterCommittedApprovalReturnsUnknown(t *testing.T) {
	f := newCallerFixture(t)
	ctx := context.Background()
	job, approval := rand.Text(), rand.Text()
	if _, err := f.db.Exec(ctx, `INSERT INTO jobs(id,tenant_id,owner_id,delegation_id,state,phase,document_id,document_version,question,question_id,question_version,execution_profile,operation_id,approval_id) VALUES($1,'tenant-a','alice','delegation-alice','approval_required','export','review-alice','v1','What access review and export controls apply?','access-review-controls','v1','synthetic-qualification',$2,$3)`, job, rand.Text(), approval); err != nil {
		t.Fatalf("cannot seed private post-dispatch job: %v", err)
	}
	if _, err := f.db.Exec(ctx, `INSERT INTO approvals(id,tenant_id,request_digest,expires_at,job_id,destination_id) VALUES($1,'tenant-a','private-digest',clock_timestamp()+interval '5 minutes',$2,'local-export')`, approval, job); err != nil {
		t.Fatalf("cannot seed private post-dispatch approval: %v", err)
	}
	decision := &committedDecisionFixture{db: f.db, entered: make(chan struct{}, 1), release: make(chan struct{})}
	committedDecisions.Store(f.guard, decision)
	defer committedDecisions.Delete(f.guard)
	expiry := time.Now().Add(2 * time.Second).Truncate(time.Second)
	client, request := f.prepareRequest(trust.Workspace, expiry, "POST", "/v1/approvals/"+approval+"/decision", map[string]any{"approve": true, "request_digest": "private-digest"}, ctx)
	token, err := f.issuer.MintAccessToken("carol", nil)
	if err != nil {
		t.Fatal("approver fixture token unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	type outcome struct {
		response *http.Response
		err      error
	}
	returned := make(chan outcome, 1)
	go func() { r, e := client.Do(request); returned <- outcome{r, e} }()
	select {
	case <-decision.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual approval endpoint did not dispatch to owned Guard fixture")
	}
	var approved bool
	if err = f.db.QueryRow(ctx, "SELECT approved_at IS NOT NULL FROM approvals WHERE id=$1", approval).Scan(&approved); err != nil || !approved {
		t.Fatal("fixture did not commit before reply was held")
	}
	if !time.Now().Before(expiry) {
		close(decision.release)
		t.Fatal("caller expired before committed-dispatch boundary")
	}
	time.Sleep(time.Until(expiry.Add(50 * time.Millisecond)))
	close(decision.release)
	response := <-returned
	code, detail := callerResponseDetail(t, response.response, response.err)
	if code != 503 || detail != "DEPENDENCY_UNAVAILABLE" {
		t.Fatalf("committed remote result misclassified: HTTP=%d code=%s; want unavailable/unknown", code, detail)
	}
	if err = f.db.QueryRow(ctx, "SELECT approved_at IS NOT NULL AND approver_id='carol' FROM approvals WHERE id=$1", approval).Scan(&approved); err != nil || !approved {
		t.Fatal("late caller expiry reset committed remote decision")
	}
	r, err := f.request(trust.Workspace, time.Now().Add(5*time.Minute), "GET", "/v1/jobs/"+job, nil, ctx)
	if got := callerResponse(t, r, err); got != 200 {
		t.Fatalf("fresh authenticated request could not observe durable job: %d", got)
	}
	// No receiver/provider is configured; the handler must not synthesize a
	// denied decision or undo the independently committed remote outcome.
}
