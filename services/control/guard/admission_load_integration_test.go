//go:build integration

package guard_test

import (
	"context"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Bounded synthetic Evaluate-only capacity proof; it does not measure actual
// PostgreSQL capacity or provider throughput, and emits no trust material.
func TestQualificationRustAdmissionSaturationCancellationAndRecovery(t *testing.T) {
	q := startQualificationKernel(t)
	control, _, _ := qualIdentity(t, q.ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	client, err := guardclient.NewRPCWithTrust(q.address, nil, control)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Evaluate(context.Background(), guardclient.Input{Action: "load.positive"}); err != nil {
		t.Fatal("healthy qualified RPC unavailable")
	}
	q.delay.Store(true)
	baseline := q.calls.Load()
	returned := make(chan error, 17)
	first, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	for i := 0; i < 16; i++ {
		ctx := context.Background()
		if i == 0 {
			ctx = first
		}
		go func(ctx context.Context) {
			_, e := client.Evaluate(ctx, guardclient.Input{Action: "load.held"})
			returned <- e
		}(ctx)
	}
	// Each admitted Evaluate fetches the policy source and its decision;
	// only the decision response is held by the fixture.
	deadline := time.Now().Add(3 * time.Second)
	for q.calls.Load() != baseline+32 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if q.calls.Load() != baseline+32 {
		close(q.release)
		t.Fatalf("expected 16 admitted requests; got policy_calls=%d", q.calls.Load()-baseline)
	}
	overflow, err := guardclient.NewRPCWithTrust(q.address, nil, control)
	if err != nil {
		t.Fatal(err)
	}
	defer overflow.Close()
	probe, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_, err = overflow.Evaluate(probe, guardclient.Input{Action: "load.overflow"})
	stop()
	if status.Code(err) != codes.ResourceExhausted || q.calls.Load() != baseline+32 {
		t.Errorf("17th request not rejected before policy: code=%s delta=%d", status.Code(err), q.calls.Load()-baseline)
	}
	cancelFirst()
	select {
	case e := <-returned:
		if status.Code(e) != codes.Canceled {
			t.Errorf("cancelled request returned %v", e)
		}
	case <-time.After(time.Second):
		t.Error("cancellation did not reach native gRPC caller")
	}
	// Cancellation releases the actual Rust permit, not merely client wait state.
	recovered := false
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, e := overflow.Evaluate(ctx, guardclient.Input{Action: "load.slot-recovery"})
		cancel()
		if status.Code(e) != codes.ResourceExhausted {
			recovered = q.calls.Load() > baseline+32
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(q.release)
	for i := 0; i < 15; i++ {
		if e := <-returned; e != nil {
			t.Errorf("valid held request failed after release: %v", e)
		}
	}
	q.delay.Store(false)
	if !recovered {
		t.Error("cancelled admission slot did not recover")
	}
	if _, err = client.Evaluate(context.Background(), guardclient.Input{Action: "load.healthy-after"}); err != nil {
		t.Fatalf("healthy RPC after bounded load unavailable: %v", err)
	}
}
