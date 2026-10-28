//go:build integration

package guard_test

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/trust"
	guardclient "github.com/5dg/nex-os/services/control/guard"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
)

// This exercises actual SIGTERM, TLS listener/admission and a pre-admitted RPC
// in the qualified Rust process. The fixture's database/signer are configured
// but deliberately unreachable; this Evaluate-only case makes no execution,
// persisted-state or database-driver-drain claim.
func TestQualificationRustSIGTERMClosesAdmissionAndDrainsRPC(t *testing.T) {
	q := startQualificationKernel(t)
	control, _, _ := qualIdentity(t, q.ca, trust.Control, pki.Spec{Name: "control", ClientAuth: true})
	client, err := guardclient.NewRPCWithTrust(q.address, nil, control)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if out, err := client.Evaluate(context.Background(), guardclient.Input{Action: "shutdown.positive"}); err != nil || out.Effect != "deny" {
		t.Fatal("positive qualified RPC failed before shutdown")
	}
	q.delay.Store(true)
	returned := make(chan error, 1)
	go func() {
		_, err := client.Evaluate(context.Background(), guardclient.Input{Action: "shutdown.held"})
		returned <- err
	}()
	select {
	case <-q.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("pre-admitted RPC did not reach the authenticated held policy")
	}
	if err := q.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for !strings.Contains(q.diagnostic.String(), "shutdown started; new admission closed") && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(q.diagnostic.String(), "shutdown started; new admission closed") {
		close(q.release)
		t.Fatal("actual SIGTERM did not enter the declared drain")
	}
	policyCalls := q.calls.Load()
	listenerClosed := false
	until = time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(until) {
		connection, err := net.DialTimeout("tcp", q.address, 50*time.Millisecond)
		if err != nil {
			listenerClosed = true
			break
		}
		connection.Close()
		time.Sleep(10 * time.Millisecond)
	}
	probe, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_, admissionErr := client.Evaluate(probe, guardclient.Input{Action: "shutdown.new"})
	stop()
	if admissionErr == nil || q.calls.Load() != policyCalls {
		t.Error("new RPC reached policy after shutdown admission closed")
	}
	close(q.release)
	if err := <-returned; err != nil {
		t.Errorf("valid pre-admitted RPC did not finish within the drain: %v", err)
	}
	var killed atomic.Bool
	watchdog := time.AfterFunc(5*time.Second, func() { killed.Store(true); q.command.Process.Kill() })
	err = q.command.Wait()
	watchdog.Stop()
	if err != nil || killed.Load() || !strings.Contains(q.diagnostic.String(), "shutdown completed; request and database drivers drained") {
		t.Errorf("Rust did not exit cleanly after the admitted RPC drained: error=%v watchdog_killed=%v", err, killed.Load())
	}
	if !listenerClosed {
		t.Error("qualification TCP listener still admitted connections during RPC drain")
	}
}
