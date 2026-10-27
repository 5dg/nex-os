package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/5dg/nex-os/packages/broker"
	"net/http/httptest"
	"testing"
)

func TestProducerIdentityCannotBeTransferred(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	control := make([]byte, 32)
	kernel := make([]byte, 32)
	kernel[0] = 1
	server := httptest.NewServer(Handler(&Journal{Directory: t.TempDir(), Private: private}, control, kernel))
	defer server.Close()
	event := Event{ID: "event-123", TenantID: "a", ActorID: "alice", Action: "model.intent", Producer: "kernel", Detail: json.RawMessage(`{"b":1,"a":2}`)}
	var proof Proof
	wrong := broker.NewClient(server.URL+"/append/kernel", "evidence.append.kernel", control)
	if e := wrong.Call(context.Background(), event, &proof); e == nil {
		t.Fatal("control identity forged kernel evidence")
	}
	client := broker.NewClient(server.URL+"/append/control", "evidence.append.control", control)
	if e := client.Call(context.Background(), event, &proof); e != nil {
		t.Fatal(e)
	}
	if proof.Producer != "control" {
		t.Fatal("producer label was caller-controlled")
	}
	event.Producer = "control"
	event.Detail = json.RawMessage(`{"a":2,"b":1}`)
	if !VerifyEvent(public, proof, event) {
		t.Fatal("canonical event proof failed")
	}
	event.ActorID = "mallory"
	if VerifyEvent(public, proof, event) {
		t.Fatal("altered database event retained a valid proof")
	}
}
