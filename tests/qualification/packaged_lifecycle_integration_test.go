//go:build integration

package qualification_test

// Run only through the single runtime coordinator's wrapper. This suite controls
// existing, identity-checked qualification containers; it never rewrites results,
// receipts, manifests, approval decisions or migrations. SQL writes are row locks
// in a transaction which is always rolled back.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	pb "github.com/5dg/nex-os/packages/contracts/gen/guardv1"
	"github.com/5dg/nex-os/packages/evidence"
	"github.com/5dg/nex-os/packages/trust"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lifecycleContainer struct {
	ID, Image string
	Config    struct {
		Labels      map[string]string
		StopTimeout int
	}
	State struct {
		Running, OOMKilled bool
		ExitCode           int
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

type lifecycleRuntime struct {
	t                             *testing.T
	project, state, output, scope string
	containers                    map[string]lifecycleContainer
}

func (r *lifecycleRuntime) docker(limit time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--host=unix:///var/run/docker.sock"}, args...)...)
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		switch key {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH":
			continue
		}
		cmd.Env = append(cmd.Env, value)
	}
	// Never return daemon diagnostics or configuration/credential text to logs.
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("owned lifecycle Docker operation failed")
	}
	return out, nil
}

func (r *lifecycleRuntime) inspect(name string) lifecycleContainer {
	r.t.Helper()
	out, err := r.docker(5*time.Second, "container", "inspect", r.project+"-"+name+"-1")
	var values []lifecycleContainer
	if err != nil || json.Unmarshal(out, &values) != nil || len(values) != 1 {
		r.t.Fatal("lifecycle container inspection failed")
	}
	c := values[0]
	if c.Config.Labels["com.docker.compose.project"] != r.project || c.Config.Labels["com.docker.compose.service"] != name || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(c.ID) || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(c.Image) {
		r.t.Fatal("lifecycle container ownership mismatch")
	}
	if old, ok := r.containers[name]; ok && (old.ID != c.ID || old.Image != c.Image) {
		r.t.Fatal("lifecycle container/image changed during the check")
	}
	return c
}

func (r *lifecycleRuntime) restart(name string) error {
	_, err := r.docker(10*time.Second, "container", "start", r.containers[name].ID)
	return err
}

func (r *lifecycleRuntime) record(name string, value any) {
	r.t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(r.output, name+".json"), append(b, '\n'), 0600) != nil {
		r.t.Fatal("cannot retain non-secret lifecycle result")
	}
}

func TestQualificationPackagedLifecycle(t *testing.T) {
	r := &lifecycleRuntime{t: t, project: os.Getenv("NEX_QUAL_PROJECT"), state: os.Getenv("NEX_QUAL_STATE_DIR"), output: os.Getenv("NEX_LIFECYCLE_OUTPUT"), scope: os.Getenv("NEX_LIFECYCLE_SCOPE"), containers: map[string]lifecycleContainer{}}
	if os.Getenv("NEX_LIFECYCLE_COORDINATED") != "1" || !regexp.MustCompile(`^nex-(qualification|alpha04-[0-9a-f]{12})$`).MatchString(r.project) || !filepath.IsAbs(r.state) || !filepath.IsAbs(r.output) || (r.scope != "canonical-candidate" && r.scope != "diagnostic-current-images") {
		t.Fatal("single coordinator wrapper and explicit isolated scope required")
	}
	if r.scope == "canonical-candidate" && os.Getenv("NEX_QUAL_CANDIDATE_MANIFEST") == "" {
		t.Fatal("canonical lifecycle requires candidate binding")
	}
	if info, err := os.Lstat(r.output); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("private lifecycle output directory required")
	}
	images := map[string]string{"guard": "NEX_GUARD_IMAGE", "model": "NEX_CONTROL_IMAGE", "executor": "NEX_CONTROL_IMAGE", "control": "NEX_CONTROL_IMAGE", "worker": "NEX_CONTROL_IMAGE"}
	for _, name := range []string{"guard", "model", "executor", "control", "worker"} {
		c := r.inspect(name)
		if !c.State.Running || c.Config.StopTimeout != 75 {
			t.Fatal("ready containers with the existing 75-second Compose grace required")
		}
		if r.scope == "canonical-candidate" && c.Image != os.Getenv(images[name]) {
			t.Fatal("running container differs from bound candidate image")
		}
		r.containers[name] = c
	}
	bindings := map[string]any{}
	for name, c := range r.containers {
		bindings[name] = map[string]string{"container_id": c.ID, "image_id": c.Image}
	}
	r.record("binding", map[string]any{"scope": r.scope, "project": r.project, "containers": bindings, "rust_drain_seconds": 20, "go_drain_seconds": 70, "compose_grace_seconds": 75, "rpc_admission": 16})
	db := kernelMutationDatabase(t, r.state)
	var active int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM jobs WHERE state IN ('queued','running','approval_required')").Scan(&active); err != nil || active != 0 {
		t.Fatal("lifecycle requires a quiescent isolated workflow stack")
	}
	if _, err := r.docker(80*time.Second, "container", "stop", "--time", "75", r.containers["worker"].ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.restart("worker"); err != nil {
			t.Error("could not restore the owned worker; coordinator must inspect")
		}
	})
	for _, name := range []string{"guard", "model", "executor", "control"} {
		if !t.Run(name, func(t *testing.T) { r.t = t; r.checkService(t, db, name) }) {
			t.Fatal("packaged lifecycle failed; preserve diagnostics and state")
		}
	}
	r.t = t
	r.record("result", map[string]any{"status": "passed", "scope": r.scope, "services": []string{"guard", "model", "executor", "control"}, "real_receiver_results": true, "no_fabricated_completion_sql": true, "replay_preserved_receipt_and_single_authorization": true, "admission_capacity_test": "separate existing native saturation gate"})
}

func lifecycleWorker(t *testing.T, state string) func(string, any, any) error {
	t.Helper()
	key, err := broker.Key(filepath.Join(state, "secrets", "worker-key"))
	if err != nil {
		t.Fatal("worker fixture credential unavailable")
	}
	client := systemClient(t, "worker")
	client.Timeout = 75 * time.Second
	return func(path string, input, out any) error {
		body, err := json.Marshal(input)
		if err != nil {
			return err
		}
		req, err := http.NewRequest("POST", "https://control:18080"+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(key))
		req.Close = true
		response, err := client.Do(req)
		if err != nil {
			return errors.New("worker transport unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("worker response status %d", response.StatusCode)
		}
		if out == nil {
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
			return err
		}
		return json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(out)
	}
}

func (r *lifecycleRuntime) receiver(t *testing.T, kind string) *broker.Client {
	t.Helper()
	role, service, port := trust.Model, "model", "8082"
	if kind == "export" {
		role, service, port = trust.Export, "executor", "8083"
	}
	c := r.inspect(service)
	// Pick the same fixed internal service network used by Control. No externally
	// supplied endpoint or TLS bypass is admitted to this fixture client.
	address := ""
	for name, network := range c.NetworkSettings.Networks {
		if _, ok := r.containers["control"].NetworkSettings.Networks[name]; ok && network.IPAddress != "" {
			address = network.IPAddress
			break
		}
	}
	if net.ParseIP(address) == nil {
		t.Fatal("receiver/control shared qualification network unavailable")
	}
	pki := filepath.Join(r.state, "current-pki")
	cfg, err := trust.LoadFiles(trust.Qualification, trust.Control, filepath.Join(pki, "ca.crt"), filepath.Join(pki, "control", "tls.crt"), filepath.Join(pki, "control", "tls.key"))
	if err != nil {
		t.Fatal("control workload trust unavailable")
	}
	tlsConfig, err := cfg.GRPCClientTLS(role, service)
	if err != nil {
		t.Fatal("receiver TLS configuration unavailable")
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	tr := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second, DialContext: func(ctx context.Context, network, endpoint string) (net.Conn, error) {
		if endpoint != service+":"+port {
			return nil, errors.New("unexpected receiver endpoint")
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(address, port))
	}}
	t.Cleanup(tr.CloseIdleConnections)
	key, err := broker.Key(filepath.Join(r.state, "secrets", kind+"-key"))
	if err != nil {
		t.Fatal("receiver capability unavailable")
	}
	return &broker.Client{URL: "https://" + service + ":" + port + "/execute", Audience: kind + ".execute", Key: key, HTTP: &http.Client{Transport: tr, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (r *lifecycleRuntime) checkService(t *testing.T, db *pgx.Conn, service string) {
	alice := newSystemBrowser(t)
	alice.login("alice")
	var job contracts.ReviewJob
	alice.workflow(map[string]any{"operation": "create", "document_id": "review-alice", "question_catalogue_id": contracts.QualificationQuestionID, "idempotency_key": fmt.Sprintf("packaged-%s-%d", service, time.Now().UnixNano())}, 202, &job)
	worker := lifecycleWorker(t, r.state)
	var lease contracts.Lease
	if err := worker("/internal/work/claim", struct{}{}, &lease); err != nil || lease.JobID != job.ID {
		t.Fatal("real worker did not claim the created lifecycle job")
	}
	kind := "model"
	expectedExport := ""
	if service == "executor" {
		if err := worker("/internal/work/"+job.ID+"/step", lease, nil); err != nil {
			t.Fatal(err)
		}
		var reviewed contracts.ReviewJob
		alice.workflow(map[string]any{"operation": "job", "id": job.ID}, 200, &reviewed)
		if reviewed.State != "completed" || reviewed.Answer == "" {
			t.Fatal("export lifecycle requires a real protected review")
		}
		var approval contracts.ApprovalView
		alice.workflow(map[string]any{"operation": "export", "id": job.ID}, 201, &approval)
		carol := newSystemBrowser(t)
		carol.login("carol")
		var visible []contracts.ApprovalView
		carol.workflow(map[string]any{"operation": "approvals"}, 200, &visible)
		for _, item := range visible {
			if item.ID == approval.ID && item.RequestDigest == approval.RequestDigest {
				expectedExport = item.ExportPreview
			}
		}
		if expectedExport == "" || expectedExport != reviewed.Answer+"\n\nSource: "+reviewed.Citation {
			t.Fatal("independent approver did not observe the exact protected preview")
		}
		carol.workflow(map[string]any{"operation": "decide", "id": approval.ID, "approve": true, "request_digest": approval.RequestDigest}, 200, nil)
		if err := worker("/internal/work/claim", struct{}{}, &lease); err != nil || lease.JobID != job.ID {
			t.Fatal("real worker did not claim independently approved export")
		}
		kind = "export"
	}
	var operation string
	if err := db.QueryRow(context.Background(), "SELECT operation_id FROM jobs WHERE id=$1", job.ID).Scan(&operation); err != nil {
		t.Fatal("actual operation identity unavailable")
	}
	control := kernelMutationClient(t, r.state, trust.Control)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	prepared, err := control.client.PrepareExecution(ctx, &pb.PrepareRequest{JobId: job.ID, OperationId: operation})
	cancel()
	if err != nil || prepared.RequestDigest == "" {
		t.Fatal("actual protected lifecycle preparation failed")
	}
	var payload any
	if kind == "model" {
		var input contracts.Generation
		if json.Unmarshal([]byte(prepared.PayloadJson), &input) != nil || contracts.ExecutionDigest(input) != prepared.RequestDigest {
			t.Fatal("invalid prepared model payload")
		}
		payload = input
	} else {
		var input contracts.Export
		if json.Unmarshal([]byte(prepared.PayloadJson), &input) != nil || contracts.ExecutionDigest(input) != prepared.RequestDigest {
			t.Fatal("invalid prepared export payload")
		}
		payload = input
	}
	receiver := r.receiver(t, kind)
	probeClient, probeURL := receiver.HTTP, strings.TrimSuffix(receiver.URL, "/execute")+"/healthz"
	if service == "control" {
		probeClient, probeURL = systemClient(t, "workspace-client"), "https://control:18080/healthz"
	}
	probeHTTP := func(limit time.Duration) bool {
		ctx, stop := context.WithTimeout(context.Background(), limit)
		defer stop()
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if err != nil {
			return false
		}
		req.Close = true
		response, err := probeClient.Do(req)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return err == nil && response.StatusCode == 200
	}
	if service == "guard" {
		ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		ready, err := control.client.CheckReadiness(ctx, &pb.ReadinessRequest{})
		stop()
		if err != nil || !ready.GetReady() {
			t.Fatal("positive packaged Guard readiness failed")
		}
	} else if !probeHTTP(3 * time.Second) {
		t.Fatal("positive direct authenticated HTTP admission failed")
	}
	blocker := kernelMutationDatabase(t, r.state)
	lock, err := blocker.Begin(context.Background())
	if err != nil {
		t.Fatal("cannot establish bounded dependency fixture")
	}
	defer lock.Rollback(context.Background())
	if _, err = lock.Exec(context.Background(), "SELECT id FROM execution_operations WHERE id=$1 FOR UPDATE", operation); err != nil {
		t.Fatal("cannot hold the existing operation")
	}
	returned := make(chan error, 1)
	go func() {
		if service == "control" {
			returned <- worker("/internal/work/"+job.ID+"/step", lease, nil)
		} else {
			var result json.RawMessage
			returned <- receiver.Call(context.Background(), payload, &result)
		}
	}()
	// Observe a real server request waiting on precisely our lock before TERM.
	deadline := time.Now().Add(1500 * time.Millisecond)
	blocked := false
	for time.Now().Before(deadline) {
		var count int
		err = db.QueryRow(context.Background(), "SELECT count(*) FROM pg_stat_activity WHERE usename='nex_guard' AND $1=ANY(pg_blocking_pids(pid))", int32(blocker.PgConn().PID())).Scan(&count)
		if err != nil {
			t.Fatal("cannot observe admitted Guard work")
		}
		if count == 1 {
			blocked = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("no actual admitted Guard request observed before shutdown")
	}
	started := time.Now()
	// Always restore the existing container, even if an assertion fails. No
	// replacement, reset, timeout increase or volume removal is allowed.
	restored := false
	t.Cleanup(func() {
		if restored {
			return
		}
		// The function's deferred lock rollback precedes this cleanup. Do not
		// call start on a still-draining process and mistake that for recovery.
		if _, err := r.docker(76*time.Second, "container", "wait", r.containers[service].ID); err != nil {
			t.Error("owned service did not finish shutdown; coordinator must inspect, no forced kill issued")
			return
		}
		if err := r.restart(service); err != nil {
			t.Error("owned lifecycle service needs coordinator recovery")
		}
	})
	if _, err = r.docker(time.Second, "container", "kill", "--signal", "TERM", r.containers[service].ID); err != nil {
		t.Fatal(err)
	}
	closed := false
	if service == "guard" {
		for time.Since(started) < 700*time.Millisecond {
			probe, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err = control.client.CheckReadiness(probe, &pb.ReadinessRequest{})
			stop()
			if status.Code(err) == codes.Unavailable {
				closed = true
				break
			}
		}
	} else {
		for time.Since(started) < 700*time.Millisecond {
			if !probeHTTP(100 * time.Millisecond) {
				closed = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !closed {
		t.Error("new packaged admission did not close promptly")
	}
	if err = lock.Rollback(context.Background()); err != nil {
		t.Fatal("cannot release the owned dependency lock")
	}
	select {
	case err = <-returned:
	case <-time.After(75 * time.Second):
		t.Fatal("admitted request exceeded the unchanged outer grace")
	}
	if err != nil && service != "guard" {
		t.Fatalf("admitted %s request failed to drain: %v", service, err)
	}
	if err != nil && service == "guard" {
		var outcome *broker.OperationError
		if errors.As(err, &outcome) && outcome.State != "unknown" {
			t.Fatal("lost Guard completion reply was incorrectly classified as a retryable no-effect result")
		}
	}
	limit := 70 * time.Second
	if service == "guard" {
		limit = 20 * time.Second
	}
	for time.Since(started) < limit {
		if !r.inspect(service).State.Running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	exited := r.inspect(service)
	if exited.State.Running || exited.State.OOMKilled || exited.State.ExitCode != 0 || time.Since(started) > limit {
		t.Fatal("packaged service did not exit cleanly within its existing drain budget")
	}
	drain := time.Since(started)
	if err = r.restart(service); err != nil {
		t.Fatal(err)
	}
	restored = true
	receiver = r.receiver(t, kind)
	if service == "control" {
		until := time.Now().Add(10 * time.Second)
		for !probeHTTP(time.Second) {
			if time.Now().After(until) {
				t.Fatal("restarted packaged control did not admit fresh requests")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// A completed local receipt may precede protected completion when Guard exits
	// between authorization and acknowledgement. Status reconciles that durable
	// fact through the real Guard; it never calls the provider again.
	statusClient, err := receiver.StatusClient()
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(10 * time.Second)
	for {
		var result json.RawMessage
		err = statusClient.Call(context.Background(), payload, &result)
		if err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("durable receiver result did not reconcile after restart")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if service != "control" {
		if err = worker("/internal/work/"+job.ID+"/step", lease, nil); err != nil {
			t.Fatal("real worker could not acknowledge protected outcome")
		}
	}
	var current contracts.ReviewJob
	alice.workflow(map[string]any{"operation": "job", "id": job.ID}, 200, &current)
	if current.State != "completed" || (kind == "model" && current.Answer == "") || (kind == "export" && current.ExportID == "") {
		t.Fatal("packaged lifecycle lacks the actual completed protected result")
	}
	receiptPath := filepath.Join(r.state, kind+"-receipts", operation+".state")
	before, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal("real receiver receipt unavailable")
	}
	var saved struct {
		State  string          `json:"state"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(before, &saved) != nil || saved.State != "completed" || len(saved.Result) == 0 {
		t.Fatal("real durable receipt is not complete")
	}
	if kind == "export" {
		var artifact struct {
			ArtifactID    string `json:"artifact_id"`
			Content       string `json:"content"`
			ContentDigest string `json:"content_digest"`
		}
		if json.Unmarshal(saved.Result, &artifact) != nil || artifact.ArtifactID != operation || artifact.Content != expectedExport || artifact.ContentDigest != broker.Hash([]byte(expectedExport)) {
			t.Fatal("real export artifact differs from independently approved bytes")
		}
	} else {
		var generated contracts.GenerationResult
		if json.Unmarshal(saved.Result, &generated) != nil || generated.Text != current.Answer || generated.Provider != current.Provider {
			t.Fatal("protected review differs from the actual model receipt")
		}
	}
	var repeated json.RawMessage
	if err = receiver.Call(context.Background(), payload, &repeated); err != nil {
		t.Fatal("completed operation replay could not return its existing result")
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("replay rewrote the receiver receipt")
	}
	var opState string
	var resultPresent bool
	var grants, completions int
	if err = db.QueryRow(context.Background(), "SELECT status,result IS NOT NULL,(SELECT count(*) FROM audit_events WHERE job_id=$2 AND action=$3),(SELECT count(*) FROM audit_events WHERE job_id=$2 AND action=$4) FROM execution_operations WHERE id=$1", operation, job.ID, kind+".authorized", kind+".completed").Scan(&opState, &resultPresent, &grants, &completions); err != nil || opState != "completed" || !resultPresent || grants != 1 || completions != 1 {
		t.Fatal("restart/replay changed protected state or repeated authorization/completion")
	}
	public, err := os.ReadFile(filepath.Join(r.state, "evidence-public"))
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("pinned evidence verification key unavailable")
	}
	entries, err := evidence.Verify(filepath.Join(r.state, "evidence"), ed25519.PublicKey(public), nil)
	if err != nil {
		t.Fatal("signed evidence chain changed across packaged shutdown")
	}
	signedGrants, signedCompletions := 0, 0
	for _, entry := range entries {
		if entry.Event.JobID != job.ID || entry.Event.Producer != "kernel" {
			continue
		}
		if entry.Event.Action == kind+".authorized" {
			signedGrants++
		}
		if entry.Event.Action == kind+".completed" {
			signedCompletions++
		}
	}
	if signedGrants != 1 || signedCompletions != 1 {
		t.Fatal("packaged receiver result lacks its single signed Guard authorization/completion")
	}
	r.record(service, map[string]any{"status": "passed", "scope": r.scope, "service": service, "container_id": exited.ID, "image_id": exited.Image, "job_id": job.ID, "operation_id": operation, "real_guard_dependency_observed": true, "new_admission_closed": closed, "drain_milliseconds": drain.Milliseconds(), "drain_budget_seconds": int(limit.Seconds()), "exit_code": exited.State.ExitCode, "receipt_sha256": broker.Hash(after), "authorization_count": grants, "completion_count": completions, "signed_authorization_count": signedGrants, "signed_completion_count": signedCompletions, "result_state": opState})
}
