package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/trust"
)

// QualificationOutboxAppender connects the outbox to the existing evidence
// service using its synthetic qualification mTLS identity and kernel
// capability. It does not establish production custody or rollback safety.
type QualificationOutboxAppender struct {
	url    string
	key    []byte
	client *http.Client
}

var _ OutboxAppender = (*QualificationOutboxAppender)(nil)

func NewQualificationOutboxAppender(baseURL string, key []byte, cfg *trust.Config) (*QualificationOutboxAppender, error) {
	if len(key) != 32 || cfg == nil || cfg.Profile != trust.Qualification || cfg.Role != trust.Guard {
		return nil, ErrOutboxUnknown
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrOutboxUnknown
	}
	u.Path = "/append/kernel"
	private := *cfg
	client, err := private.HTTPClient(trust.Evidence, 5*time.Second)
	if err != nil {
		return nil, ErrOutboxUnknown
	}
	return &QualificationOutboxAppender{url: u.String(), key: append([]byte(nil), key...), client: client}, nil
}

// AppendExact sends the same canonical bytes as the body-bound capability.
// Any failed or ambiguous response remains unknown; the caller must not infer
// that the journal did not append. The outbox separately verifies the proof.
func (a *QualificationOutboxAppender) AppendExact(ctx context.Context, raw []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || len(a.key) != 32 || a.client == nil || len(raw) == 0 || len(raw) > 128*1024 {
		return nil, ErrOutboxUnknown
	}
	body := append([]byte(nil), raw...)
	var event Event
	if json.Unmarshal(body, &event) != nil || event.Producer != "kernel" || event.Action != "model.prepared" {
		return nil, ErrOutboxUnknown
	}
	canonical, err := json.Marshal(normalized(event))
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrOutboxUnknown
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return nil, ErrOutboxUnknown
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Capability "+broker.Token(a.key, "evidence.append.kernel", body))
	response, err := a.client.Do(req)
	if err != nil {
		return nil, ErrOutboxUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrOutboxUnknown
	}
	proof, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(proof) == 0 || len(proof) > 16*1024 || ctx.Err() != nil {
		return nil, ErrOutboxUnknown
	}
	if _, err = uniqueObject(proof); err != nil {
		return nil, ErrOutboxUnknown
	}
	return proof, nil
}
