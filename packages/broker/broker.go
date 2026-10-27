// Package broker implements request-bound, short-lived service capabilities.
// Keys are provisioned separately per execution trust boundary, never to workers.
package broker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func Key(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil || len(b) != 32 {
		return nil, errors.New("32-byte service key required")
	}
	return b, nil
}

type claims struct {
	Audience string `json:"aud"`
	Digest   string `json:"digest"`
	Expires  int64  `json:"exp"`
}

func Token(key []byte, audience string, body []byte) string {
	b, _ := json.Marshal(claims{audience, Hash(body), time.Now().Add(15 * time.Second).Unix()})
	p := base64.RawURLEncoding.EncodeToString(b)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func Verify(key []byte, audience, token string, body []byte) error {
	p, s, ok := bytes.Cut([]byte(token), []byte("."))
	if !ok {
		return errors.New("invalid capability")
	}
	sig, e := base64.RawURLEncoding.DecodeString(string(s))
	if e != nil {
		return e
	}
	h := hmac.New(sha256.New, key)
	h.Write(p)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return errors.New("invalid capability signature")
	}
	b, e := base64.RawURLEncoding.DecodeString(string(p))
	if e != nil {
		return e
	}
	var c claims
	if json.Unmarshal(b, &c) != nil || c.Audience != audience || c.Digest != Hash(body) || c.Expires <= time.Now().Unix() || c.Expires > time.Now().Add(16*time.Second).Unix() {
		return errors.New("capability scope or expiry mismatch")
	}
	return nil
}

type Client struct {
	URL, Audience string
	Key           []byte
	HTTP          *http.Client
}

func NewClient(url, audience string, key []byte) *Client {
	return &Client{url, audience, key, &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *Client) Call(ctx context.Context, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Capability "+Token(c.Key, c.Audience, b))
	response, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		body, e := io.ReadAll(io.LimitReader(response.Body, 1025))
		if e != nil || len(body) > 1024 {
			return ErrUnknown
		}
		var outcome OperationError
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&outcome) == nil && decoder.Decode(&struct{}{}) == io.EOF &&
			(outcome.State == "not_started" || outcome.State == "in_progress" || outcome.State == "unknown") {
			return &outcome
		}
		return ErrUnknown
	}
	// A bounded 12 KiB semantic result may require six JSON bytes per input
	// byte. Include protocol overhead without admitting unbounded responses.
	body, e := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if e != nil || len(body) > 128*1024 {
		return ErrUnknown
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if e = decoder.Decode(out); e != nil {
		return ErrUnknown
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrUnknown
	}
	return nil
}

// Read enforces the executor capability request limit. Services with a larger
// bounded internal contract may use ReadLimit without relaxing other receivers.
func Read(w http.ResponseWriter, r *http.Request, key []byte, audience string, v any) bool {
	return ReadLimit(w, r, key, audience, v, 16384)
}
func ReadLimit(w http.ResponseWriter, r *http.Request, key []byte, audience string, v any, limit int64) bool {
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "invalid request", 400)
		return false
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if e != nil {
		http.Error(w, "invalid request", 400)
		return false
	}
	token := r.Header.Get("Authorization")
	if len(token) < 11 || token[:11] != "Capability " || Verify(key, audience, token[11:], b) != nil {
		http.Error(w, "unauthorized", 401)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}

// ReceiptStore records a durable boundary before authorization/effects. A live
// lock distinguishes a concurrent call from a receipt left by a crashed process.
// Legacy .pending receipts remain unknown and are never removed automatically.
type ReceiptStore struct {
	Directory string
	custody   *Custody
}

var ErrUnknown = errors.New("operation outcome unknown; reconcile before retrying")
var ErrInProgress = errors.New("operation in progress")
var ErrNotStarted = errors.New("operation did not start")

type receipt struct {
	Version int             `json:"version"`
	Digest  string          `json:"request_digest"`
	State   string          `json:"state"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func validID(id string) bool {
	if len(id) < 8 || len(id) > 100 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func syncDirectory(path string) error {
	dir, e := os.Open(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// Persist newly created receipt-directory entries before admitting effects.
// Syncing the receipt directory alone does not persist its name in its parent.
func ensureDirectory(path string) error {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(absolute, 0700); e != nil {
		return e
	}
	// Include existing ancestors: a previous failed mkdir/sync attempt may have
	// left a visible but not yet durable directory. A retry must not skip it.
	for current := absolute; ; current = filepath.Dir(current) {
		if e = syncDirectory(current); e != nil {
			return e
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}
func (s ReceiptStore) publish(id string, record receipt) error {
	b, e := json.Marshal(record)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.Directory, ".receipt-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, filepath.Join(s.Directory, id+".state")); e != nil {
		return e
	}
	return syncDirectory(s.Directory)
}
func (s ReceiptStore) lookup(id, digest string) (receipt, error) {
	path := filepath.Join(s.Directory, id)
	for _, suffix := range []string{".state", ".done"} {
		b, e := os.ReadFile(path + suffix)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return receipt{}, e
		}
		var old receipt
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&old) != nil || decoder.Decode(&struct{}{}) != io.EOF || old.Digest != digest {
			return receipt{}, ErrUnknown
		}
		if suffix == ".done" {
			// The legacy record contains only digest/result. Never interpret a
			// versioned or stateful object in that legacy format.
			if old.Version != 0 || old.State != "" {
				return receipt{}, ErrUnknown
			}
			old.State = "completed"
		} else {
			if old.Version != 2 {
				return receipt{}, ErrUnknown
			}
			switch old.State {
			case "prepared", "started", "not_started":
				if len(old.Result) != 0 {
					return receipt{}, ErrUnknown
				}
			case "completed":
			default:
				return receipt{}, ErrUnknown
			}
		}
		if old.State == "completed" && (!json.Valid(old.Result) || bytes.Equal(bytes.TrimSpace(old.Result), []byte("null"))) {
			return receipt{}, ErrUnknown
		}
		return old, nil
	}
	if _, e := os.Stat(path + ".pending"); e == nil {
		return receipt{}, ErrUnknown
	} else if !errors.Is(e, os.ErrNotExist) {
		return receipt{}, e
	}
	return receipt{}, nil
}
func (s ReceiptStore) locked(id string, fn func() (json.RawMessage, error)) (json.RawMessage, error) {
	if !validID(id) {
		return nil, ErrNotStarted
	}
	if s.custody != nil && s.custody.Check() != nil {
		return nil, ErrUnknown
	}
	if e := ensureDirectory(s.Directory); e != nil {
		// The path may be an inaccessible/lost prior receipt volume. Storage
		// failures do not establish that this operation has never had an effect.
		return nil, ErrUnknown
	}
	lock, e := os.OpenFile(filepath.Join(s.Directory, id+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil, ErrInProgress
		}
		return nil, e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// Inspect returns only a durable completed result. It never authorizes or runs an
// effect; callers may use it to reconcile an interrupted completion report.
func (s ReceiptStore) Inspect(id, digest string) (json.RawMessage, error) {
	// Missing storage is not proof that this operation never executed. Unlike
	// execution, inspection does not create a replacement receipt directory.
	if _, e := os.Stat(s.Directory); e != nil {
		return nil, ErrUnknown
	}
	return s.locked(id, func() (json.RawMessage, error) {
		old, e := s.lookup(id, digest)
		if e != nil {
			return nil, e
		}
		switch old.State {
		case "completed":
			return old.Result, nil
		case "not_started":
			return nil, ErrNotStarted
		default:
			return nil, ErrUnknown
		}
	})
}
func (s ReceiptStore) Do(id string, request any, fn func() (any, error)) (json.RawMessage, error) {
	b, e := json.Marshal(request)
	if e != nil {
		return nil, ErrNotStarted
	}
	return s.DoAuthorized(id, Hash(b), nil, fn)
}

// DoAuthorized requires positive authorization before effects. ErrNotStarted
// from authorize must attest an authenticated pending/no-effect operation state;
// ordinary errors may hide a prior start and therefore remain unknown.
func (s ReceiptStore) DoAuthorized(id, digest string, authorize func() error, fn func() (any, error)) (json.RawMessage, error) {
	return s.locked(id, func() (json.RawMessage, error) {
		old, e := s.lookup(id, digest)
		if e != nil {
			return nil, e
		}
		switch old.State {
		case "completed":
			return old.Result, nil
		case "", "not_started":
		default:
			return nil, ErrUnknown
		}
		state := receipt{Version: 2, Digest: digest, State: "prepared"}
		if e = s.publish(id, state); e != nil {
			return nil, ErrNotStarted
		}
		if authorize != nil {
			if e = authorize(); e != nil {
				// An unavailable authorization response may have followed a
				// committed start, or a lost receipt volume may hide an earlier
				// effect. Only explicit pending-state proof permits not_started.
				if !errors.Is(e, ErrNotStarted) {
					return nil, ErrUnknown
				}
				state.State = "not_started"
				if s.publish(id, state) != nil {
					return nil, ErrUnknown
				}
				return nil, ErrNotStarted
			}
		}

		state.State = "started"
		if e = s.publish(id, state); e != nil {
			return nil, ErrUnknown
		}
		if s.custody != nil && s.custody.Check() != nil {
			return nil, ErrUnknown
		}
		result, e := fn()
		if e != nil {
			return nil, ErrUnknown
		}
		out, e := json.Marshal(result)
		if e != nil || bytes.Equal(bytes.TrimSpace(out), []byte("null")) {
			return nil, ErrUnknown
		}
		state.State = "completed"
		state.Result = out
		if e = s.publish(id, state); e != nil {
			return nil, ErrUnknown
		}
		return out, nil
	})
}

// OperationError is a bounded, typed response from an authenticated executor.
// Transport failures and malformed responses remain unknown.
type OperationError struct {
	State string `json:"state"`
}

func (e *OperationError) Error() string { return "executor outcome: " + e.State }
func (e *OperationError) Is(target error) bool {
	return target == ErrNotStarted && e.State == "not_started" || target == ErrInProgress && e.State == "in_progress" || target == ErrUnknown && e.State == "unknown"
}
func WriteError(w http.ResponseWriter, e error) {
	state := "unknown"
	if errors.Is(e, ErrNotStarted) {
		state = "not_started"
	}
	if errors.Is(e, ErrInProgress) {
		state = "in_progress"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(OperationError{State: state})
}
