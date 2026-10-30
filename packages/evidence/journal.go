// Package evidence provides a local tamper-evident journal, not a claim of
// independent production custody. Pin checkpoint heads outside this host to
// detect rollback/truncation by an administrator who controls local storage.
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/5dg/nex-os/packages/broker"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ResourceID   string          `json:"resource_id"`
	DelegationID string          `json:"delegation_id"`
	Timestamp    int64           `json:"timestamp_us"`
	Producer     string          `json:"producer"`
	ID           string          `json:"event_id"`
	TenantID     string          `json:"tenant_id"`
	ActorID      string          `json:"actor_id"`
	JobID        string          `json:"job_id,omitempty"`
	Action       string          `json:"action"`
	Detail       json.RawMessage `json:"detail"`
}
type Proof struct {
	Producer  string `json:"producer"`
	Previous  string `json:"previous"`
	Sequence  int    `json:"sequence"`
	Head      string `json:"head"`
	Signature string `json:"signature"`
	EventID   string `json:"event_id"`
}
type Entry struct {
	Event    Event  `json:"event"`
	Previous string `json:"previous"`
	Proof    Proof  `json:"proof"`
}
type Journal struct {
	Directory string
	Private   ed25519.PrivateKey
	mu        sync.Mutex
	custody   *broker.Custody
}

func message(p Proof) []byte {
	return []byte(fmt.Sprintf("nex-evidence-v1:%d:%s:%s:%s", p.Sequence, p.Head, p.EventID, p.Producer))
}
func VerifyProof(public ed25519.PublicKey, p Proof) bool {
	s, e := base64.RawURLEncoding.DecodeString(p.Signature)
	return e == nil && len(public) == ed25519.PublicKeySize && ed25519.Verify(public, message(p), s)
}
func normalized(event Event) Event {
	var detail any
	decoder := json.NewDecoder(bytes.NewReader(event.Detail))
	decoder.UseNumber()
	if decoder.Decode(&detail) == nil {
		event.Detail, _ = json.Marshal(detail)
	}
	return event
}
func VerifyEvent(public ed25519.PublicKey, p Proof, event Event) bool {
	return p.EventID == event.ID && p.Producer == event.Producer && p.Head == hashEvent(event, p.Previous) && VerifyProof(public, p)
}
func hashEvent(event Event, previous string) string {
	event = normalized(event)
	b, _ := json.Marshal(struct {
		Event    Event  `json:"event"`
		Previous string `json:"previous"`
	}{event, previous})
	return broker.Hash(b)
}
func Verify(directory string, public ed25519.PublicKey, expected *Proof) ([]Entry, error) {
	return VerifyContext(context.Background(), directory, public, expected)
}
func VerifyContext(ctx context.Context, directory string, public ed25519.PublicKey, expected *Proof) ([]Entry, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	files, e := filepath.Glob(filepath.Join(directory, "*.json"))
	if e != nil {
		return nil, e
	}
	entries := []Entry{}
	previous := ""
	for i, path := range files {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if filepath.Base(path) != fmt.Sprintf("%012d.json", i+1) {
			return nil, errors.New("journal sequence gap")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var entry Entry
		if json.Unmarshal(b, &entry) != nil || entry.Proof.Sequence != i+1 || entry.Previous != previous || entry.Proof.Head != hashEvent(entry.Event, previous) || !VerifyEvent(public, entry.Proof, entry.Event) || entry.Proof.Previous != previous {
			return nil, errors.New("journal integrity failure")
		}
		entries = append(entries, entry)
		previous = entry.Proof.Head
	}
	if expected != nil && (expected.Sequence != len(entries) || expected.Head != previous || !VerifyProof(public, *expected)) {
		return nil, errors.New("pinned checkpoint mismatch")
	}
	return entries, nil
}

// AnchoredVerificationLimits bound directory entries inspected (including
// non-journal files), individual journal files, and total journal bytes read.
// Deployment callers should choose lower limits appropriate for their storage.
type AnchoredVerificationLimits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
}

// VerifyAnchoredExtensionContext verifies a complete journal and requires an
// independently retained, signed checkpoint to occur at its original sequence.
// Entries after the checkpoint may have been lost or replaced since that
// checkpoint was retained: callers must advance and protect their anchor using
// an independently trustworthy custody protocol before relying on those
// entries. This function neither provisions that custody nor fences writers.
// The directory must not be concurrently modified by an untrusted writer. The
// bounds constrain normal file reads, not hostile replacement with device files.
func VerifyAnchoredExtensionContext(ctx context.Context, directory string, public ed25519.PublicKey, anchor Proof, limits AnchoredVerificationLimits) ([]Entry, error) {
	if ctx == nil || anchor.Sequence <= 0 || !VerifyProof(public, anchor) ||
		limits.MaxEntries < 1 || limits.MaxEntries > 100000 ||
		limits.MaxEntryBytes < 1 || limits.MaxEntryBytes > 1024*1024 ||
		limits.MaxTotalBytes < 1 || limits.MaxTotalBytes > 64*1024*1024 {
		return nil, errors.New("invalid pinned checkpoint")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names := make([]string, 0)
	seen := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := dir.ReadDir(128)
		seen += len(batch)
		if seen > limits.MaxEntries {
			return nil, errors.New("journal directory entry limit exceeded")
		}
		for _, file := range batch {
			if strings.HasSuffix(file.Name(), ".json") {
				if !file.Type().IsRegular() {
					return nil, errors.New("journal entry is not a regular file")
				}
				names = append(names, file.Name())
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	sort.Strings(names)
	entries := make([]Entry, 0, len(names))
	previous := ""
	var total int64
	for i, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if name != fmt.Sprintf("%012d.json", i+1) {
			return nil, errors.New("journal sequence gap")
		}
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		remaining := limits.MaxTotalBytes - total
		readLimit := min(limits.MaxEntryBytes, remaining)
		data, readErr := io.ReadAll(io.LimitReader(file, readLimit+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		total += int64(len(data))
		if int64(len(data)) > limits.MaxEntryBytes || total > limits.MaxTotalBytes {
			return nil, errors.New("journal byte limit exceeded")
		}
		var entry Entry
		if json.Unmarshal(data, &entry) != nil || entry.Proof.Sequence != i+1 || entry.Previous != previous || entry.Proof.Head != hashEvent(entry.Event, previous) || !VerifyEvent(public, entry.Proof, entry.Event) || entry.Proof.Previous != previous {
			return nil, errors.New("journal integrity failure")
		}
		entries = append(entries, entry)
		previous = entry.Proof.Head
	}
	if anchor.Sequence > len(entries) || entries[anchor.Sequence-1].Proof != anchor {
		return nil, errors.New("pinned checkpoint mismatch")
	}
	return entries, nil
}

func (j *Journal) Append(event Event) (Proof, error) {
	return j.AppendContext(context.Background(), event, nil)
}
func (j *Journal) AppendContext(ctx context.Context, event Event, check func() error) (Proof, error) {
	return j.appendContext(ctx, event, check, syncJournalDirectory)
}

// Sync the directory even on an identical retry: a previous append may have
// linked the entry but failed before the directory entry became durable.
// This is local crash durability, not an independent nonrollback guarantee.
func syncJournalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (j *Journal) appendContext(ctx context.Context, event Event, check func() error, syncDirectory func(string) error) (Proof, error) {
	if e := j.lockContext(ctx); e != nil {
		return Proof{}, e
	}
	defer j.mu.Unlock()
	if len(j.Private) != ed25519.PrivateKeySize || event.ID == "" || event.TenantID == "" || event.Action == "" {
		return Proof{}, errors.New("invalid evidence configuration/event")
	}
	if e := os.MkdirAll(j.Directory, 0700); e != nil {
		return Proof{}, e
	}
	all, e := VerifyContext(ctx, j.Directory, j.Private.Public().(ed25519.PublicKey), nil)
	if e != nil {
		return Proof{}, e
	}
	if j.custody != nil {
		if e := j.custody.Check(); e != nil {
			return Proof{}, e
		}
	}
	if e := ctx.Err(); e != nil {
		return Proof{}, e
	}
	if check != nil {
		if e := check(); e != nil {
			return Proof{}, e
		}
	}
	event = normalized(event)
	canonical, _ := json.Marshal(event)
	for _, entry := range all {
		if e := ctx.Err(); e != nil {
			return Proof{}, e
		}
		if entry.Event.ID == event.ID {
			old, _ := json.Marshal(entry.Event)
			if string(old) != string(canonical) {
				return Proof{}, errors.New("event ID/content mismatch")
			}
			if e := syncDirectory(j.Directory); e != nil {
				return Proof{}, e
			}
			if e := ctx.Err(); e != nil {
				return Proof{}, e
			}
			return entry.Proof, nil
		}
	}
	previous := ""
	if len(all) > 0 {
		previous = all[len(all)-1].Proof.Head
	}
	p := Proof{Sequence: len(all) + 1, Head: hashEvent(event, previous), EventID: event.ID, Producer: event.Producer, Previous: previous}
	p.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(j.Private, message(p)))
	b, _ := json.Marshal(Entry{Event: event, Previous: previous, Proof: p})
	temporary, e := os.CreateTemp(j.Directory, ".entry-")
	if e != nil {
		return Proof{}, e
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, e = temporary.Write(b); e == nil {
		e = temporary.Sync()
	}
	if closeErr := temporary.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return Proof{}, e
	}
	if e = os.Link(name, filepath.Join(j.Directory, fmt.Sprintf("%012d.json", p.Sequence))); e != nil {
		return Proof{}, e
	}
	if e = syncDirectory(j.Directory); e != nil {
		return Proof{}, e
	}
	if e = ctx.Err(); e != nil {
		return Proof{}, e
	}
	return p, nil
}

// Journal contention must honor the caller's bounded qualification request.
func (j *Journal) lockContext(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if j.mu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if j.mu.TryLock() {
				if e := ctx.Err(); e != nil {
					j.mu.Unlock()
					return e
				}
				return nil
			}
		}
	}
}
