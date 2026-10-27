package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/5dg/nex-os/packages/broker"
)

const EvidenceServiceIdentity = "spiffe://nex.local/service/evidence"

type ChallengeRequest struct {
	Nonce string `json:"nonce"`
}
type ChallengeProof struct {
	Producer       string `json:"producer"`
	Nonce          string `json:"nonce"`
	KeyFingerprint string `json:"key_fingerprint"`
	Signature      string `json:"signature"`
}

func validChallenge(producer, nonce string) bool {
	if producer != "control" && producer != "kernel" {
		return false
	}
	b, e := hex.DecodeString(nonce)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == nonce
}
func challengeFingerprint(public ed25519.PublicKey) string {
	s := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(s[:])
}
func challengeMessage(producer, nonce, fingerprint string) []byte {
	b := []byte("nex.evidence.readiness.v1\x00")
	for _, field := range []string{producer, nonce, fingerprint, EvidenceServiceIdentity} {
		b = binary.BigEndian.AppendUint64(b, uint64(len([]byte(field))))
		b = append(b, []byte(field)...)
	}
	return b
}
func VerifyChallenge(public ed25519.PublicKey, p ChallengeProof, producer, nonce string) bool {
	if len(public) != ed25519.PublicKeySize || !validChallenge(producer, nonce) || p.Producer != producer || p.Nonce != nonce || p.KeyFingerprint != challengeFingerprint(public) {
		return false
	}
	sig, e := base64.RawURLEncoding.DecodeString(p.Signature)
	return e == nil && ed25519.Verify(public, challengeMessage(producer, nonce, p.KeyFingerprint), sig)
}

// Challenge authenticates the producer credential and pinned signing key without
// appending an event or trusting a health response as proof of that key match.
func Challenge(ctx context.Context, client *broker.Client, public ed25519.PublicKey, producer string) error {
	if client == nil || len(public) != 32 || (producer != "control" && producer != "kernel") {
		return errors.New("signing readiness configuration unavailable")
	}
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return errors.New("signing readiness nonce unavailable")
	}
	req := ChallengeRequest{Nonce: hex.EncodeToString(nonce)}
	u, e := url.Parse(client.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid signing endpoint")
	}
	u.Path = "/challenge/" + producer
	u.RawPath = ""
	scoped := *client
	scoped.URL = u.String()
	scoped.Audience = "evidence.challenge." + producer
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var proof ChallengeProof
	if e = scoped.Call(ctx, req, &proof); e != nil {
		return errors.New("required signing challenge unavailable")
	}
	if !VerifyChallenge(public, proof, producer, req.Nonce) {
		return errors.New("required signing identity mismatch")
	}
	return nil
}

// OpenJournal establishes the one local writer before accepting any traffic.
// It does not implement distributed ownership or production key custody.
func OpenJournal(directory string, private ed25519.PrivateKey) (*Journal, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key required")
	}
	custody, e := broker.OpenCustody(directory, "evidence")
	if e != nil {
		return nil, e
	}
	j := &Journal{Directory: custody.Directory, Private: private, custody: custody}
	if e = j.Ready(); e != nil {
		custody.Close()
		return nil, e
	}
	return j, nil
}
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	return j.custody.Close()
}
func (j *Journal) Ready() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := j.lockContext(ctx); e != nil {
		return e
	}
	defer j.mu.Unlock()
	return j.readyLocked(ctx)
}
func (j *Journal) readyLocked(ctx context.Context) error {
	if len(j.Private) != ed25519.PrivateKeySize || j.custody == nil {
		return errors.New("single writer custody not configured")
	}
	if e := j.custody.Check(); e != nil {
		return e
	}
	if _, e := VerifyContext(ctx, j.Directory, j.Private.Public().(ed25519.PublicKey), nil); e != nil {
		return errors.New("evidence integrity failure")
	}
	f, e := os.CreateTemp(j.Directory, ".readiness-")
	if e != nil {
		return errors.New("evidence storage unavailable")
	}
	path := f.Name()
	defer os.Remove(path)
	e = f.Sync()
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return errors.New("evidence storage unavailable")
	}
	directory, e := os.Open(filepath.Dir(path))
	if e != nil {
		return errors.New("evidence storage unavailable")
	}
	defer directory.Close()
	return directory.Sync()
}
func (j *Journal) ChallengeContext(ctx context.Context, producer, nonce string, check func() error) (ChallengeProof, error) {
	if !validChallenge(producer, nonce) {
		return ChallengeProof{}, errors.New("invalid signing challenge")
	}
	if e := j.lockContext(ctx); e != nil {
		return ChallengeProof{}, e
	}
	defer j.mu.Unlock()
	if e := j.readyLocked(ctx); e != nil {
		return ChallengeProof{}, e
	}
	if e := ctx.Err(); e != nil {
		return ChallengeProof{}, e
	}
	if check != nil {
		if e := check(); e != nil {
			return ChallengeProof{}, e
		}
	}
	p := ChallengeProof{Producer: producer, Nonce: nonce, KeyFingerprint: challengeFingerprint(j.Private.Public().(ed25519.PublicKey))}
	p.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(j.Private, challengeMessage(p.Producer, p.Nonce, p.KeyFingerprint)))
	return p, nil
}
