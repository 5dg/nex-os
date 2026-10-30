// Downstream Nex OS diagnostic regression; not part of an upstream release.
package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

type nexAlgorithmKeys struct{ private, public, wrong string }

func nexPEMKeys(t *testing.T, private any, public any, wrong any) nexAlgorithmKeys {
	t.Helper()
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKIXPublicKey(wrong)
	if err != nil {
		t.Fatal(err)
	}
	return nexAlgorithmKeys{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrongDER}))}
}

func TestNexBundleAlgorithmRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaWrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeys := nexPEMKeys(t, rsaKey, &rsaKey.PublicKey, &rsaWrong.PublicKey)
	curves := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}
	ecdsaKeys := make(map[string]nexAlgorithmKeys)
	for alg, curve := range curves {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrong, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecdsaKeys[alg] = nexPEMKeys(t, key, &key.PublicKey, &wrong.PublicKey)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edWrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKeys := nexPEMKeys(t, edPrivate, edPublic, edWrong)
	hmacKeys := nexAlgorithmKeys{strings.Repeat("s", 64), strings.Repeat("s", 64), strings.Repeat("w", 64)}
	algs := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"}
	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			keys := rsaKeys
			switch {
			case strings.HasPrefix(alg, "HS"):
				keys = hmacKeys
			case strings.HasPrefix(alg, "ES"):
				keys = ecdsaKeys[alg]
			case strings.HasPrefix(alg, "Ed"):
				keys = edKeys
			}
			files := []FileInfo{NewFile("policy.rego", strings.Repeat("a", 64), "sha256")}
			token, err := GenerateSignedToken(files, NewSigningConfig(keys.private, alg, ""), "foo")
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			segments := strings.Split(token, ".")
			if len(segments) != 3 {
				t.Fatal("unexpected compact token")
			}
			sig, err := base64.RawURLEncoding.DecodeString(segments[2])
			if err != nil || len(sig) == 0 {
				t.Fatal("invalid signature")
			}
			sig[0] ^= 1
			tampered := segments[0] + "." + segments[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
			hdr, err := base64.RawURLEncoding.DecodeString(segments[0])
			if err != nil {
				t.Fatal(err)
			}
			var header map[string]any
			if err := json.Unmarshal(hdr, &header); err != nil {
				t.Fatal(err)
			}
			header["alg"] = "none"
			hdr, err = json.Marshal(header)
			if err != nil {
				t.Fatal(err)
			}
			mismatch := base64.RawURLEncoding.EncodeToString(hdr) + "." + segments[1] + "." + segments[2]
			for _, configuredID := range []string{"", "foo"} {
				t.Run("configured="+configuredID, func(t *testing.T) {
					cfg := NewVerificationConfig(map[string]*KeyConfig{"foo": {Key: keys.public, Algorithm: alg}}, configuredID, "", nil)
					got, err := VerifyBundleSignature(SignaturesConfig{Signatures: []string{token}}, cfg)
					if err != nil || got["policy.rego"] != files[0] {
						t.Fatalf("valid round trip: %v", err)
					}
					for name, bad := range map[string]string{"tampered": tampered, "algorithm_mismatch": mismatch} {
						t.Run(name, func(t *testing.T) {
							if result, err := VerifyBundleSignature(SignaturesConfig{Signatures: []string{bad}}, cfg); err == nil || len(result) != 0 {
								t.Fatalf("invalid signed bundle accepted: %v", err)
							}
						})
					}
					wrong := NewVerificationConfig(map[string]*KeyConfig{"foo": {Key: keys.wrong, Algorithm: alg}}, configuredID, "", nil)
					if result, err := VerifyBundleSignature(SignaturesConfig{Signatures: []string{token}}, wrong); err == nil || len(result) != 0 {
						t.Fatalf("wrong verification key accepted: %v", err)
					}
				})
			}
		})
	}
}
