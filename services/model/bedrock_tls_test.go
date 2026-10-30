package model

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

func fixtureCertificate(t *testing.T, host string) (tls.Certificate, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBedrockPreservesConfiguredCATrust(t *testing.T) {
	const host = "bedrock-runtime.us-gov-west-1.amazonaws.com"
	cert, _, bundle := fixtureCertificate(t, host)
	caFile := filepath.Join(t.TempDir(), "fixture-public-ca.pem")
	if err := os.WriteFile(caFile, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", caFile)
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "")
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	adapter, err := NewBedrock(context.Background(), "us-gov-west-1", "arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/fixture-model-v1:0", "https://"+host)
	if err != nil {
		t.Fatal(err)
	}
	opts := adapter.route.client.(*bedrockruntime.Client).Options()
	httpClient, ok := opts.HTTPClient.(*http.Client)
	if !ok {
		t.Fatal("missing guarded HTTP client")
	}
	guard, ok := httpClient.Transport.(bedrockBoundTransport)
	if !ok {
		t.Fatal("missing destination guard")
	}
	transport, ok := guard.next.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("configured CA trust was lost or verification disabled")
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	client := tls.Client(clientConn, &tls.Config{RootCAs: transport.TLSClientConfig.RootCAs, ServerName: host, MinVersion: tls.VersionTLS12})
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("configured CA handshake failed: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("fixture server handshake failed: %v", err)
	}
	_, foreign, _ := fixtureCertificate(t, host)
	if _, err := foreign.Verify(x509.VerifyOptions{Roots: transport.TLSClientConfig.RootCAs, DNSName: host}); err == nil {
		t.Fatal("untrusted CA accepted")
	}
}
