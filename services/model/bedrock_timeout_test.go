package model

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

func TestBedrockPreservesSDKTimeoutAndRejectsUnsafeClients(t *testing.T) {
	sdk := awshttp.NewBuildableClient().WithTimeout(2 * time.Second).WithReadTimeout(100 * time.Millisecond)
	transport, timeout, err := configuredBedrockTransport(sdk, "example.invalid")
	if err != nil || timeout != 2*time.Second || transport.DialContext == nil {
		t.Fatalf("configured timeouts not preserved: %v", err)
	}
	if bedrockHTTPClient("example.invalid", transport, timeout).Timeout != 2*time.Second {
		t.Fatal("SDK client timeout was lost")
	}
	if _, _, err := configuredBedrockTransport(&http.Client{}, "example.invalid"); err == nil {
		t.Fatal("unsupported client accepted")
	}
	// This fixture never connects; it proves insecure TLS settings are rejected.
	insecure := sdk.WithTransportOptions(func(tr *http.Transport) { tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} })
	if _, _, err := configuredBedrockTransport(insecure, "example.invalid"); err == nil {
		t.Fatal("insecure TLS client accepted")
	}
}

func TestBedrockTLSNameMustMatchApprovedHost(t *testing.T) {
	const host = "bedrock-runtime.us-gov-west-1.amazonaws.com"
	_, root, _ := fixtureCertificate(t, host)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, tc := range []struct {
		name    string
		allowed bool
	}{
		{"", true},
		{host, true},
		{"other.example.invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sdk := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
				tr.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: tc.name, MinVersion: tls.VersionTLS12}
			})
			transport, _, err := configuredBedrockTransport(sdk, host)
			if !tc.allowed {
				if err == nil {
					t.Fatal("alternate TLS identity accepted")
				}
				return
			}
			if err != nil || transport.TLSClientConfig.RootCAs != roots || transport.TLSClientConfig.ServerName != tc.name {
				t.Fatalf("valid TLS configuration was not retained: %v", err)
			}
		})
	}
	if _, _, err := configuredBedrockTransport(awshttp.NewBuildableClient(), ""); err == nil {
		t.Fatal("empty approved TLS identity accepted")
	}
}

func TestBedrockPreservesSDKConfiguredTransportDialer(t *testing.T) {
	want := errors.New("fixture custom dialer reached")
	calls := 0
	sdk := awshttp.NewBuildableClient().WithReadTimeout(100 * time.Millisecond).WithTransportOptions(func(tr *http.Transport) {
		tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, want
		}
	})
	transport, _, err := configuredBedrockTransport(sdk, "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.DialContext(context.Background(), "tcp", "fixture.invalid:443"); !errors.Is(err, want) || calls != 1 {
		t.Fatalf("configured transport dialer was not preserved: calls=%d err=%v", calls, err)
	}
}

func TestBedrockReadTimeoutRejectsStalledTLSResponse(t *testing.T) {
	const host = "bedrock-runtime.us-gov-west-1.amazonaws.com"
	certificate, root, _ := fixtureCertificate(t, host)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() {
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if server.Handshake() != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_, _ = io.Copy(io.Discard, server) // Read until closed; send no response.
	}()
	dial := func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	sdk := awshttp.NewBuildableClient().WithReadTimeout(150 * time.Millisecond)
	transport := &http.Transport{
		DialContext:     bedrockConfiguredDial(sdk, dial),
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := bedrockHTTPClient(host, transport, 3*time.Second)
	request, err := http.NewRequest(http.MethodPost, "https://"+host+"/model/test/converse", strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	var timeout *awshttp.ResponseTimeoutError
	if !errors.As(err, &timeout) || timeout.TimeoutDur != 150*time.Millisecond {
		t.Fatalf("stalled response did not hit configured read timeout: %v", err)
	}
}
