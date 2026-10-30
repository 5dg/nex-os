package model

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

// pinnedBedrockEndpoint retains the SDK's endpoint and signing properties,
// while rejecting any region, FIPS, dual-stack or endpoint substitution.
type pinnedBedrockEndpoint struct {
	region, endpoint, host string
	fips                   bool
}

func approvedBedrockEndpoint(ctx context.Context, region, endpoint string) (*pinnedBedrockEndpoint, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return nil, errors.New("exact HTTPS Bedrock endpoint required")
	}
	for _, fips := range []bool{false, true} {
		resolved, err := bedrockruntime.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, bedrockruntime.EndpointParameters{
			Region: aws.String(region), UseFIPS: aws.Bool(fips), UseDualStack: aws.Bool(false),
		})
		if err == nil && resolved.URI.String() == endpoint {
			return &pinnedBedrockEndpoint{region: region, endpoint: endpoint, host: u.Host, fips: fips}, nil
		}
	}
	return nil, errors.New("endpoint does not match regional Bedrock service")
}

func (r *pinnedBedrockEndpoint) ResolveEndpoint(ctx context.Context, p bedrockruntime.EndpointParameters) (smithyendpoints.Endpoint, error) {
	if p.Region == nil || *p.Region != r.region || aws.ToBool(p.UseFIPS) != r.fips || aws.ToBool(p.UseDualStack) || p.Endpoint != nil {
		return smithyendpoints.Endpoint{}, errors.New("Bedrock endpoint parameters differ from approved route")
	}
	resolved, err := bedrockruntime.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, p)
	if err != nil || resolved.URI.String() != r.endpoint {
		return smithyendpoints.Endpoint{}, errors.New("Bedrock resolver differs from approved route")
	}
	return resolved, nil
}

type bedrockBoundTransport struct {
	host string
	next http.RoundTripper
}

func (t bedrockBoundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil || (r.Host != "" && r.Host != t.host) {
		return nil, errors.New("Bedrock request destination differs from approved route")
	}
	return t.next.RoundTrip(r)
}

// deadlineConn mirrors the SDK's rolling read-inactivity deadline. Replacing
// the SDK's redirect-following client must not discard its effective timeout.
type bedrockDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *bedrockDeadlineConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, &awshttp.ResponseTimeoutError{TimeoutDur: c.timeout}
	}
	return n, err
}

func bedrockDialWithReadTimeout(dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &bedrockDeadlineConn{Conn: conn, timeout: timeout}, nil
	}
}

func bedrockConfiguredDial(client *awshttp.BuildableClient, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if timeout, set := client.GetReadTimeout(); set && timeout > 0 {
		return bedrockDialWithReadTimeout(dial, timeout)
	}
	return dial
}

func configuredBedrockTransport(client bedrockruntime.HTTPClient) (*http.Transport, time.Duration, error) {
	sdkHTTP, ok := client.(*awshttp.BuildableClient)
	if !ok || sdkHTTP == nil {
		return nil, 0, errors.New("unsupported SDK HTTP client")
	}
	transport := sdkHTTP.GetTransport()
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, 0, errors.New("insecure SDK TLS configuration denied")
	}
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		return nil, 0, errors.New("unsupported SDK TLS dialer")
	}
	dial := transport.DialContext
	if dial == nil {
		dial = sdkHTTP.GetDialer().DialContext
	}
	transport.DialContext = bedrockConfiguredDial(sdkHTTP, dial)
	return transport, sdkHTTP.GetTimeout(), nil
}

func bedrockHTTPClient(host string, transport http.RoundTripper, timeout time.Duration) *http.Client {
	if transport == nil {
		transport = awshttp.NewBuildableClient().GetTransport()
	}
	return &http.Client{
		Transport: bedrockBoundTransport{host: host, next: transport},
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
