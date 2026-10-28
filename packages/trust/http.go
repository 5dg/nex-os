package trust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func (c *Config) CheckURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("valid credential-free service URL required")
	}
	if c == nil || (c.Profile != Development && c.Profile != Qualification) {
		return ErrIdentity
	}
	if c.Profile == Qualification && u.Scheme != "https" {
		return errors.New("qualification requires verified HTTPS")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("unsupported service URL scheme")
	}
	return nil
}

type checkedTransport struct {
	config *Config
	peer   Role
	next   http.RoundTripper
}
type checkedBody struct {
	io.ReadCloser
	config *Config
	peer   Role
	state  *tls.ConnectionState
}

func (b checkedBody) Read(p []byte) (int, error) {
	if e := b.config.CheckPeer(b.state, []Role{b.peer}); e != nil {
		return 0, e
	}
	n, e := b.ReadCloser.Read(p)
	if check := b.config.CheckPeer(b.state, []Role{b.peer}); check != nil {
		return 0, check
	}
	return n, e
}

func (t checkedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if e := t.config.CheckURL(r.URL.String()); e != nil {
		return nil, e
	}
	if e := t.config.CheckOwn(); e != nil {
		return nil, e
	}
	response, e := t.next.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	if t.config.Profile == Qualification {
		if e = t.config.CheckPeer(response.TLS, []Role{t.peer}); e != nil {
			response.Body.Close()
			return nil, e
		}
		response.Body = checkedBody{response.Body, t.config, t.peer, response.TLS}
	}
	return response, nil
}
func (c *Config) HTTPClient(peer Role, timeout time.Duration) (*http.Client, error) {
	if c == nil || !peer.Valid() || timeout <= 0 || timeout > 65*time.Second {
		return nil, ErrIdentity
	}
	if e := c.CheckOwn(); e != nil {
		return nil, e
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 3 * time.Second
	transport.DialContext = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.MaxConnsPerHost = 16
	if c.Profile == Qualification {
		cfg, e := c.clientTLS(peer, "")
		if e != nil {
			return nil, e
		}
		cfg.NextProtos = []string{"http/1.1"}
		transport.TLSClientConfig = cfg
		transport.DisableKeepAlives = true
		transport.ForceAttemptHTTP2 = false
	}
	return &http.Client{Timeout: timeout, Transport: checkedTransport{c, peer, transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func (c *Config) Middleware(allowed []Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := c.CheckPeer(r.TLS, allowed); e != nil {
			http.Error(w, "service identity required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServeHTTP never changes a qualification listener into plaintext on an error.
func ServeHTTP(ctx context.Context, address string, handler http.Handler, c *Config, requireClient bool) error {
	if c == nil {
		return ErrIdentity
	}
	cfg, e := c.ServerTLS(requireClient)
	if e != nil {
		return e
	}
	server := &http.Server{Addr: address, Handler: handler, TLSConfig: cfg, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	serveDone := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			// The longest admitted control request is 60 seconds, followed by
			// at most seven seconds of fenced operational/evidence cleanup.
			// Compose supplies a 75-second outer stop grace.
			shutdown, stop := context.WithTimeout(context.Background(), 70*time.Second)
			err := server.Shutdown(shutdown)
			stop()
			if err != nil {
				_ = server.Close()
				drainDone <- ErrUncleanShutdown
				return
			}
			drainDone <- nil
		case <-serveDone:
			drainDone <- nil
		}
	}()

	if c.Profile == Qualification {
		e = server.ListenAndServeTLS("", "")
	} else {
		e = server.ListenAndServe()
	}
	close(serveDone)
	drainErr := <-drainDone
	if errors.Is(e, http.ErrServerClosed) {
		return drainErr
	}
	return e
}

// ErrUncleanShutdown requires a process-fatal exit before releasing custody:
// forced connection closure cannot prove a callback that ignored cancellation
// has stopped. Current service mains terminate on every ServeHTTP error.
var ErrUncleanShutdown = errors.New("HTTP drain exceeded bound; terminate process before releasing custody")
