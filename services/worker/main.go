package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/5dg/nex-os/packages/broker"
	"github.com/5dg/nex-os/packages/contracts"
	"github.com/5dg/nex-os/packages/trust"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func validLease(lease contracts.Lease) bool {
	valid := func(x string) bool {
		if len(x) < 8 || len(x) > 100 {
			return false
		}
		for _, r := range x {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
		return true
	}
	return valid(lease.JobID) && valid(lease.Token)
}
func readLease(response *http.Response) (contracts.Lease, error) {
	var lease contracts.Lease
	body, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(body) > 8192 {
		return lease, errors.New("invalid bounded lease")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&lease) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validLease(lease) {
		return lease, errors.New("invalid lease")
	}
	return lease, nil
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	profile, e := trust.FromEnv()
	if e != nil {
		log.Fatal(e)
	}
	if e = workerEnvironment(profile, os.Getenv("APP_ENV")); e != nil {
		log.Fatal(e)
	}
	cfg, e := trust.Load(profile, trust.Worker)
	if e != nil {
		log.Fatal(e)
	}
	key, e := broker.Key(os.Getenv("WORKER_KEY_FILE"))
	if e != nil {
		log.Fatal(e)
	}
	auth := "Bearer " + base64.RawURLEncoding.EncodeToString(key)
	base := strings.TrimRight(os.Getenv("CONTROL_URL"), "/")
	if e = cfg.CheckURL(base); e != nil {
		log.Fatal("valid fixed control URL required")
	}
	claimClient, e := cfg.HTTPClient(trust.Control, 10*time.Second)
	if e != nil {
		log.Fatal(e)
	}
	stepClient, e := cfg.HTTPClient(trust.Control, 45*time.Second)
	if e != nil {
		log.Fatal(e)
	}
	call := func(client *http.Client, path string, body any) (*http.Response, error) {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, e
		}
		r, e := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", auth)
		return client.Do(r)
	}
	log.Print("restricted fixed-workflow worker started; profile=", profile)
	var lastDiagnostic time.Time
	diagnostic := func() {
		if time.Since(lastDiagnostic) >= 30*time.Second {
			log.Print("worker dependency or lease unavailable; no direct execution retry requested")
			lastDiagnostic = time.Now()
		}
	}
	for ctx.Err() == nil {
		response, e := call(claimClient, "/internal/work/claim", struct{}{})
		if e == nil {
			if response.StatusCode == 200 {
				lease, e := readLease(response)
				response.Body.Close()
				if e == nil {
					done, e := call(stepClient, "/internal/work/"+lease.JobID+"/step", lease)
					if e == nil {
						if done.StatusCode != 200 {
							diagnostic()
						}
						done.Body.Close()
					} else {
						diagnostic()
					}
				} else {
					diagnostic()
				}
			} else {
				if response.StatusCode != 204 {
					diagnostic()
				}
				response.Body.Close()
			}
		} else {
			diagnostic()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func workerEnvironment(profile trust.Profile, environment string) error {
	if profile != trust.Development && profile != trust.Qualification {
		return errors.New("unsupported worker profile")
	}
	if environment != "" && environment != "development" {
		return errors.New("synthetic worker requires development environment")
	}
	if profile == trust.Qualification && environment != "development" {
		return errors.New("qualification requires explicit development environment")
	}
	return nil
}
