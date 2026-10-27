package main

import (
	"github.com/5dg/nex-os/packages/trust"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestWorkerAcceptsOnlyBoundedFixedWorkflowLease(t *testing.T) {
	good := `{"job_id":"job-123456","lease_token":"lease-123456"}`
	if _, e := readLease(&http.Response{Body: io.NopCloser(strings.NewReader(good))}); e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{`{"job_id":"../../v1/actions","lease_token":"lease-123456"}`, `{"job_id":"job-123456?route=other","lease_token":"lease-123456"}`, `{"job_id":"job-123456","lease_token":"bad\nheader"}`, `{"job_id":"job-123456","lease_token":"lease-123456","url":"https://other"}`, good + `{}`, strings.Repeat("x", 8193)} {
		if _, e := readLease(&http.Response{Body: io.NopCloser(strings.NewReader(body))}); e == nil {
			t.Fatal("unbounded or non-fixed lease accepted")
		}
	}
}

func TestWorkerSyntheticEnvironmentCannotStartProduction(t *testing.T) {
	for _, profile := range []trust.Profile{trust.Development, trust.Qualification} {
		if workerEnvironment(profile, "production") == nil {
			t.Fatal("production workerstarted", profile)
		}
		if e := workerEnvironment(profile, "development"); e != nil {
			t.Fatal(e)
		}
	}
	if workerEnvironment(trust.Qualification, "") == nil {
		t.Fatal("qualification accepted undeclaredenvironment")
	}
	if e := workerEnvironment(trust.Development, ""); e != nil {
		t.Fatal("legacy development unsetenvironment rejected", e)
	}
}
