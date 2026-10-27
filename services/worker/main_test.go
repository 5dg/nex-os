package main

import (
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
