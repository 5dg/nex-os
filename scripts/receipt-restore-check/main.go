// Verify receiver lookup semantics in copied receipt stores during restore.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/5dg/nex-os/packages/broker"
)

func exists(path string) bool { _, e := os.Stat(path); return e == nil }
func verify(directory string) (int, error) {
	entries, e := os.ReadDir(directory)
	if e != nil {
		return 0, e
	}
	store := broker.ReceiptStore{Directory: directory}
	checked := 0
	for _, entry := range entries {
		suffix := ""
		for _, candidate := range []string{".state", ".done", ".pending"} {
			if strings.HasSuffix(entry.Name(), candidate) {
				suffix = candidate
				break
			}
		}
		if suffix == "" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), suffix)
		// The store gives v2 state precedence. A completed legacy receipt supersedes
		// its old reservation; copying that leftover reservation cannot make it run.
		if suffix != ".state" && exists(filepath.Join(directory, id+".state")) {
			continue
		}
		if suffix == ".pending" && exists(filepath.Join(directory, id+".done")) {
			continue
		}
		b, e := os.ReadFile(filepath.Join(directory, entry.Name()))
		if e != nil {
			return checked, e
		}
		var saved struct {
			Digest string          `json:"request_digest"`
			State  string          `json:"state"`
			Result json.RawMessage `json:"result"`
		}
		if suffix == ".pending" {
			saved.Digest = string(b)
		} else if e = json.Unmarshal(b, &saved); e != nil {
			return checked, e
		}
		out, e := store.Inspect(id, saved.Digest)
		switch {
		case suffix == ".done" || saved.State == "completed":
			if e != nil || !bytes.Equal(out, saved.Result) {
				return checked, errors.New("completed receipt did not restore")
			}
		case saved.State == "not_started":
			if !errors.Is(e, broker.ErrNotStarted) {
				return checked, errors.New("known-not-started receipt changed")
			}
		default:
			if !errors.Is(e, broker.ErrUnknown) {
				return checked, errors.New("pending or uncertain receipt became retryable")
			}
		}
		checked++
	}
	return checked, nil
}
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Copied receipt directories required")
		os.Exit(2)
	}
	total := 0
	for _, directory := range os.Args[1:] {
		count, e := verify(directory)
		if e != nil {
			fmt.Fprintln(os.Stderr, "Receipt restore verification failed:", e)
			os.Exit(1)
		}
		total += count
	}
	fmt.Printf("Restored receipt lookups passed: %d records\n", total)
}
