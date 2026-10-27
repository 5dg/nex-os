// pki is a synthetic test-PKI generator. It refuses existing output directories
// and never prints/stores the CA private key or prints leaf private material.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/5dg/nex-os/tests/qualification/fixtures/pki"
	"io"
	"os"
)

func main() {
	configPath := flag.String("config", "", "public JSON identity specification")
	directory := flag.String("directory", "", "NEW qualification PKI directory")
	flag.Parse()
	if *configPath == "" || *directory == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: pki --config <public-json> --directory <new-directory>")
		os.Exit(2)
	}
	input, e := os.Open(*configPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, "test PKI configuration unavailable")
		os.Exit(1)
	}
	defer input.Close()
	info, e := input.Stat()
	if e != nil || info.Size() > 32768 {
		fmt.Fprintln(os.Stderr, "bounded test PKI configuration required")
		os.Exit(1)
	}
	decoder := json.NewDecoder(io.LimitReader(input, 32768))
	decoder.DisallowUnknownFields()
	var config pki.BundleConfig
	if e = decoder.Decode(&config); e != nil {
		fmt.Fprintln(os.Stderr, "invalid test PKI configuration")
		os.Exit(1)
	}
	if e = decoder.Decode(&struct{}{}); e != io.EOF {
		fmt.Fprintln(os.Stderr, "single test PKI configuration required")
		os.Exit(1)
	}
	if _, e = pki.WriteBundle(*directory, config); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Synthetic qualification test PKI created; public manifest written.")
}
