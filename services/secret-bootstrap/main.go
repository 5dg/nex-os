// secret-bootstrap is a short-lived, root-owned file delivery process for a
// task-private volume. It never starts the application or retrieves secrets.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"golang.org/x/sys/unix"
)

const secretDirectory = "/run/nex-secrets"
const tempDirectory = "/run/nex-tmp"
const maxLayoutBytes = 16384
const maxSecretBytes = 65536

var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var secretName = regexp.MustCompile(`^NEX_SECRET_VALUE_[A-Z0-9_]{1,56}$`)

type fileSpec struct {
	Name   string `json:"name"`
	Env    string `json:"env"`
	Base64 bool   `json:"base64"`
}
type layout struct {
	UID   int        `json:"uid"`
	GID   int        `json:"gid"`
	Tmp   bool       `json:"tmp"`
	Files []fileSpec `json:"files"`
}
type secretFile struct {
	name  string
	value []byte
}

// encoding/json otherwise accepts duplicate object keys and silently keeps the
// last value. Reject them recursively, including in individual file entries.
func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate key")
				}
				seen[key] = true
				if err = value(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid object")
			}
		case '[':
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid array")
			}
		default:
			return errors.New("invalid value")
		}
		return nil
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// Struct decoding in encoding/json is case-insensitive. Enforce the exact
// schema before struct decoding so aliases such as UID or Name cannot replace
// a differently cased field. Duplicate keys are rejected separately above.
func exactLayoutKeys(data []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil || top == nil {
		return false
	}
	for key, value := range top {
		if key != "uid" && key != "gid" && key != "tmp" && key != "files" {
			return false
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(top["files"], &entries) != nil {
		return false
	}
	for _, entry := range entries {
		if entry == nil {
			return false
		}
		for key, value := range entry {
			if key != "name" && key != "env" && key != "base64" {
				return false
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return false
			}
		}
	}
	return true
}

// resolve validates the entire input before opening or modifying the mount.
// Returned errors intentionally contain neither names nor secret contents.
func resolve(raw string, getenv func(string) (string, bool)) (layout, []secretFile, error) {
	var cfg layout
	bad := func() (layout, []secretFile, error) {
		return layout{}, nil, errors.New("invalid secret layout or value")
	}
	if len(raw) == 0 || len(raw) > maxLayoutBytes || uniqueJSON([]byte(raw)) != nil || !exactLayoutKeys([]byte(raw)) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || cfg.UID <= 0 || cfg.GID <= 0 || cfg.UID > 1<<31-1 || cfg.GID > 1<<31-1 || len(cfg.Files) == 0 || len(cfg.Files) > 64 {
		return bad()
	}
	names, envs := map[string]bool{}, map[string]bool{}
	files := make([]secretFile, 0, len(cfg.Files))
	for _, entry := range cfg.Files {
		if !fileName.MatchString(entry.Name) || !secretName.MatchString(entry.Env) || names[entry.Name] || envs[entry.Env] {
			return bad()
		}
		names[entry.Name], envs[entry.Env] = true, true
		v, ok := getenv(entry.Env)
		if !ok || len(v) == 0 || len(v) > maxSecretBytes*2 {
			return bad()
		}
		data := []byte(v)
		if entry.Base64 {
			var err error
			data, err = base64.StdEncoding.Strict().DecodeString(v)
			if err != nil {
				return bad()
			}
		}
		if len(data) == 0 || len(data) > maxSecretBytes {
			return bad()
		}
		files = append(files, secretFile{name: entry.Name, value: data})
	}
	return cfg, files, nil
}

// deliver requires a fresh mount owned by this process. Files are created
// exclusively relative to the open directory, and ownership is handed off only
// after every file is complete. ECS must gate application start on SUCCESS.
func deliver(directory string, uid, gid int, files []secretFile) (err error) {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("secret volume unavailable")
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return errors.New("secret volume ownership invalid")
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return errors.New("secret volume unavailable")
	}
	dir := os.NewFile(uintptr(dup), "secret-volume")
	_, readErr := dir.Readdirnames(1)
	closeErr := dir.Close()
	if readErr != io.EOF || closeErr != nil {
		return errors.New("secret volume must be empty")
	}
	if unix.Fchmod(fd, 0700) != nil {
		return errors.New("secret volume permissions unavailable")
	}
	created := []string{}
	handedOff := false
	defer func() {
		if err != nil && !handedOff {
			for _, name := range created {
				_ = unix.Unlinkat(fd, name, 0)
			}
			_ = unix.Fsync(fd)
		}
	}()
	for _, f := range files {
		child, e := unix.Openat(fd, f.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e != nil {
			return errors.New("secret file unavailable")
		}
		created = append(created, f.name)
		out := os.NewFile(uintptr(child), "secret-file")
		if out.Chmod(0600) != nil {
			_ = out.Close()
			return errors.New("secret file unavailable")
		}
		if _, e = out.Write(f.value); e == nil {
			e = out.Sync()
		}
		if e == nil {
			e = unix.Fchown(child, uid, gid)
		}
		if e == nil {
			e = out.Sync()
		}
		if closeError := out.Close(); e == nil {
			e = closeError
		}
		if e != nil {
			return errors.New("secret file unavailable")
		}
	}
	if unix.Fsync(fd) != nil || unix.Fchown(fd, uid, gid) != nil {
		return errors.New("secret volume handoff failed")
	}
	handedOff = true
	if unix.Fsync(fd) != nil {
		return errors.New("secret volume handoff failed")
	}
	return nil
}

// Initialization needs CHOWN for the task-volume handoff, and no other
// capabilities. The task must explicitly drop every other default capability.
func restrictProcess() error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap identity invalid")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) != nil || data[0].Effective != 1<<unix.CAP_CHOWN || data[0].Permitted != 1<<unix.CAP_CHOWN || data[0].Inheritable != 0 || data[1] != (unix.CapUserData{}) {
		return errors.New("bootstrap capabilities invalid")
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errors.New("bootstrap process restrictions unavailable")
	}
	return nil
}

func main() {
	if err := restrictProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "secret bootstrap failed:", err)
		os.Exit(1)
	}
	cfg, files, err := resolve(os.Getenv("NEX_SECRET_LAYOUT"), os.LookupEnv)
	if err == nil {
		for _, entry := range cfg.Files {
			_ = os.Unsetenv(entry.Env)
		}
		if cfg.Tmp {
			err = deliver(tempDirectory, cfg.UID, cfg.GID, nil)
		}
		if err == nil {
			err = deliver(secretDirectory, cfg.UID, cfg.GID, files)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "secret bootstrap failed:", err)
		os.Exit(1)
	}
}
