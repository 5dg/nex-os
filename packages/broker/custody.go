package broker

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Custody is a single live local owner of a private storage directory. It is not
// a distributed lease and does not authorize multiple volumes or replicas.
type Custody struct {
	Directory string
	file      *os.File
	mu        sync.Mutex
}

func OpenCustody(directory, role string) (*Custody, error) {
	if directory == "" || role == "" || !filepath.IsAbs(directory) || !validID("custody-"+role) {
		return nil, errors.New("absolute private custody directory and fixed role required")
	}
	directory = filepath.Clean(directory)
	if e := ensureDirectory(directory); e != nil {
		return nil, errors.New("custody storage unavailable")
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private custody directory required")
	}
	lockPath := filepath.Join(directory, ".custody.lock")
	f, e := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, errors.New("custody lock unavailable")
	}
	fail := func() (*Custody, error) {
		f.Close()
		return nil, errors.New("custody domain already owned or unavailable")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail()
	}
	if e = f.Sync(); e != nil {
		return fail()
	}
	if e = syncDirectory(directory); e != nil {
		return fail()
	}
	c := &Custody{Directory: directory, file: f}
	if c.Check() != nil {
		return fail()
	}
	return c, nil
}
func (c *Custody) Check() error {
	if c == nil {
		return errors.New("local custody not acquired")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return errors.New("local custody closed")
	}
	directory, e := os.Lstat(c.Directory)
	if e != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm()&0077 != 0 {
		return errors.New("private custody storage unavailable")
	}
	held, e := c.file.Stat()
	if e != nil {
		return errors.New("custody lock unavailable")
	}
	current, e := os.Lstat(filepath.Join(c.Directory, ".custody.lock"))
	if e != nil || !current.Mode().IsRegular() || current.Mode().Perm()&0077 != 0 || !os.SameFile(held, current) {
		return errors.New("custody lock replaced")
	}
	return nil
}
func (c *Custody) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	e := c.file.Close()
	c.file = nil
	return e
}
func OpenReceiptStore(directory, role string) (ReceiptStore, error) {
	c, e := OpenCustody(directory, role)
	if e != nil {
		return ReceiptStore{}, e
	}
	return ReceiptStore{Directory: c.Directory, custody: c}, nil
}
func (s ReceiptStore) CheckCustody() error { return s.custody.Check() }
func (s ReceiptStore) Close() error        { return s.custody.Close() }
func (s ReceiptStore) Ready() error {
	if e := s.custody.Check(); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.Directory, ".readiness-")
	if e != nil {
		return errors.New("receipt storage unavailable")
	}
	path := f.Name()
	defer os.Remove(path)
	e = f.Sync()
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return errors.New("receipt storage unavailable")
	}
	return syncDirectory(s.Directory)
}

// StatusClient preserves the client/key/transport while narrowing the method
// capability. Its path is fixed and cannot be supplied by a browser or model.
func (c *Client) StatusClient() (*Client, error) {
	if c == nil {
		return nil, errors.New("executor client required")
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid executor endpoint")
	}
	out := *c
	switch c.Audience {
	case "model.execute":
		out.Audience = "model.status"
	case "export.execute":
		out.Audience = "export.status"
	default:
		return nil, errors.New("executor audience required")
	}
	u.Path = "/status"
	u.RawPath = ""
	out.URL = u.String()
	return &out, nil
}
