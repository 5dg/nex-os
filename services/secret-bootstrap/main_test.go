package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLayout(uid, gid int, files string) string {
	return fmt.Sprintf(`{"uid":%d,"gid":%d,"files":[%s]}`, uid, gid, files)
}

func TestResolveAndDeliverPrivateFiles(t *testing.T) {
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 || gid == 0 {
		t.Skip("test expects a non-root workspace user")
	}
	values := map[string]string{"NEX_SECRET_VALUE_PEM": "line1\nline2\n", "NEX_SECRET_VALUE_KEY": base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3})}
	get := func(key string) (string, bool) { v, ok := values[key]; return v, ok }
	cfg, files, err := resolve(testLayout(uid, gid, `{"name":"tls.pem","env":"NEX_SECRET_VALUE_PEM"},{"name":"key","env":"NEX_SECRET_VALUE_KEY","base64":true}`), get)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = deliver(dir, cfg.UID, cfg.GID, files); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"tls.pem": "line1\nline2\n", "key": string([]byte{0, 1, 2, 3})} {
		path := filepath.Join(dir, name)
		got, e := os.ReadFile(path)
		if e != nil || string(got) != want {
			t.Fatalf("wrong secret contents for %s", name)
		}
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("secret file permissions for %s", name)
		}
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("secret volume must be private")
	}
}

func TestResolveRejectsAmbiguousAndUnsafeLayouts(t *testing.T) {
	get := func(key string) (string, bool) { return "private-test-value", true }
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid = 1000
	}
	if gid == 0 {
		gid = 1000
	}
	cases := []string{
		testLayout(uid, gid, `{"name":"../escape","env":"NEX_SECRET_VALUE_A"}`),
		testLayout(uid, gid, `{"name":"file","env":"AWS_SECRET_ACCESS_KEY"}`),
		testLayout(uid, gid, `{"name":"same","env":"NEX_SECRET_VALUE_A"},{"name":"same","env":"NEX_SECRET_VALUE_B"}`),
		testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A"},{"name":"two","env":"NEX_SECRET_VALUE_A"}`),
		testLayout(uid, gid, `{"name":"one","name":"two","env":"NEX_SECRET_VALUE_A"}`),
		fmt.Sprintf(`{"uid":%d,"uid":%d,"gid":%d,"files":[{"name":"one","env":"NEX_SECRET_VALUE_A"}]}`, uid, uid, gid),
		fmt.Sprintf(`{"uid":%d,"UID":%d,"gid":%d,"files":[{"name":"one","env":"NEX_SECRET_VALUE_A"}]}`, uid, uid, gid),
		fmt.Sprintf(`{"UID":%d,"gid":%d,"files":[{"name":"one","env":"NEX_SECRET_VALUE_A"}]}`, uid, gid),
		fmt.Sprintf(`{"uid":%d,"gid":%d,"FILES":[{"name":"one","env":"NEX_SECRET_VALUE_A"}]}`, uid, gid),
		testLayout(uid, gid, `{"name":"one","NAME":"two","env":"NEX_SECRET_VALUE_A"}`),
		testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A","BASE64":false}`),
		testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A","base64":null}`),
		fmt.Sprintf(`{"uid":%d,"gid":%d,"extra":true,"files":[{"name":"one","env":"NEX_SECRET_VALUE_A"}]}`, uid, gid),
		testLayout(0, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A"}`),
		testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A","base64":true}`),
		testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A"}`) + `{}`,
	}
	for i, raw := range cases {
		_, _, err := resolve(raw, get)
		if err == nil {
			t.Fatalf("unsafe layout %d accepted", i)
		}
		if strings.Contains(err.Error(), "private-test-value") {
			t.Fatal("error leaked a secret")
		}
	}
	_, _, err := resolve(testLayout(uid, gid, `{"name":"one","env":"NEX_SECRET_VALUE_A"}`), func(string) (string, bool) { return "", false })
	if err == nil {
		t.Fatal("missing secret accepted")
	}
}

func TestDeliverRejectsExistingOrSymlinkedMount(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "existing")
	if err := os.WriteFile(sentinel, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	files := []secretFile{{name: "key", value: []byte("private-test-value")}}
	if err := deliver(dir, os.Geteuid(), os.Getegid(), files); err == nil {
		t.Fatal("nonempty volume accepted")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "preserved" {
		t.Fatal("existing file changed")
	}
	other := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if err := deliver(link, os.Geteuid(), os.Getegid(), files); err == nil {
		t.Fatal("symlinked volume accepted")
	}
	entries, err := os.ReadDir(other)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target changed")
	}
}

func TestEmptyTempVolumeGetsPrivateOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := deliver(dir, os.Geteuid(), os.Getegid(), nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("temporary volume must be private")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary volume must remain empty")
	}
}
