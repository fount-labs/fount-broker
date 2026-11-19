package coordinator

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnExportHasTheWorkersThreadsMailAndFiles(t *testing.T) {
	r := newSendRig(t, modeNotify)
	th, e := r.drafted()
	if res := r.approve(th, e, "op_ok", 1); !res.OK {
		t.Fatalf("approve: %+v", res)
	}
	r.pass()
	held := r.edge.deliver(r.mb, email{from: "eve@elsewhere.example", to: testWorkerAddr, subject: "Hello"})
	r.pass()
	if err := r.c.change(r.w.ID, anyDevice, func(t *Tree) error {
		if err := t.Write(prefixRoot+"notes/q3.md", []byte("Q3 notes")); err != nil {
			return err
		}
		return t.Write(prefixIndex+"chunks.bin", []byte("index"))
	}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(r.c.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v0/workers/" + r.w.ID + "/export")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("export: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	files := map[string][]byte{}
	tr := tar.NewReader(resp.Body)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		files[h.Name] = data
	}
	has := func(prefix string) bool {
		for name := range files {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	}
	if string(files["files/notes/q3.md"]) != "Q3 notes" {
		t.Errorf("the file: %q", files["files/notes/q3.md"])
	}
	var view ThreadView
	if err := json.Unmarshal(files["threads/"+th.ID+".json"], &view); err != nil || view.ID != th.ID {
		t.Errorf("the thread: %v %+v", err, view)
	}
	if !has("mail/sent/") {
		t.Error("no sent mail")
	}
	if !has("mail/held/") {
		t.Errorf("no held mail (edge id %s)", held)
	}
	if !has("record/mail/ledger.json") {
		t.Error("no mail ledger")
	}
	if has("index/") || has("record/other/index/") {
		t.Error("the index was exported")
	}
	if !strings.Contains(string(files["mail/address.json"]), testWorkerAddr) {
		t.Errorf("the address: %s", files["mail/address.json"])
	}
	for name, data := range files {
		if bytes.Contains(data, []byte("signingKey")) || bytes.Contains(data, []byte("decryptionKey")) {
			t.Errorf("%s has the mailbox's keys", name)
		}
	}
	var idx ExportIndex
	if err := json.Unmarshal(files["fount-export.json"], &idx); err != nil || idx.Worker != r.w.ID || idx.Threads < 1 || idx.Files < 1 {
		t.Fatalf("the index: %v %+v", err, idx)
	}
}
