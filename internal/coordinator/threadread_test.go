package coordinator

import (
	"net/http/httptest"
	"testing"
)

// markRead takes no base revision, doesn't move the revision, and is per
// device; a device's own op reads the thread, and a finished job unreads it.
func TestMarkReadIsPerDeviceAndOutsideTheRevision(t *testing.T) {
	c, r, _ := newThreadCoordinator(t, `{"model":"m"}`)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	_, w := do(t, srv, "POST", "/v0/workers", `{"account":"acme"}`)
	base := "/v0/workers/" + w["id"].(string)
	_, res := do(t, srv, "POST", base+"/ops", `{"opId":"op_1","kind":"startThread","args":{"text":"Close Acme"}}`)
	tid := res["threadId"].(string)
	eventually(t, "the job runs", func() bool { return r.started() == 1 })

	unreadNow := func() bool {
		t.Helper()
		_, list := do(t, srv, "GET", base+"/threads", "")
		return list["threads"].([]any)[0].(map[string]any)["unread"].(bool)
	}
	revision := func() float64 {
		_, v := do(t, srv, "GET", base+"/threads/"+tid, "")
		return v["revision"].(float64)
	}
	if unreadNow() {
		t.Fatal("a thread its own device started is unread")
	}
	r.release <- struct{}{}
	eventually(t, "the job finishes", func() bool { return unreadNow() })

	rev := revision()
	markRead := `{"opId":"op_2","threadId":"` + tid + `","kind":"markRead","args":{}}`
	code, res := do(t, srv, "POST", base+"/threads/"+tid+"/ops", markRead)
	if code != 200 || res["ok"] != true || res["revision"] != rev {
		t.Fatalf("markRead: %d %v", code, res)
	}
	if unreadNow() || revision() != rev {
		t.Fatalf("after markRead: unread %v, revision %v (was %v)", unreadNow(), revision(), rev)
	}
	if code, res := do(t, srv, "POST", base+"/threads/"+tid+"/ops", markRead); code != 200 || res["ok"] != true {
		t.Fatalf("markRead again: %d %v", code, res)
	}

	// Another device hasn't read it.
	reads := func() map[string]threadRead {
		var out map[string]threadRead
		lock, wk, _ := c.workerLock(w["id"].(string))
		lock.Lock()
		defer lock.Unlock()
		tr, err := c.loadTree(wk, anyDevice)
		if err != nil {
			t.Fatal(err)
		}
		out, _ = loadReads(tr, tid)
		return out
	}()
	th := readThread(t, c, Worker{ID: w["id"].(string)}, tid)
	if !unread(reads, "dev_other", th) || unread(reads, anyDevice, th) {
		t.Fatal("read state isn't per device")
	}

	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"opId":"op_3","threadId":"` + tid + `","kind":"markRead","args":{"x":1}}`, 400},
		{`{"opId":"op_3","threadId":"thr_other","kind":"markRead","args":{}}`, 400},
	} {
		if code, out := do(t, srv, "POST", base+"/threads/"+tid+"/ops", tc.body); code != tc.want {
			t.Errorf("%s: %d %v", tc.body, code, out)
		}
	}
	if code, res := do(t, srv, "POST", base+"/threads/thr_nope/ops", `{"opId":"op_4","threadId":"thr_nope","kind":"markRead","args":{}}`); code != 200 || res["code"] != "NOT_FOUND" {
		t.Errorf("markRead on no thread: %d %v", code, res)
	}
}
