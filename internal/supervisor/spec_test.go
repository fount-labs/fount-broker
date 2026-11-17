package supervisor

import (
	"encoding/json"
	"testing"
)

func TestJobSpecIsTheSandboxPolicy(t *testing.T) {
	img := &Image{Entrypoint: []string{"/opt/fount/bin/fount-runner"}, Env: []string{"PATH=/bin"}}
	limits := Limits{MemoryBytes: 2 << 30, Pids: 1024, CPUs: 1.5, TmpBytes: 1 << 30}
	job := Job{ID: "j1", Workspace: "/w", Data: "/d", Index: "/i", JobFile: "/j.json", SocketDir: "/s"}
	data, err := jobSpec("/harness/rootfs", img, 10001, 10001, limits, job, []string{"/opt/fount/bin/fount-runner"}, "/fount-jobs/j1/sandbox")
	if err != nil {
		t.Fatal(err)
	}
	var spec runtimeSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if !spec.Root.Readonly || spec.Root.Path != "/harness/rootfs" {
		t.Errorf("root = %+v", spec.Root)
	}
	if spec.Process.User.UID != 10001 || !spec.Process.NoNewPrivileges {
		t.Errorf("process = %+v", spec.Process)
	}
	for set, caps := range spec.Process.Capabilities {
		if len(caps) != 0 {
			t.Errorf("%s capabilities %v", set, caps)
		}
	}
	if len(spec.Process.Capabilities) != 5 {
		t.Errorf("capability sets %v, want all five empty", spec.Process.Capabilities)
	}
	namespaces := map[string]bool{}
	for _, ns := range spec.Linux.Namespaces {
		namespaces[ns.Type] = true
	}
	if !namespaces["network"] || !namespaces["pid"] || !namespaces["mount"] {
		t.Errorf("namespaces %v", spec.Linux.Namespaces)
	}
	r := spec.Linux.Resources
	if r.Memory.Limit != 2<<30 || r.Memory.Swap != 2<<30 || r.Pids.Limit != 1024 || r.CPU.Quota != 150_000 {
		t.Errorf("resources %+v %+v", r, r.CPU)
	}
	mounts := map[string]specMount{}
	for _, m := range spec.Mounts {
		mounts[m.Destination] = m
	}
	want := map[string]string{"/work": "/w", "/data": "/d", "/index": "/i", "/job.json": "/j.json", "/run/broker": "/s"}
	for dest, src := range want {
		if mounts[dest].Source != src {
			t.Errorf("%s mounted from %q, want %q", dest, mounts[dest].Source, src)
		}
	}
	if opts := mounts["/job.json"].Options; opts[len(opts)-1] != "ro" {
		t.Errorf("job file options %v", opts)
	}
	if spec.Process.Env[len(spec.Process.Env)-1] != "HOME=/tmp" {
		t.Errorf("env %v", spec.Process.Env)
	}
}
