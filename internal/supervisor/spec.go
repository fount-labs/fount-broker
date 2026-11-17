package supervisor

import (
	"encoding/json"
	"strconv"
	"strings"
)

// The OCI runtime spec, as much of it as a job's sandbox uses.
type runtimeSpec struct {
	OCIVersion string      `json:"ociVersion"`
	Process    specProcess `json:"process"`
	Root       specRoot    `json:"root"`
	Hostname   string      `json:"hostname"`
	Mounts     []specMount `json:"mounts"`
	Linux      specLinux   `json:"linux"`
}

type specProcess struct {
	Terminal        bool                `json:"terminal"`
	User            specUser            `json:"user"`
	Args            []string            `json:"args"`
	Env             []string            `json:"env"`
	Cwd             string              `json:"cwd"`
	Capabilities    map[string][]string `json:"capabilities"`
	Rlimits         []specRlimit        `json:"rlimits"`
	NoNewPrivileges bool                `json:"noNewPrivileges"`
}

type specUser struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type specRlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type specRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type specMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type specLinux struct {
	Namespaces  []specNamespace `json:"namespaces"`
	Resources   specResources   `json:"resources"`
	CgroupsPath string          `json:"cgroupsPath"`
}

type specNamespace struct {
	Type string `json:"type"`
}

type specResources struct {
	Memory specMemory `json:"memory"`
	Pids   specPids   `json:"pids"`
	CPU    *specCPU   `json:"cpu,omitempty"`
}

type specMemory struct {
	Limit int64 `json:"limit"`
	// Swap is memory plus swap, so equal to Limit means no swap.
	Swap int64 `json:"swap"`
}

type specPids struct {
	Limit int64 `json:"limit"`
}

type specCPU struct {
	Quota  int64  `json:"quota"`
	Period uint64 `json:"period"`
}

// Limits are each sandbox's cgroup caps (m4-cloud-runners.md §5.1c).
type Limits struct {
	MemoryBytes int64
	Pids        int64
	// CPUs caps the sandbox's share of the enclave's cores; 0 leaves it
	// uncapped.
	CPUs float64
	// TmpBytes sizes the sandbox's tmpfs /tmp.
	TmpBytes int64
}

// Sandbox paths, fixed: the runner sees the same layout in every job.
const (
	sandboxWork   = "/work"
	sandboxData   = "/data"
	sandboxIndex  = "/index"
	sandboxJob    = "/job.json"
	sandboxBroker = "/run/broker"
	// jobSocket is the broker's socket in a job's socket folder (package relay).
	jobSocket = "job.sock"
)

func jobSpec(rootfs string, img *Image, uid, gid uint32, limits Limits, job Job, args []string, cgroupsPath string) ([]byte, error) {
	env := append([]string{}, img.Env...)
	if !hasEnv(env, "HOME") {
		env = append(env, "HOME=/tmp")
	}
	mounts := []specMount{
		{Destination: "/proc", Type: "proc", Source: "proc"},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "size=" + strconv.FormatInt(limits.TmpBytes, 10)}},
		{Destination: sandboxWork, Type: "bind", Source: job.Workspace, Options: []string{"rbind", "rw"}},
		{Destination: sandboxData, Type: "bind", Source: job.Data, Options: []string{"rbind", "rw"}},
		{Destination: sandboxIndex, Type: "bind", Source: job.Index, Options: []string{"rbind", "rw"}},
		{Destination: sandboxJob, Type: "bind", Source: job.JobFile, Options: []string{"rbind", "ro"}},
	}
	if job.SocketDir != "" {
		mounts = append(mounts, specMount{Destination: sandboxBroker, Type: "bind", Source: job.SocketDir, Options: []string{"rbind", "rw"}})
	}
	none := []string{}
	spec := runtimeSpec{
		OCIVersion: "1.0.0",
		Process: specProcess{
			User: specUser{UID: uid, GID: gid},
			Args: args,
			Env:  env,
			Cwd:  "/",
			Capabilities: map[string][]string{
				"bounding": none, "effective": none, "inheritable": none, "permitted": none, "ambient": none,
			},
			Rlimits:         []specRlimit{{Type: "RLIMIT_NOFILE", Hard: 4096, Soft: 4096}},
			NoNewPrivileges: true,
		},
		Root:     specRoot{Path: rootfs, Readonly: true},
		Hostname: "job",
		Mounts:   mounts,
		Linux: specLinux{
			Namespaces: []specNamespace{{Type: "pid"}, {Type: "network"}, {Type: "ipc"}, {Type: "uts"}, {Type: "mount"}},
			Resources: specResources{
				Memory: specMemory{Limit: limits.MemoryBytes, Swap: limits.MemoryBytes},
				Pids:   specPids{Limit: limits.Pids},
			},
			CgroupsPath: cgroupsPath,
		},
	}
	if limits.CPUs > 0 {
		const period = 100_000
		spec.Linux.Resources.CPU = &specCPU{Quota: int64(limits.CPUs * period), Period: period}
	}
	return json.MarshalIndent(spec, "", "  ")
}

func hasEnv(env []string, name string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, name+"=") {
			return true
		}
	}
	return false
}
