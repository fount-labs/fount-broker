package coordinator

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/fount-labs/fount-broker/internal/filetree"
	"github.com/fount-labs/fount-broker/internal/frame"
	"github.com/fount-labs/fount-broker/internal/jobwire"
)

// fakeEnclave answers one intake job with exit 0 and back as its out/ stream,
// after checking the job carries nothing but the email.
func fakeEnclave(t *testing.T, back []byte) (addr string, saw chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	saw = make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		saw <- func() error {
			first, err := frame.Read(conn)
			if err != nil {
				return err
			}
			job, err := jobwire.DecodeJob(first, jobwire.FromCoordinator)
			if err != nil {
				return err
			}
			if job.Mode != jobwire.ModeIntake || job.Credentials != nil || len(first.Body) != 0 {
				return &jobwire.Remote{Message: "intake carried " + string(first.Header)}
			}
			in := &jobwire.Stream{R: conn, Kind: jobwire.KindWorkspace}
			if _, err := filetree.Extract(in, t.TempDir(), filetree.Limits{}, nil); err != nil {
				return err
			}
			return in.Drain()
		}()
		w := frame.NewWriter(conn)
		jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindExit}, nil)
		out := jobwire.Chunks{W: w, Kind: jobwire.KindWorkspace}
		out.Write(back)
		out.Close()
		jobwire.Send(w, jobwire.Reply{Kind: jobwire.KindEnd}, nil)
	}()
	return l.Addr().String(), saw
}

func tarOf(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		tw.WriteHeader(h)
		// A giant file's header is enough: it is refused before its body.
		if h.Typeflag == tar.TypeReg && h.Size <= 1<<20 {
			tw.Write(make([]byte, h.Size))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func manyFiles(n int) []*tar.Header {
	var h []*tar.Header
	for i := range n {
		h = append(h, &tar.Header{Typeflag: tar.TypeReg, Name: fmt.Sprintf("attachments/%d", i), Mode: 0o644})
	}
	return h
}

func TestRemoteIntakeRefusesAHostileTree(t *testing.T) {
	file := func(name string) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: 1, Mode: 0o644}
	}
	for name, back := range map[string][]byte{
		"a link":           tarOf(t, file("message.md"), &tar.Header{Typeflag: tar.TypeSymlink, Name: "attachments/a", Linkname: "/etc/passwd"}),
		"a hard link":      tarOf(t, file("message.md"), &tar.Header{Typeflag: tar.TypeLink, Name: "x", Linkname: "message.md"}),
		"climbing out":     tarOf(t, file("../../escape")),
		"an absolute name": tarOf(t, file("/tmp/escape")),
		"a giant file":     tarOf(t, &tar.Header{Typeflag: tar.TypeReg, Name: "message.md", Size: maxIntakeTotalBytes + 1, Mode: 0o644}),
		"too many entries": tarOf(t, manyFiles(maxIntakeAttachments+10)...),
		"not a tar":        []byte("not a tar stream at all, just noise"),
	} {
		addr, saw := fakeEnclave(t, back)
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "message.eml"), []byte("x"), 0o644)
		_, err := RemoteRunner{Addr: addr}.RunIntake(context.Background(), "runner-1", "acct1", dir)
		if err := <-saw; err != nil {
			t.Fatalf("%s: the enclave saw %v", name, err)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape")); err == nil {
			t.Errorf("%s: wrote outside out/", name)
		}
	}
}

func TestRemoteIntakeKeepsAGoodTree(t *testing.T) {
	out := writeIntakeOut(t, goodIntakeSpec())
	var buf bytes.Buffer
	if err := filetree.Pack(out, &buf, filetree.Limits{}); err != nil {
		t.Fatal(err)
	}
	addr, saw := fakeEnclave(t, buf.Bytes())
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "message.eml"), []byte("x"), 0o644)
	if _, err := (RemoteRunner{Addr: addr}).RunIntake(context.Background(), "runner-1", "acct1", dir); err != nil {
		t.Fatal(err)
	}
	if err := <-saw; err != nil {
		t.Fatal(err)
	}
	if _, files, err := ReadIntake(filepath.Join(dir, intakeOut), testEdgeID); err != nil || len(files) != 3 {
		t.Fatalf("%v: %v", files, err)
	}
}
