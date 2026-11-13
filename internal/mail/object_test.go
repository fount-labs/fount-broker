package mail

import (
	"slices"
	"strings"
	"testing"
)

// The edge's TestPlaintextV2Layout bytes (internal/store/store_test.go at 10d7677).
const (
	v2Layout     = "\x00\x05a@b.c" + "\x00\x06w@f.co" + "\x01" + "\x09192.0.2.1" + "\x06mx.b.c" + "RAW"
	v2LayoutNone = "\x00\x00" + "\x00\x06w@f.co" + "\x00" + "\x00" + "\x00"
	// v3Layout is v2's envelope, then a 2-byte check, then the message.
	v3Layout = "\x00\x05a@b.c" + "\x00\x06w@f.co" + "\x01" + "\x09192.0.2.1" + "\x06mx.b.c" + "\x00\x00\x00\x02{}" + "RAW"
)

// unframeEnv is unframe for the v1/v2 tests, which have no check.
func unframeEnv(version byte, p []byte) (Envelope, []byte, error) {
	o, err := unframe(version, p)
	return o.Envelope, o.Raw, err
}

func TestUnframeV2Layout(t *testing.T) {
	env, raw, err := unframeEnv(objV2, []byte(v2Layout))
	if err != nil {
		t.Fatal(err)
	}
	want := Envelope{Sender: "a@b.c", Recipient: "w@f.co", ClientIP: "192.0.2.1", ClientIPSource: ClientIPGatewayProxy, HELO: "mx.b.c"}
	if env != want || string(raw) != "RAW" {
		t.Fatalf("got %+v %q", env, raw)
	}
	env, raw, err = unframeEnv(objV2, []byte(v2LayoutNone))
	if err != nil {
		t.Fatal(err)
	}
	if (env != Envelope{Recipient: "w@f.co"}) || len(raw) != 0 {
		t.Fatalf("empty framing: %+v %q", env, raw)
	}
	// The same bytes read as version 1 end the envelope after the recipient.
	env, raw, err = unframeEnv(objV1, []byte(v2Layout))
	if err != nil || (env != Envelope{Sender: "a@b.c", Recipient: "w@f.co"}) || string(raw) != v2Layout[15:] {
		t.Fatalf("v1: %+v %q %v", env, raw, err)
	}
}

func TestUnframeRefusesBadV2(t *testing.T) {
	head := "\x00\x05a@b.c" + "\x00\x06w@f.co"
	ip8 := func(s string) string { return string([]byte{byte(len(s))}) + s }
	for name, p := range map[string]string{
		"no source byte":      head,
		"no ip length":        head + "\x01",
		"ip overruns":         head + "\x01\x09192.0",
		"no helo length":      head + "\x01" + ip8("192.0.2.1"),
		"helo overruns":       head + "\x01" + ip8("192.0.2.1") + "\x06mx",
		"ip with source none": head + "\x00" + ip8("192.0.2.1") + "\x00",
		"source proxy, no ip": head + "\x01\x00\x00",
		"unknown source":      head + "\x02" + ip8("192.0.2.1") + "\x00",
		"ip not an address":   head + "\x01" + ip8("mx.b.c") + "\x00",
		"ip with a zone":      head + "\x01" + ip8("fe80::1%en0") + "\x00",
		"ip not canonical":    head + "\x01" + ip8("2001:DB8::1") + "\x00",
		"ip over 45 bytes":    head + "\x01" + ip8(strings.Repeat("1", 46)) + "\x00",
		"sender overruns":     "\x00\x09a@b.c",
		"recipient missing":   "\x00\x05a@b.c",
	} {
		if _, _, err := unframeEnv(objV2, []byte(p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	long := head + "\x01" + ip8("2001:db8::25") + "\xff" + strings.Repeat("h", 255) + "RAW"
	if env, raw, err := unframeEnv(objV2, []byte(long)); err != nil || len(env.HELO) != 255 || string(raw) != "RAW" {
		t.Fatalf("255-byte HELO: %v", err)
	}
	if _, _, err := unframeEnv(4, []byte(v2Layout)); err == nil {
		t.Fatal("unframe accepted version 4")
	}
}

func TestUnframeV3Layout(t *testing.T) {
	o, err := unframe(objV3, []byte(v3Layout))
	if err != nil {
		t.Fatal(err)
	}
	want := Envelope{Sender: "a@b.c", Recipient: "w@f.co", ClientIP: "192.0.2.1", ClientIPSource: ClientIPGatewayProxy, HELO: "mx.b.c"}
	if o.Envelope != want || string(o.Check) != "{}" || string(o.Raw) != "RAW" {
		t.Fatalf("got %+v", o)
	}
	head := v3Layout[:len(v3Layout)-len("\x00\x00\x00\x02{}RAW")]
	for name, p := range map[string]string{
		"no check length":  head,
		"short length":     head + "\x00\x00",
		"check overruns":   head + "\x00\x00\x00\x09{}",
		"check over limit": head + "\x00\x04\x00\x01" + strings.Repeat(" ", MaxCheck+1),
	} {
		if _, err := unframe(objV3, []byte(p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A v2 plaintext read as v3 takes "RAW" as a check length and refuses it.
	if _, err := unframe(objV3, []byte(v2Layout)); err == nil {
		t.Fatal("v2 bytes read as v3")
	}
}

func TestParseObjectVersions(t *testing.T) {
	obj := loadVectors(t).Messages[0].Object
	for version, ok := range map[byte]bool{0: false, 1: true, 2: true, 3: true, 4: false, 0xff: false} {
		b := slices.Clone(obj)
		b[4] = version
		o, err := ParseObject(b)
		if (err == nil) != ok {
			t.Fatalf("version %d: %v", version, err)
		}
		if ok && o.Version != version {
			t.Fatalf("version %d parsed as %d", version, o.Version)
		}
	}
}
