package protocol

import (
	"errors"
	"testing"
)

func TestDecodeRequest(t *testing.T) {
	valid := []string{
		`{"kind":"fetch","id":1,"dest":"tinfoil.chat_completions"}`,
		`{"kind":"fetch","id":2,"dest":"tinfoil.chat_completions","accept":"text/event-stream"}`,
		`{"kind":"fetch","id":6,"dest":"updates.package","path":"v1.2.3/Fount_1.2.3_x64-setup.exe"}`,
		`{"kind":"cancel","id":3}`,
		`{"kind":"credential","id":4,"name":"license"}`,
		`{"kind":"status","id":5,"route":"tinfoil"}`,
		`{"kind":"mail","id":7,"op":"list","mailbox":"ab"}`,
		`{"kind":"mail","id":8,"op":"get","mailbox":"ab","path":"cd"}`,
	}
	for _, h := range valid {
		if _, err := DecodeRequest([]byte(h)); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}

	invalid := map[string]string{
		"unknown field":      `{"kind":"fetch","id":1,"dest":"x","url":"https://evil.example"}`,
		"unknown kind":       `{"kind":"connect","id":1}`,
		"missing id":         `{"kind":"cancel"}`,
		"trailing data":      `{"kind":"cancel","id":1}{"kind":"cancel","id":2}`,
		"fetch without dest": `{"kind":"fetch","id":1}`,
		"fetch with route":   `{"kind":"fetch","id":1,"dest":"x","route":"tinfoil"}`,
		"cancel with dest":   `{"kind":"cancel","id":1,"dest":"x"}`,
		"status with path":   `{"kind":"status","id":1,"route":"models","path":"x"}`,
		"credential no name": `{"kind":"credential","id":1}`,
		"status no route":    `{"kind":"status","id":1}`,
		"mail no op":         `{"kind":"mail","id":1,"mailbox":"ab"}`,
		"mail no mailbox":    `{"kind":"mail","id":1,"op":"list"}`,
		"mail with dest":     `{"kind":"mail","id":1,"op":"list","mailbox":"ab","dest":"x"}`,
		"fetch with op":      `{"kind":"fetch","id":1,"dest":"x","op":"list"}`,
		"credential mailbox": `{"kind":"credential","id":1,"name":"license","mailbox":"ab"}`,
		"not json":           `kind=fetch`,
		"wrong type":         `{"kind":"cancel","id":"1"}`,
	}
	for name, h := range invalid {
		if _, err := DecodeRequest([]byte(h)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}
