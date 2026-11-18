package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJobConfigIsAFileOrTheObjectItself(t *testing.T) {
	file := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(file, []byte(" {\"model\":\"m\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{file, `{"model":"m"}`, ` {"model":"m"} `} {
		got, err := readJobConfig(value)
		if err != nil || string(got) != `{"model":"m"}` {
			t.Fatalf("readJobConfig(%q) = %s, %v", value, got, err)
		}
	}
	if got, err := readJobConfig(""); got != nil || err != nil {
		t.Fatalf("empty: %s, %v", got, err)
	}
	for _, bad := range []string{`{"model":`, filepath.Join(t.TempDir(), "missing.json")} {
		if _, err := readJobConfig(bad); err == nil {
			t.Fatalf("readJobConfig(%q) took it", bad)
		}
	}
	array := filepath.Join(t.TempDir(), "array.json")
	os.WriteFile(array, []byte(`["m"]`), 0o600)
	if _, err := readJobConfig(array); err == nil {
		t.Fatal("took an array")
	}
}
