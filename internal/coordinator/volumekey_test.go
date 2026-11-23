package coordinator

import (
	"bytes"
	"testing"
)

func TestVolumeKeysAreTheirOwn(t *testing.T) {
	w, _ := NewWrappingKey()
	b := backupKey(&w)
	vk, dev := VolumeKey(&w), DevVolumeKey(w[:])
	if len(vk) != KeySize || !bytes.Equal(vk, VolumeKey(&w)) {
		t.Fatal("VolumeKey isn't a fixed 32-byte key")
	}
	for _, other := range [][]byte{w[:], b[:], dev} {
		if bytes.Equal(vk, other) {
			t.Fatal("the volume key is another key")
		}
	}
}
