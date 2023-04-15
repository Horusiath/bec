package bec

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestRecordsReadWrite(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}

	a := NewRecord(pub, priv, []ID{}, []byte("A"))
	b := NewRecord(pub, priv, []ID{a.id}, []byte("B"))
	c := NewRecord(pub, priv, []ID{a.id, b.id}, []byte("C"))

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	if err = WriteRecords([]*Record{a, b, c}, w); err != nil {
		t.Fatalf(err.Error())
	}
	if err = w.Flush(); err != nil {
		t.Fatalf(err.Error())
	}

	r := bufio.NewReader(&buf)
	rs, err := ReadRecords(r)
	if err != nil {
		t.Fatalf(err.Error())
	}

	// since id is inferred from content, if content differs, then id differs as well
	if rs[0].id != a.id {
		t.Fatalf("deserialized content is different from the original at index 0")
	}
	if rs[1].id != b.id {
		t.Fatalf("deserialized content is different from the original at index 1")
	}
	if rs[2].id != c.id {
		t.Fatalf("deserialized content is different from the original at index 2")
	}
}
