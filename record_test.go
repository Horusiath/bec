package bec

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestRecordReadWrite(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}

	a := NewRecord(pub, priv, []ID{}, []byte("A"))
	b := NewRecord(pub, priv, []ID{a.id}, []byte("B"))
	c := NewRecord(pub, priv, []ID{a.id, b.id}, []byte("C"))

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	if err = c.Write(w); err != nil {
		t.Fatalf(err.Error())
	}
	if err = w.Flush(); err != nil {
		t.Fatalf(err.Error())
	}

	r := bufio.NewReader(&buf)
	p, err := ReadRecord(r)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if !bytes.Equal(p.id, c.id) {
		// since id is inferred from content, if content differs, then id differs as well
		t.Fatalf("deserialized content is different from the original")
	}
}
