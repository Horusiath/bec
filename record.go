package bec

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ID is a unique Record identifier. Generated as a consistent hash of that Record contents.
type ID = [sha256.Size]byte

func NewID(b []byte) ID {
	var id ID
	copy(id[:], b)
	return id
}

// AuthorId is a unique identifier of an author who produced given Record.
type AuthorId = [ed25519.PublicKeySize]byte

func NewAuthorId(pub ed25519.PublicKey) AuthorId {
	var res AuthorId
	copy(res[:], pub)
	return res
}

type Record struct {
	id     ID       // globally unique content addressed SHA256 hash of current Record
	author AuthorId // creator of current Record
	sign   []byte   // signature used by an author used for Record verification
	deps   []ID     // dependencies: hashes of direct predecessors of this Record
	data   []byte   // user data
}

func NewRecord(pub ed25519.PublicKey, priv ed25519.PrivateKey, deps []ID, data []byte) *Record {
	p := &Record{
		data:   data,
		deps:   deps,
		author: NewAuthorId(pub),
	}
	p.id = p.hash()
	p.sign = ed25519.Sign(priv, p.data) // could we just sign p.id? It's probably smaller and unique as well.
	return p
}

func (r *Record) Verify() error {
	if r.hash() != r.id {
		return fmt.Errorf("record hash and id don't match: %s", hex.EncodeToString(r.id[:]))
	}
	if !ed25519.Verify(r.author[:], r.data, r.sign) {
		return fmt.Errorf("record signature verficiation failed: %s", hex.EncodeToString(r.id[:]))
	}
	return nil
}

// Returns a content addressable hash of a given Record.
func (r *Record) hash() ID {
	h := sha256.New()
	for _, d := range r.deps {
		h.Write(d[:])
	}
	h.Write(r.data)
	h.Write(r.author[:])
	return NewID(h.Sum(nil))
}
