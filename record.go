package bec

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// ID is a unique Record identifier. Generated as a consistent hash of that Record contents.
type ID = []byte

// AuthorId is a unique identifier of an author who produced given Record.
type AuthorId = ed25519.PublicKey

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
		author: pub,
	}
	p.id = p.hash()
	p.sign = ed25519.Sign(priv, p.data) // could we just sign p.id? It's probably smaller and unique as well.
	return p
}

func (r *Record) Verify() error {
	if bytes.Compare(r.hash(), r.id) != 0 {
		return fmt.Errorf("record hash and id don't match: %s", hex.EncodeToString(r.id))
	}
	if !ed25519.Verify(r.author, r.data, r.sign) {
		return fmt.Errorf("record signature verficiation failed: %s", hex.EncodeToString(r.id))
	}
	return nil
}

// Returns a content addressable hash of a given Record.
func (r *Record) hash() ID {
	h := sha256.New()
	for _, d := range r.deps {
		h.Write(d)
	}
	h.Write(r.data)
	h.Write(r.author)
	return h.Sum(nil)
}

func (r *Record) Write(w io.Writer) error {
	var inlined [5]byte // inline buffer for variable length integers
	buf := inlined[:]

	n, err := w.Write(r.author)
	if err != nil {
		return err
	}
	n, err = w.Write(r.sign)
	if err != nil {
		return err
	}
	n = binary.PutUvarint(buf, uint64(len(r.deps)))
	n, err = w.Write(buf[:n])
	if err != nil {
		return err
	}
	for _, d := range r.deps {
		n, err = w.Write(d)
		if err != nil {
			return err
		}
	}

	n = binary.PutUvarint(buf, uint64(len(r.data)))
	n, err = w.Write(buf[:n])
	if err != nil {
		return err
	}
	n, err = w.Write(r.data)
	if err != nil {
		return err
	}
	return nil
}

func ReadRecord(r *bufio.Reader) (*Record, error) {
	var inlined [ed25519.SignatureSize]byte
	buf := inlined[:]
	n, err := r.Read(buf[:ed25519.PublicKeySize])
	if err != nil || n != ed25519.PublicKeySize {
		return nil, err
	}
	var author []byte
	author = append(author, buf[:ed25519.PublicKeySize]...)
	n, err = r.Read(buf[:ed25519.SignatureSize])
	if err != nil || n != ed25519.SignatureSize {
		return nil, err
	}
	var sig []byte
	sig = append(sig, buf[:ed25519.SignatureSize]...)
	dl, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	deps := make([]ID, int(dl), int(dl))
	for i := 0; i < int(dl); i++ {
		n, err = r.Read(buf[:ed25519.PublicKeySize])
		if err != nil || n != ed25519.PublicKeySize {
			return nil, err
		}
		var parent ID
		parent = append(parent, buf[:ed25519.PublicKeySize]...)
		deps[i] = parent
	}
	dl, err = binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(dl), int(dl))
	n, err = r.Read(data)
	if err != nil || n != int(dl) {
		return nil, err
	}
	p := &Record{
		id:     nil,
		author: author,
		sign:   sig,
		deps:   deps,
		data:   data,
	}
	p.id = p.hash() // hash was not serialized, we can infer it from content
	if err = p.Verify(); err != nil {
		return nil, err
	}
	return p, nil
}
