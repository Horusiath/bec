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

// ID is a unique Patch identifier. Generated as a consistent hash of that Patch contents.
type ID = []byte

// AuthorId is a unique identifier of an author who produced given Patch.
type AuthorId = ed25519.PublicKey

type Patch struct {
	id     ID       // globally unique content addressed SHA256 hash of current Patch
	author AuthorId // creator of current Patch
	sign   []byte   // signature used by an author used for Patch verification
	deps   []ID     // dependencies: hashes of direct predecessor patches of this Patch
	data   []byte   // user data
}

func NewPatch(pub ed25519.PublicKey, priv ed25519.PrivateKey, deps []ID, data []byte) *Patch {
	p := &Patch{
		data:   data,
		deps:   deps,
		author: pub,
	}
	p.id = p.hash()
	p.sign = ed25519.Sign(priv, p.data) // could we just sign p.id? It's probably smaller and unique as well.
	return p
}

func (p *Patch) Verify() error {
	if bytes.Compare(p.hash(), p.id) != 0 {
		return fmt.Errorf("patch hash and id don't match: %s", hex.EncodeToString(p.id))
	}
	if !ed25519.Verify(p.author, p.data, p.sign) {
		return fmt.Errorf("patch signature verficiation failed: %s", hex.EncodeToString(p.id))
	}
	return nil
}

// Returns a content addressable hash of a given Patch.
func (p *Patch) hash() ID {
	h := sha256.New()
	for _, d := range p.deps {
		h.Write(d)
	}
	h.Write(p.data)
	h.Write(p.author)
	return h.Sum(nil)
}

func (p *Patch) Write(w io.Writer) error {
	var inlined [5]byte // inline buffer for variable length integers
	buf := inlined[:]

	n, err := w.Write(p.author)
	if err != nil {
		return err
	}
	n, err = w.Write(p.sign)
	if err != nil {
		return err
	}
	n = binary.PutUvarint(buf, uint64(len(p.deps)))
	n, err = w.Write(buf[:n])
	if err != nil {
		return err
	}
	for _, d := range p.deps {
		n, err = w.Write(d)
		if err != nil {
			return err
		}
	}

	n = binary.PutUvarint(buf, uint64(len(p.data)))
	n, err = w.Write(buf[:n])
	if err != nil {
		return err
	}
	n, err = w.Write(p.data)
	if err != nil {
		return err
	}
	return nil
}

func ReadPatch(r *bufio.Reader) (*Patch, error) {
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
	p := &Patch{
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
