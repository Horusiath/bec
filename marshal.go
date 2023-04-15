package bec

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"io"
)

func (r *Record) Write(w io.Writer) error {
	var inlined [5]byte // inline buffer for variable length integers
	buf := inlined[:]

	n, err := w.Write(r.author[:])
	if err != nil {
		return err
	}
	n, err = w.Write(r.sign)
	if err != nil {
		return err
	}
	err = WriteIDs(r.deps, w)
	if err != nil {
		return err
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
	var author AuthorId
	copy(author[:], buf[:ed25519.PublicKeySize])
	n, err = r.Read(buf[:ed25519.SignatureSize])
	if err != nil || n != ed25519.SignatureSize {
		return nil, err
	}
	var sig []byte
	sig = append(sig, buf[:ed25519.SignatureSize]...)
	deps, err := ReadIDs(r)
	if err != nil {
		return nil, err
	}
	dl, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(dl), int(dl))
	n, err = r.Read(data)
	if err != nil || n != int(dl) {
		return nil, err
	}
	p := &Record{
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

func WriteRecords(rs []*Record, w io.Writer) error {
	var inlined [5]byte // inline buffer for variable length integers
	buf := inlined[:]
	n := binary.PutUvarint(buf, uint64(len(rs)))
	n, err := w.Write(buf[:n])
	if err != nil {
		return err
	}
	for _, r := range rs {
		err = r.Write(w)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadRecords(r *bufio.Reader) ([]*Record, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	res := make([]*Record, int(n), int(n))
	for i := 0; i < int(n); i++ {
		r, err := ReadRecord(r)
		if err != nil {
			return nil, err
		}
		res[i] = r
	}

	return res, nil
}

func WriteIDs(ids []ID, w io.Writer) error {
	var inlined [5]byte // inline buffer for variable length integers
	buf := inlined[:]

	n := binary.PutUvarint(buf, uint64(len(ids)))
	n, err := w.Write(buf[:n])
	if err != nil {
		return err
	}
	for _, d := range ids {
		n, err = w.Write(d[:])
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadIDs(r *bufio.Reader) ([]ID, error) {
	var inlined [ed25519.PublicKeySize]byte
	buf := inlined[:]

	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	res := make([]ID, int(n), int(n))
	for i := 0; i < int(n); i++ {
		read, err := r.Read(buf[:ed25519.PublicKeySize])
		if err != nil || read != ed25519.PublicKeySize {
			return nil, err
		}
		copy(res[i][:], buf[:ed25519.PublicKeySize])
	}

	return res, nil
}
