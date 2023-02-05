package bec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

/*
	     / B - D
		A    \
		 \ C - E - F
*/
func testRecords(pub ed25519.PublicKey, priv ed25519.PrivateKey) []*Record {
	a := NewRecord(pub, priv, []ID{}, []byte("A"))
	b := NewRecord(pub, priv, []ID{a.id}, []byte("B"))
	c := NewRecord(pub, priv, []ID{a.id}, []byte("C"))
	d := NewRecord(pub, priv, []ID{b.id}, []byte("D"))
	e := NewRecord(pub, priv, []ID{b.id, c.id}, []byte("E"))
	f := NewRecord(pub, priv, []ID{e.id}, []byte("F"))

	return []*Record{
		a, b, c, d, e, f,
	}
}

func TestMemStoreCommitGet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	for _, p := range records {
		o := ms.Get(p.id)
		if o != p {
			t.Fatalf("commit/get records don't match")
		}
	}
}

func TestMemStoreCommitMissingDependency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	const Removed = 4
	records = append(records[:Removed], records[Removed+1:]...)

	for i, p := range records {
		err := ms.Commit(p)
		if i == Removed && err == DependencyNotFoundError {
			break
		} else if err != nil {
			t.Fatalf(err.Error())
		}
	}
}

func TestMemStorePagination(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}

	// first page - shifted by 1
	res := ms.LatestN(1, 2)
	if len(res) != 2 {
		t.Fatalf("returned result length doesn't match")
	}
	if res[0] != records[3] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[1] != records[4] {
		t.Fatalf("returned first element of the page doesn't match")
	}

	// second page - shifted by 3
	res = ms.LatestN(3, 3)
	if len(res) != 3 {
		t.Fatalf("returned result length doesn't match")
	}
	if res[0] != records[0] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[1] != records[1] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[2] != records[2] {
		t.Fatalf("returned first element of the page doesn't match")
	}
}

func TestMemStorePredecessors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{records[4].id}
	missing := ms.Predecessors(heads)
	expect := []*Record{
		records[4],
		records[1],
		records[2],
		records[0],
	}
	for i, a := range missing {
		b := expect[i]
		if a != b {
			t.Fatalf("expected %s, found %s", hex.EncodeToString(b.id), hex.EncodeToString(a.id))
		}
	}
}

func TestMemStorePredecessorsMultiHeads(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{records[4].id, records[3].id}
	missing := ms.Predecessors(heads)
	expect := []*Record{
		records[4],
		records[3],
		records[1],
		records[2],
		records[0],
	}
	for i, a := range missing {
		b := expect[i]
		if a != b {
			t.Fatalf("expected %s, found %s", hex.EncodeToString(b.id), hex.EncodeToString(a.id))
		}
	}
}

func TestMemStoreMissing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{records[4].id}
	missing := ms.Missing(heads)
	expect := []*Record{
		records[3],
		records[5],
	}
	for i, a := range missing {
		b := expect[i]
		if a != b {
			t.Fatalf("expected %s, found %s", hex.EncodeToString(b.id), hex.EncodeToString(a.id))
		}
	}
}

func TestMemStoreMissingMultiHeads(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	records := testRecords(pub, priv)
	for _, p := range records {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{records[1].id, records[2].id}
	missing := ms.Missing(heads)
	expect := []*Record{
		records[3],
		records[4],
		records[5],
	}
	for i, a := range missing {
		b := expect[i]
		if a != b {
			t.Fatalf("expected %s, found %s", hex.EncodeToString(b.id), hex.EncodeToString(a.id))
		}
	}
}
