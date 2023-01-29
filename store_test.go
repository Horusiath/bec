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
func testPatches(pub ed25519.PublicKey, priv ed25519.PrivateKey) []*Patch {
	a := NewPatch(pub, priv, []ID{}, []byte("A"))
	b := NewPatch(pub, priv, []ID{a.id}, []byte("B"))
	c := NewPatch(pub, priv, []ID{a.id}, []byte("C"))
	d := NewPatch(pub, priv, []ID{b.id}, []byte("D"))
	e := NewPatch(pub, priv, []ID{b.id, c.id}, []byte("E"))
	f := NewPatch(pub, priv, []ID{e.id}, []byte("F"))

	return []*Patch{
		a, b, c, d, e, f,
	}
}

func TestMemStoreCommitGet(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	for _, p := range patches {
		o := ms.Get(p.id)
		if o != p {
			t.Fatalf("commit/get patches don't match")
		}
	}
}

func TestMemStoreCommitMissingDependency(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	patches := testPatches(pub, priv)
	const Removed = 4
	patches = append(patches[:Removed], patches[Removed+1:]...)

	for i, p := range patches {
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
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}

	// first page - shifted by 1
	res := ms.LatestN(1, 2)
	if len(res) != 2 {
		t.Fatalf("returned result length doesn't match")
	}
	if res[0] != patches[3] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[1] != patches[4] {
		t.Fatalf("returned first element of the page doesn't match")
	}

	// second page - shifted by 3
	res = ms.LatestN(3, 3)
	if len(res) != 3 {
		t.Fatalf("returned result length doesn't match")
	}
	if res[0] != patches[0] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[1] != patches[1] {
		t.Fatalf("returned first element of the page doesn't match")
	}
	if res[2] != patches[2] {
		t.Fatalf("returned first element of the page doesn't match")
	}
}

func TestMemStorePredecessors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf(err.Error())
	}
	ms := NewMemStore()
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{patches[4].id}
	missing := ms.Predecessors(heads)
	expect := []*Patch{
		patches[4],
		patches[1],
		patches[2],
		patches[0],
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
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{patches[4].id, patches[3].id}
	missing := ms.Predecessors(heads)
	expect := []*Patch{
		patches[4],
		patches[3],
		patches[1],
		patches[2],
		patches[0],
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
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{patches[4].id}
	missing := ms.Missing(heads)
	expect := []*Patch{
		patches[3],
		patches[5],
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
	patches := testPatches(pub, priv)
	for _, p := range patches {
		if err := ms.Commit(p); err != nil {
			t.Fatalf(err.Error())
		}
	}
	heads := []ID{patches[1].id, patches[2].id}
	missing := ms.Missing(heads)
	expect := []*Patch{
		patches[3],
		patches[4],
		patches[5],
	}
	for i, a := range missing {
		b := expect[i]
		if a != b {
			t.Fatalf("expected %s, found %s", hex.EncodeToString(b.id), hex.EncodeToString(a.id))
		}
	}
}
