package bec

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestReconcileV1(t *testing.T) {
	testReconcile(t, reconcileV1)
}

func testReconcile(t *testing.T, reconcile func(src *Peer, dst *Peer) error) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("P1 failed to generate key: %s", err.Error())
	}
	p1 := NewPeer(pub1, priv1, NewPOLog())

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("P2 failed to generate key: %s", err.Error())
	}
	p2 := NewPeer(pub2, priv2, NewPOLog())

	records := testRecords(p1.pub, p1.priv)
	if err = p1.Integrate(records); err != nil {
		t.Fatalf("P1 failed to integrate init records: %s", err.Error())
	}
	if err = p2.Integrate(records); err != nil {
		t.Fatalf("P2 failed to integrate init records: %s", err.Error())
	}
	if _, err = p1.Commit([]byte("G")); err != nil {
		t.Fatalf("P1 failed to commit 'G': %s", err.Error())
	}
	if _, err = p2.Commit([]byte("H")); err != nil {
		t.Fatalf("P2 failed to commit 'H': %s", err.Error())
	}
	if _, err = p2.Commit([]byte("I")); err != nil {
		t.Fatalf("P2 failed to commit 'I': %s", err.Error())
	}
	if err = reconcile(p1, p2); err != nil {
		t.Fatalf("Reconcile P1->P2 failed: %s", err.Error())
	}
	if err = reconcile(p2, p1); err != nil {
		t.Fatalf("Reconcile P2->P1 failed: %s", err.Error())
	}

	compareStores(p1.store, p2.store, t)
}

func compareStores(s1 *POLog, s2 *POLog, t *testing.T) {
	k1 := make(map[ID]struct{})
	for k := range s1.index {
		k1[k] = struct{}{}
	}
	k2 := make(map[ID]struct{})
	for k := range s2.index {
		k2[k] = struct{}{}
	}
	if len(k1) != len(k2) {
		t.Fatal("stores have different size")
	}
	for k := range k1 {
		if _, ok := k2[k]; !ok {
			t.Fatalf("hash from k1 not found int k2: %s", k)
		}
	}
	for k := range k2 {
		if _, ok := k1[k]; !ok {
			t.Fatalf("hash from k2 not found int k1: %s", k)
		}
	}
}

func reconcileV1(src *Peer, dst *Peer) error {
	heads := src.Announce()        // A sends its own most recent PIDs
	missing := dst.NotFound(heads) // B filters out which of the A's head PIDs were unknown of it
	for len(missing) > 0 {         // until all missing records are found
		records := src.Request(missing) // send request to A asking for missing PIDs
		err := dst.Integrate(records)   // B tries to integrate A's records
		if err != nil {
			return err
		}
		missing = dst.MissingDeps() // B recalculates missing records
	}
	return nil
}
