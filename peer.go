package bec

import (
	"crypto/ed25519"
)

const (
	BloomBitsPerEntry = 10
	BloomHashes       = 7
)

type Peer struct {
	pub         ed25519.PublicKey  // Peer's public key, equals to Author
	priv        ed25519.PrivateKey // Peer's private key, used for verification
	heads       []ID               // the "youngest" (logically) records. All newly created records on this peer will refer to heads as their deps.
	store       *MemStore          // Store where records are stored
	stash       *Stash             // Stash used as a temporary container for records which are being resolved
	missingDeps map[ID]struct{}    // "known" missing deps preventing records from stash to be integrated into store
}

// NewPeer returns a peer instance representing current peer.
func NewPeer(pub ed25519.PublicKey, priv ed25519.PrivateKey, store *MemStore) *Peer {
	return &Peer{
		pub:         pub,
		priv:        priv,
		heads:       store.Heads(),
		store:       store,
		missingDeps: make(map[ID]struct{}),
		stash:       NewStash(),
	}
}

func (p *Peer) Author() AuthorId {
	return NewAuthorId(p.pub)
}

func (p *Peer) Heads() []ID {
	return p.heads
}

func (p *Peer) Commit(data []byte) (*Record, error) {
	c := NewRecord(p.pub, p.priv, p.heads, data)
	err := p.store.Commit(c)
	if err != nil {
		return nil, err
	}
	// since newly created patch is the latest one dependent on
	// the previous heads, it becomes the new head
	p.heads = []ID{c.id}
	return c, err
}

// Integrate records into current peer. Patches are expected to be listed in their causal order.
// If Record has some unsatisfied dependencies, it will be stashed instead.
func (p *Peer) Integrate(rs []*Record) error {
	changed := false
	for _, r := range rs {
		if err := r.Verify(); err != nil {
			return err // remote patch was forged
		}
		if p.store.Contains(r.id) || p.stash.Contains(r.id) {
			continue // already seen in either log or stash
		}

		// check if dependencies are satisfied
		var missingDeps []ID
		for _, dep := range r.deps {
			if !p.store.Contains(dep) {
				if !p.stash.Contains(dep) {
					missingDeps = append(missingDeps, dep)
				}
			}
		}

		if len(missingDeps) > 0 {
			p.stash.Add(r)
			for _, dep := range missingDeps {
				p.missingDeps[dep] = struct{}{}
			}
		} else {
			if err := p.store.Commit(r); err != nil {
				return err
			}
			delete(p.missingDeps, r.id)
			changed = true
		}
	}
	if changed {
		p.heads = p.store.Heads()
		// try to reintegrate stashed elements
		rs = p.stash.UnStash()
		if len(rs) != 0 {
			return p.Integrate(rs) // can we hope for tail recursion here?
		}
	}
	return nil
}

// MissingDeps returns a list of known missing records that prevent applying records from stash to be put into the store.
func (p *Peer) MissingDeps() []ID {
	var res []ID
	for dep := range p.missingDeps {
		res = append(res, dep)
	}
	return res
}

func (p *Peer) Announce() []ID {
	if p.stash == nil {
		p.stash = NewStash()
	}
	return p.heads
}

func (p *Peer) Request(ids []ID) []*Record {
	return p.store.GetMany(ids)
}

// NotFound filters out incoming ids, returning the ones from input slice that have not been found in current Peer.
func (p *Peer) NotFound(ids []ID) []ID {
	var res []ID
	for _, id := range ids {
		if !p.store.Contains(id) && !p.stash.Contains(id) {
			res = append(res, id)
		}
	}
	return res
}

// Grant moderation permission over a collection with given name to a provided mod.
func (p *Peer) Grant(name string, mod AuthorId) error {
	panic("todo")
}

// Revoke moderation permission over a collection with given name from a provided mod.
func (p *Peer) Revoke(name string, mod AuthorId) error {
	panic("todo")
}

const (
	MsgAnnounce = iota
	MsgRequest
	MsgRecords
)

type PeerController struct {
	in   chan []byte
	out  map[string]chan<- []byte
	peer *Peer
}

func NewController(p *Peer) *PeerController {
	return &PeerController{
		in:   make(chan []byte),
		out:  make(map[string]chan<- []byte),
		peer: p,
	}
}

func (c *PeerController) Process() error {
	for {
		select {
		case msg := <-c.in:
			switch msg[0] {
			case MsgAnnounce:
				// heads []ID := parse(msg)
				// ids := peer.NotFound(heads)
				// sender <- MsgRequest(ids)
			case MsgRequest:
				// ids []ID := parse(msg)
				// records := peer.store.GetMany(pids)
				// sender <- MsgRecords(records)
			case MsgRecords:
				// records []*Record := parse(msg)
				// peer.Integrate(records)
				// ids := peer.MissingDeps()
				// if len(ids) > 0:
				//     sender <- MsgRequest(ids)
			}
		}
	}
}
