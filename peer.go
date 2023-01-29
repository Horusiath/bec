package bec

import (
	"crypto/ed25519"
	"encoding/hex"
)

const (
	BloomBitsPerEntry = 10
	BloomHashes       = 7
)

type Peer struct {
	pub         ed25519.PublicKey   // Peer's public key, equals to Author
	priv        ed25519.PrivateKey  // Peer's private key, used for verification
	heads       []ID                // the "youngest" (logically) patches. All newly created patches on this peer will refer to heads as their deps.
	store       *MemStore           // Store where patches are stored
	stash       *Stash              // Stash used as a temporary container for patches which are being resolved
	missingDeps map[string]struct{} // "known" missing deps preventing patches from stash to be integrated into store
}

// NewPeer returns a peer instance representing current peer.
func NewPeer(pub ed25519.PublicKey, priv ed25519.PrivateKey, store *MemStore) *Peer {
	return &Peer{
		pub:         pub,
		priv:        priv,
		heads:       store.Heads(),
		store:       store,
		missingDeps: make(map[string]struct{}),
		stash:       NewStash(),
	}
}

func (p *Peer) Author() AuthorId {
	return p.pub
}

func (p *Peer) Heads() []ID {
	return p.heads
}

func (p *Peer) Commit(data []byte) (*Patch, error) {
	c := NewPatch(p.pub, p.priv, p.heads, data)
	err := p.store.Commit(c)
	if err != nil {
		return nil, err
	}
	// since newly created patch is the latest one dependent on
	// the previous heads, it becomes the new head
	p.heads = []ID{c.id}
	return c, err
}

// Integrate patches into current peer. Patches are expected to be listed in their causal order.
// If Patch has some unsatisfied dependencies, it will be stashed instead.
func (p *Peer) Integrate(patches []*Patch) error {
	changed := false
	for _, u := range patches {
		if err := u.Verify(); err != nil {
			return err // remote patch was forged
		}
		if p.store.Contains(u.id) || p.stash.Contains(u.id) {
			continue // already seen in either log or stash
		}

		// check if dependencies are satisfied
		var missingDeps []ID
		for _, dep := range u.deps {
			if !p.store.Contains(dep) {
				if !p.stash.Contains(dep) {
					missingDeps = append(missingDeps, dep)
				}
			}
		}

		if len(missingDeps) > 0 {
			p.stash.Add(u)
			for _, d := range missingDeps {
				p.missingDeps[hex.EncodeToString(d)] = struct{}{}
			}
		} else {
			if err := p.store.Commit(u); err != nil {
				return err
			}
			delete(p.missingDeps, hex.EncodeToString(u.id))
			changed = true
		}
	}
	if changed {
		p.heads = p.store.Heads()
		// try to reintegrate stashed elements
		patches = p.stash.UnStash()
		if len(patches) != 0 {
			return p.Integrate(patches) // can we hope for tail recursion here?
		}
	}
	return nil
}

// MissingDeps returns a list of known missing patches that prevent applying patches from stash to be put into the store.
func (p *Peer) MissingDeps() []ID {
	var res []ID
	for dep := range p.missingDeps {
		pid, _ := hex.DecodeString(dep)
		res = append(res, pid)
	}
	return res
}

func (p *Peer) Announce() []ID {
	if p.stash == nil {
		p.stash = NewStash()
	}
	return p.heads
}

func (p *Peer) Request(ids []ID) []*Patch {
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

const (
	MsgAnnounce = iota
	MsgRequest
	MsgPatches
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
				// patches := peer.store.GetMany(pids)
				// sender <- MsgPatches(patches)
			case MsgPatches:
				// patches []*Patch := parse(msg)
				// peer.Integrate(patches)
				// ids := peer.MissingDeps()
				// if len(ids) > 0:
				//     sender <- MsgRequest(ids)
			}
		}
	}
}
