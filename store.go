package bec

import (
	"encoding/hex"
	"fmt"
)

var (
	// AlreadyCommittedError happens when duplicate Patch has been sent to Store.Commit
	AlreadyCommittedError = fmt.Errorf("provided patch has been already comitted")

	// DependencyNotFoundError happens when Patch was committed to the store which was missing one or more of its dependencies.
	DependencyNotFoundError = fmt.Errorf("parent patch not found")
)

type MemStore struct {
	log        []*Patch       // ever-growing log of patches, every new Commit is appended to the end and never deleted
	index      map[string]int // index of patch.id to its location in the log
	childrenOf [][]int        // a list from parent Commit to its children descendants, by their log index position. Indexes of childrenOf match indexes of log
}

// NewMemStore returns a new empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		log:        []*Patch{},
		index:      make(map[string]int),
		childrenOf: [][]int{},
	}
}

// Get returns a Patch identified by provided id. Returns nil if no Patch with given id was found.
func (ms *MemStore) Get(id ID) *Patch {
	key := hex.EncodeToString(id)
	i, found := ms.index[key]
	if !found {
		return nil
	}
	return ms.log[i]
}

// GetMany returns a slice of patches matching provided sequence of ids.
// If a ID from provided input has not been found, it will be omitted from the result slice.
func (ms *MemStore) GetMany(ids []ID) []*Patch {
	res := make([]*Patch, 0, len(ids))
	for _, id := range ids {
		key := hex.EncodeToString(id)
		i := ms.index[key]
		res = append(res, ms.log[i])
	}
	return res
}

// LatestN is a paging function, which returns the `take` latest integrated patches, skiping the `skip` amount of them.
func (ms *MemStore) LatestN(skip int, take int) []*Patch {
	limit := len(ms.log)
	start := limit - skip - take
	if start < 0 {
		start = 0
	}
	end := limit - skip
	if end < 0 {
		return nil
	}
	res := ms.log[start:end]
	return res
}

// Heads recovers the most recent patches that can serve as anchors for newly created patches.
func (ms *MemStore) Heads() []ID {
	var res []ID
	for i, children := range ms.childrenOf {
		if children == nil || len(children) == 0 {
			// this Patch has no children => it must be a head
			res = append(res, ms.log[i].id)
		}
	}

	return res
}

func (ms *MemStore) indexes(heads []ID) []int {
	is := make([]int, 0, len(heads))
	for _, h := range heads {
		k := hex.EncodeToString(h)
		if i, found := ms.index[k]; found {
			is = append(is, i)
		}
	}
	return is
}

func pop(q *[]int) (int, bool) {
	d := *q
	i := len(d)
	if i == 0 {
		return 0, false
	} else {
		v := d[0]
		*q = d[1:]
		return v, true
	}
}

// Traverses over the patches of heads and their predecessors, executing given function f with patch
// index location in MemStore.log and patch itself. Returns a Bitmap which is a filter describing all visited patches.
func (ms *MemStore) predecessorsF(heads []ID, f func(int, *Patch)) Bitmap {
	q := ms.indexes(heads)
	visited := NewBitmap(len(ms.log))
	for {
		i, ok := pop(&q)
		if !ok {
			break // q is empty
		}
		// check if we haven't visited this patch already
		if !visited.Get(i) {
			visited.Set(i, true)
			p := ms.log[i]
			q = append(q, ms.indexes(p.deps)...) // append patch parents
			f(i, p)
		}
	}
	return visited
}

func (ms *MemStore) Predecessors(heads []ID) []*Patch {
	var res []*Patch
	ms.predecessorsF(heads, func(i int, p *Patch) {
		res = append(res, p)
	})
	return res
}

// Missing returns a list of patches that are successors or concurrent to given heads.
func (ms *MemStore) Missing(heads []ID) []*Patch {
	v := ms.predecessorsF(heads, func(i int, patch *Patch) {
		/* do nothing */
	})
	var res []*Patch
	for i, p := range ms.log {
		if !v.Get(i) {
			res = append(res, p)
		}
	}
	return res
}

func (ms *MemStore) Commit(p *Patch) error {
	if err := p.Verify(); err != nil {
		return err // invalid patch trying to be committed
	}
	cid := hex.EncodeToString(p.id)
	if _, found := ms.index[cid]; found {
		return AlreadyCommittedError
	}
	for _, d := range p.deps {
		k := hex.EncodeToString(d)
		if _, found := ms.index[k]; !found {
			return DependencyNotFoundError
		}
	}
	i := len(ms.log)
	ms.log = append(ms.log, p)
	ms.childrenOf = append(ms.childrenOf, nil)
	ms.index[cid] = i
	for _, d := range p.deps {
		k := hex.EncodeToString(d)
		pi := ms.index[k]
		ms.childrenOf[pi] = append(ms.childrenOf[pi], i)
	}
	return nil
}

func (ms *MemStore) Contains(id ID) bool {
	_, ok := ms.index[hex.EncodeToString(id)]
	return ok
}

type Stash struct {
	log   []*Patch
	index map[string]int
}

func NewStash() *Stash {
	return &Stash{
		log:   []*Patch{},
		index: make(map[string]int),
	}
}

func (s *Stash) Add(p *Patch) {
	id := hex.EncodeToString(p.id)
	if _, found := s.index[id]; found {
		return
	}
	i := len(s.log)
	s.log = append(s.log, p)
	s.index[id] = i
}

func (s *Stash) Contains(id ID) bool {
	_, ok := s.index[hex.EncodeToString(id)]
	return ok
}

// UnStash returns all logs and clears up current Stash.
func (s *Stash) UnStash() []*Patch {
	res := s.log
	// reverse the log order
	for i := 0; i < len(res)/2; i++ {
		j := len(res) - 1 - i
		res[i], res[j] = res[j], res[i]
	}
	s.log = []*Patch{}
	s.index = make(map[string]int)
	return res
}
