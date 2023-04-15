package bec

import (
	"fmt"
)

var (
	// AlreadyCommittedError happens when duplicate Record has been sent to Store.Commit
	AlreadyCommittedError = fmt.Errorf("provided record has been already comitted")

	// DependencyNotFoundError happens when Record was committed to the store which was missing one or more of its dependencies.
	DependencyNotFoundError = fmt.Errorf("parent record not found")
)

type MemStore struct {
	log        []*Record  // ever-growing log of records, every new Commit is appended to the end and never deleted
	index      map[ID]int // index of patch.id to its location in the log
	childrenOf [][]int    // a list from parent Record to its children descendants, by their log index position. Indexes of childrenOf match indexes of log
}

// NewMemStore returns a new empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		log:        []*Record{},
		index:      make(map[ID]int),
		childrenOf: [][]int{},
	}
}

// Get returns a Record identified by provided id. Returns nil if no Record with given id was found.
func (ms *MemStore) Get(id ID) *Record {
	i, found := ms.index[id]
	if !found {
		return nil
	}
	return ms.log[i]
}

// GetMany returns a slice of records matching provided sequence of ids.
// If a ID from provided input has not been found, it will be omitted from the result slice.
func (ms *MemStore) GetMany(ids []ID) []*Record {
	res := make([]*Record, 0, len(ids))
	for _, id := range ids {
		i := ms.index[id]
		res = append(res, ms.log[i])
	}
	return res
}

// LatestN is a paging function, which returns the `take` latest integrated records, skiping the `skip` amount of them.
func (ms *MemStore) LatestN(skip int, take int) []*Record {
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

// Heads recovers the most recent records that can serve as anchors for newly created records.
func (ms *MemStore) Heads() []ID {
	var res []ID
	for i, children := range ms.childrenOf {
		if children == nil || len(children) == 0 {
			// this Record has no children => it must be a head
			res = append(res, ms.log[i].id)
		}
	}

	return res
}

func (ms *MemStore) indexes(heads []ID) []int {
	is := make([]int, 0, len(heads))
	for _, h := range heads {
		if i, found := ms.index[h]; found {
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

// Traverses over the records of heads and their predecessors, executing given function f with patch
// index location in MemStore.log and patch itself. Returns a Bitmap which is a filter describing all visited records.
func (ms *MemStore) predecessorsF(heads []ID, f func(int, *Record)) Bitmap {
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

func (ms *MemStore) Predecessors(heads []ID) []*Record {
	var res []*Record
	ms.predecessorsF(heads, func(i int, p *Record) {
		res = append(res, p)
	})
	return res
}

// Missing returns a list of records that are successors or concurrent to given heads.
func (ms *MemStore) Missing(heads []ID) []*Record {
	v := ms.predecessorsF(heads, func(i int, r *Record) {
		/* do nothing */
	})
	var res []*Record
	for i, p := range ms.log {
		if !v.Get(i) {
			res = append(res, p)
		}
	}
	return res
}

func (ms *MemStore) Commit(p *Record) error {
	if err := p.Verify(); err != nil {
		return err // invalid patch trying to be committed
	}
	if _, found := ms.index[p.id]; found {
		return AlreadyCommittedError
	}
	for _, dep := range p.deps {
		if _, found := ms.index[dep]; !found {
			return DependencyNotFoundError
		}
	}
	i := len(ms.log)
	ms.log = append(ms.log, p)
	ms.childrenOf = append(ms.childrenOf, nil)
	ms.index[p.id] = i
	for _, dep := range p.deps {
		pi := ms.index[dep]
		ms.childrenOf[pi] = append(ms.childrenOf[pi], i)
	}
	return nil
}

func (ms *MemStore) Contains(id ID) bool {
	_, ok := ms.index[id]
	return ok
}

type Stash struct {
	log   []*Record
	index map[ID]int
}

func NewStash() *Stash {
	return &Stash{
		log:   []*Record{},
		index: make(map[ID]int),
	}
}

func (s *Stash) Add(p *Record) {
	if _, found := s.index[p.id]; found {
		return
	}
	i := len(s.log)
	s.log = append(s.log, p)
	s.index[p.id] = i
}

func (s *Stash) Contains(id ID) bool {
	_, ok := s.index[id]
	return ok
}

// UnStash returns all logs and clears up current Stash.
func (s *Stash) UnStash() []*Record {
	res := s.log
	// reverse the log order
	for i := 0; i < len(res)/2; i++ {
		j := len(res) - 1 - i
		res[i], res[j] = res[j], res[i]
	}
	s.log = []*Record{}
	s.index = make(map[ID]int)
	return res
}
