package bec

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"math"
	"strings"
)

type Bitmap []byte

func NewBitmap(n int) Bitmap {
	i := n / 8
	if n%8 != 0 {
		i++
	}
	return make([]byte, i)
}

func (b Bitmap) Set(i int, value bool) {
	n := i / 8
	r := i % 8
	if value {
		b[n] |= 1 << r
	} else {
		b[n] &= ^(1 << r)
	}
}

func (b Bitmap) Get(i int) bool {
	n := i / 8
	r := i % 8
	v := b[n] & (1 << r)
	return v != 0
}

func (b Bitmap) Len() int {
	return len(b) * 8
}

func (b Bitmap) String() string {
	var sb strings.Builder
	for _, a := range b {
		fmt.Fprintf(&sb, "%08b", a)
	}
	return sb.String()
}

func (b Bitmap) Equals(o Bitmap) bool {
	if len(b) != len(o) {
		return false
	}
	return bytes.Compare(b, o) == 0
}

func (b Bitmap) AddBloom(id ID, hashes int) {
	c := append(id, 0)
	l := b.Len()
	for i := 0; i < hashes; i++ {
		h := crc32.ChecksumIEEE(c) & math.MaxInt32
		b.Set(int(h)%l, true)
		c[l] = byte(i)
	}
}
