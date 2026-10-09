// Copyright 2026 The Gosleigh Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import "sort"

// chunkList is a sorted sequence kept as a list of chunks, so an insertion
// or removal moves at most one chunk instead of the whole sequence. C++
// keeps these orders in std::set / std::map; a flat sorted slice made every
// insert and remove O(n), which dominated large functions (tens of
// thousands of Varnodes and ops, each created, re-keyed and destroyed
// several times).
type chunkList[T comparable] struct {
	chunks [][]T
	n      int
}

// vnList is the Varnode location order of a VarnodeBank.
type vnList = chunkList[*Varnode]

const vnChunkMax = 512

// vnPos is a position in a chunkList: chunk ci, element i within it.
type vnPos struct{ ci, i int }

func (l *chunkList[T]) Len() int { return l.n }

// search is the first position whose element satisfies pred, which must
// be false then true along the sequence (sort.Search semantics).
func (l *chunkList[T]) search(pred func(T) bool) vnPos {
	ci := sort.Search(len(l.chunks), func(c int) bool {
		ch := l.chunks[c]
		return pred(ch[len(ch)-1])
	})
	if ci == len(l.chunks) {
		return vnPos{ci, 0}
	}
	ch := l.chunks[ci]
	return vnPos{ci, sort.Search(len(ch), func(i int) bool { return pred(ch[i]) })}
}

// at is the element at p, or the zero value past the end.
func (l *chunkList[T]) at(p vnPos) T {
	if p.ci >= len(l.chunks) {
		var zero T
		return zero
	}
	return l.chunks[p.ci][p.i]
}

// next is the position after p.
func (l *chunkList[T]) next(p vnPos) vnPos {
	p.i++
	if p.i >= len(l.chunks[p.ci]) {
		p.ci++
		p.i = 0
	}
	return p
}

// insertAt puts vn at position p, splitting a chunk that grows too big.
func (l *chunkList[T]) insertAt(p vnPos, vn T) {
	l.n++
	if len(l.chunks) == 0 {
		l.chunks = [][]T{{vn}}
		return
	}
	if p.ci == len(l.chunks) { // past the end: append to the last chunk
		p.ci--
		p.i = len(l.chunks[p.ci])
	}
	var zero T
	ch := append(l.chunks[p.ci], zero)
	copy(ch[p.i+1:], ch[p.i:])
	ch[p.i] = vn
	if len(ch) <= 2*vnChunkMax {
		l.chunks[p.ci] = ch
		return
	}
	tail := append([]T(nil), ch[vnChunkMax:]...)
	l.chunks[p.ci] = ch[:vnChunkMax:vnChunkMax]
	l.chunks = append(l.chunks, nil)
	copy(l.chunks[p.ci+2:], l.chunks[p.ci+1:])
	l.chunks[p.ci+1] = tail
}

// removeAt deletes the element at p, dropping a chunk left empty.
func (l *chunkList[T]) removeAt(p vnPos) {
	l.n--
	ch := l.chunks[p.ci]
	copy(ch[p.i:], ch[p.i+1:])
	var zero T
	ch[len(ch)-1] = zero
	ch = ch[:len(ch)-1]
	if len(ch) == 0 {
		l.chunks = append(l.chunks[:p.ci], l.chunks[p.ci+1:]...)
		return
	}
	l.chunks[p.ci] = ch
}

// all is every element in order.
func (l *chunkList[T]) all() []T {
	out := make([]T, 0, l.n)
	for _, ch := range l.chunks {
		out = append(out, ch...)
	}
	return out
}

func (l *chunkList[T]) clear() {
	l.chunks = nil
	l.n = 0
}
