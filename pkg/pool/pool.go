package pool

import (
	"errors"
	"sync"
)

// Pool is ...
var Pool *Allocator = NewAllocator()

type lazySlice struct {
	Pointer *[]byte
}

// Allocator for incoming frames, optimized to prevent overwriting after zeroing
type Allocator struct {
	buffers []sync.Pool
}

// NewAllocator initiates a []byte allocator for frames less than 65536 bytes,
// the waste(memory fragmentation) of space allocation is guaranteed to be
// no more than 50%.
func NewAllocator() *Allocator {
	alloc := new(Allocator)
	alloc.buffers = make([]sync.Pool, 17) // 1B -> 64K
	for k := range alloc.buffers {
		i := k
		alloc.buffers[k].New = func() interface{} {
			b := make([]byte, 1<<uint32(i))
			// Return a *[]byte instead of []byte ensures that
			// the []byte is not copied, which would cause a heap
			// allocation on every call to sync.pool.Pool.Put
			return &b
		}
	}
	return alloc
}

// Get a []byte from pool with most appropriate cap
func (alloc *Allocator) Get(size int) (lazySlice, []byte) {
	if size <= 0 || size > 65536 {
		return lazySlice{}, nil
	}

	bits := msb(size)
	if size == 1<<bits {
		p := alloc.buffers[bits].Get().(*[]byte)
		return lazySlice{Pointer: p}, *p
	} else {
		p := alloc.buffers[bits+1].Get().(*[]byte)
		return lazySlice{Pointer: p}, *p
	}
}

// Put returns a []byte to pool for future use,
// which the cap must be exactly 2^n
func (alloc *Allocator) Put(s lazySlice) error {
	buf := *s.Pointer
	bits := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > 65536 || cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}
	alloc.buffers[bits].Put(s.Pointer)
	return nil
}

// msb return the pos of most significiant bit
// http://supertech.csail.mit.edu/papers/debruijn.pdf
func msb(size int) byte {
	// var debruijinPos = [...]byte{0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31}
	const debruijinPos = "\x00\x09\x01\x0a\x0d\x15\x02\x1d\x0b\x0e\x10\x12\x16\x19\x03\x1e\x08\x0c\x14\x1c\x0f\x11\x18\x07\x13\x1b\x17\x06\x1a\x05\x04\x1f"
	v := uint32(size)
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	return debruijinPos[(v*0x07C4ACDD)>>27]
}
