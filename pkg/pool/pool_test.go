package pool

import "testing"

func TestGet(t *testing.T) {
	Pool := NewAllocator()
	for k, v := range map[int]int{
		1:    1,
		2:    2,
		3:    4,
		4:    4,
		5:    8,
		6:    8,
		7:    8,
		8:    8,
		9:    16,
		31:   32,
		63:   64,
		65:   128,
		127:  128,
		129:  256,
		257:  512,
		513:  1024,
		1025: 2048,
		2049: 4096,
	} {
		sc, b := Pool.Get(k)
		if len(b) != v {
			t.Errorf("Pool.Get error, size: %v, length: %v", k, v)
		}
		Pool.Put(sc)
	}
}
