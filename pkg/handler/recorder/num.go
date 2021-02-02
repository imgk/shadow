package recorder

import (
	"strconv"
)

// ByteNum is ...
type ByteNum uint64

// String is ...
func (n ByteNum) String() (str string) {
	const mask = (^uint64(0)) >> (64 - 10)

	str = ""
	for _, unit := range []string{" B", " K, ", " M, ", " G, ", " T, "} {
		if n > 0 {
			str = strconv.FormatUint(uint64(n)&mask, 10) + unit + str
			n = n >> 10
			continue
		}
		if str == "" {
			str = "0 B"
		}
	}

	return
}
