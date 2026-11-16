package render

import (
	"fmt"
	"strconv"
)

const (
	kibi           = 1024
	binaryPrefixes = "KMGTPE"
)

// humanise writes a byte count in binary units, rounded half up.
func humanise(n int64) string {
	if n < kibi {
		return strconv.FormatInt(n, 10) + " B"
	}
	u := uint64(n)
	unit, prefix := uint64(kibi), 0
	// A count that would round to 1,024 of a unit is written as 1.0 of the next.
	for prefix < len(binaryPrefixes)-1 && u >= kibi*unit-unit/2 {
		unit *= kibi
		prefix++
	}
	// Dividing before multiplying keeps the largest counts inside 64 bits.
	if tenths := u/unit*10 + (u%unit*10+unit/2)/unit; tenths < 100 {
		return fmt.Sprintf("%d.%d %ciB", tenths/10, tenths%10, binaryPrefixes[prefix])
	}
	return fmt.Sprintf("%d %ciB", (u+unit/2)/unit, binaryPrefixes[prefix])
}
