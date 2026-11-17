package device

import (
	"encoding/binary"
	"syscall"
)

// physical is the memory of the machine: hw.memsize, eight bytes that the
// call returns without the zero bytes they end in.
func physical() (uint64, bool) {
	raw, err := syscall.Sysctl("hw.memsize")
	if err != nil || len(raw) > 8 {
		return 0, false
	}
	var value [8]byte
	copy(value[:], raw)
	return binary.LittleEndian.Uint64(value[:]), true
}
