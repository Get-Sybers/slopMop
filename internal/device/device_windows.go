package device

import (
	"syscall"
	"unsafe"
)

// memoryStatus is MEMORYSTATUSEX, which GlobalMemoryStatusEx fills.
type memoryStatus struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// physical is the memory of the machine, as Windows reports it.
func physical() (uint64, bool) {
	var status memoryStatus
	status.length = uint32(unsafe.Sizeof(status))
	call := syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	if call.Find() != nil {
		return 0, false
	}
	done, _, _ := call.Call(uintptr(unsafe.Pointer(&status)))
	return status.totalPhys, done != 0
}
