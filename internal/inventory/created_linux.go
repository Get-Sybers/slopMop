//go:build linux && (amd64 || arm64)

package inventory

import (
	"encoding/binary"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// What statx(2) of linux/stat.h is called with, and where its answer keeps
// the fields that are read.
const (
	atEmptyPath  = 0x1000
	statxBtime   = 0x800
	statxSize    = 256
	maskOffset   = 0
	btimeSeconds = 80
	btimeNanos   = 88
)

// statxNumber is the number of statx(2), which the syscall package lacks.
func statxNumber() uintptr {
	if runtime.GOARCH == "arm64" {
		return 291
	}
	return 332
}

// created is when a file was made, where its file system records it. Stat
// does not give it on Linux; statx does, on the handle that is already open.
func created(h *os.File, _ fs.FileInfo) time.Time {
	conn, err := h.SyscallConn()
	if err != nil {
		return time.Time{}
	}
	var answer [statxSize]byte
	var empty [1]byte
	var failed syscall.Errno
	err = conn.Control(func(fd uintptr) {
		//nolint:gosec // G103: statx reads a path and fills a buffer, and both are arrays of this function.
		_, _, failed = syscall.Syscall6(statxNumber(), fd, uintptr(unsafe.Pointer(&empty[0])), atEmptyPath,
			statxBtime, uintptr(unsafe.Pointer(&answer[0])), 0)
	})
	if err != nil || failed != 0 || binary.NativeEndian.Uint32(answer[maskOffset:])&statxBtime == 0 {
		return time.Time{}
	}
	seconds := int64(binary.NativeEndian.Uint64(answer[btimeSeconds:])) //nolint:gosec // G115: the kernel writes a signed count of seconds here.
	if seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, int64(binary.NativeEndian.Uint32(answer[btimeNanos:]))).UTC()
}
