package inventory

import (
	"io/fs"
	"os"
	"syscall"
	"time"
)

// created is when a file was made, as its volume records it.
func created(_ *os.File, info fs.FileInfo) time.Time {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || d.CreationTime == (syscall.Filetime{}) {
		return time.Time{}
	}
	return time.Unix(0, d.CreationTime.Nanoseconds()).UTC()
}
