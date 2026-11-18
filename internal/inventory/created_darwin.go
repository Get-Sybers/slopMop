package inventory

import (
	"io/fs"
	"os"
	"syscall"
	"time"
)

// created is when a file was made, as its volume records it.
func created(_ *os.File, info fs.FileInfo) time.Time {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Birthtimespec.Sec <= 0 {
		return time.Time{}
	}
	return time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec).UTC()
}
