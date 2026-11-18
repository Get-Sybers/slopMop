//go:build !windows && !darwin && !(linux && (amd64 || arm64))

package inventory

import (
	"io/fs"
	"os"
	"time"
)

// created is when a file was made. This system gives no way to read it.
func created(_ *os.File, _ fs.FileInfo) time.Time {
	return time.Time{}
}
