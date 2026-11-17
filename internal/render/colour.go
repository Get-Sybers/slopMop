package render

import (
	"io"
	"os"
	"runtime"
)

// noColour is the environment variable that turns colour off wherever it is set.
const noColour = "NO_COLOR" //nolint:misspell // the variable is spelled so

// TakesColour reports whether w is a terminal that takes ANSI colours. The
// variable above and a dumb terminal turn them off; on Windows only Windows
// Terminal is trusted to read them.
func TakesColour(w io.Writer) bool {
	f, isFile := w.(*os.File)
	if !isFile || os.Getenv(noColour) != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
