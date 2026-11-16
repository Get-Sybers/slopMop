// Command slopmop reads a folder of scripts an AI agent wrote and the outputs they produced.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/get-sybers/slopmop/internal/cli"
	"github.com/get-sybers/slopmop/internal/command"
	"github.com/get-sybers/slopmop/internal/render"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run maps the result to an exit code: 0 success, 1 failure, 2 usage error.
func run(args []string, stdout, stderr io.Writer) int {
	app := cli.New("slopmop", stdout)
	err := command.Register(app, command.Env{Stdout: stdout, Local: time.Local, Colour: render.TakesColour(stdout)})
	if err == nil {
		err = app.Run(args)
	}
	if err == nil {
		return 0
	}
	// An error can carry a file name from the evidence, so it is escaped.
	_, _ = fmt.Fprintln(stderr, "error:", render.Escape(err.Error()))
	if errors.Is(err, cli.ErrUsage) {
		return 2
	}
	return 1
}
