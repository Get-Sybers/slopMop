// Package state keeps the selected evidence folder between runs.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

type State struct {
	Evidence string `json:"evidence"`
}

// Path is the state file in the user's configuration directory.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("state file: %w", err)
	}
	return filepath.Join(dir, "slopmop", "state.json"), nil
}

// Load reads the state file. A missing file is the zero State.
func Load(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("state file: %w", err)
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return State{}, fmt.Errorf("state file %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return State{}, fmt.Errorf("state file %s: data after the document", path)
	}
	if s.Evidence != "" && !filepath.IsAbs(s.Evidence) {
		return State{}, fmt.Errorf("state file %s: evidence %q is not an absolute path", path, s.Evidence)
	}
	return s, nil
}

// Save replaces the state file through a rename, so a reader never sees half of it.
func (s State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("state file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	return nil
}
