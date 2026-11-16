package cli

import (
	"errors"
	"fmt"
)

// ErrUsage matches every parse and dispatch failure through errors.Is.
var ErrUsage = errors.New("usage")

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func (e *usageError) Is(target error) bool { return target == ErrUsage }

// Usagef is the usage error of a verb that rejects the value of a param.
func Usagef(format string, args ...any) error {
	return usagef(format, args...)
}

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}
