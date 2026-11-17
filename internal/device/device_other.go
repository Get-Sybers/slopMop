//go:build !linux && !windows && !darwin

package device

// physical is not known on this system.
func physical() (uint64, bool) {
	return 0, false
}
