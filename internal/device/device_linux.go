package device

import "os"

// physical is the memory of the machine, or the limit of the control group
// the process runs in when that is less.
func physical() (uint64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	total, ok := meminfoTotal(string(data))
	if !ok {
		return 0, false
	}
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if limit, limited := groupLimit(string(data)); limited && limit < total {
			total = limit
		}
	}
	return total, true
}
