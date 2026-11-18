package intent

import (
	"strings"
	"testing"
)

func TestOf(t *testing.T) {
	table, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, path string
		want       Ref
		found      bool
	}{
		{"a run folder", "tasks/7/i1042/scan.sh", Ref{ID: "i1042", Task: "7"}, true},
		{"the output folder of a run", "data/tasks/7/i1042/cmd-output/out-3.txt", Ref{ID: "i1042", Task: "7"}, true},
		{"a run folder that is read itself", "7/i1042/scan.sh", Ref{ID: "i1042"}, true},
		{"a folder alone", "i5/a.sh", Ref{ID: "i5"}, true},
		{"the folder nearest the file", "i1/kept/i2/a.sh", Ref{ID: "i2"}, true},
		{"a run folder before a folder", "i9/tasks/3/i12/keep/i7/a.sh", Ref{ID: "i12", Task: "3"}, true},
		{"a session in a file name", "noa/exp3-worker-i1042.jsonl", Ref{ID: "i1042"}, true},
		{"a session in a folder name", "noa/exp3-worker-i77/turn-1.json", Ref{ID: "i77"}, true},
		{"a session before a folder", "i4/exp3-worker-i77.jsonl", Ref{ID: "i77"}, true},
		{"no intent", "stage/20261022_090000_step01_recon.sh", Ref{}, false},
		{"a file name that is the intent", "notes/i1042.txt", Ref{ID: "i1042"}, true},
		{"a file name that begins with the intent", "out/i1042_scan.sh", Ref{ID: "i1042"}, true},
		{"a file name that ends with the intent", "out/scan-i1042", Ref{ID: "i1042"}, true},
		{"a file name with the intent inside", "out/cmd.i1042.stdout.txt", Ref{ID: "i1042"}, true},
		{"a file name with two", "out/i12_after_i11.txt", Ref{ID: "i12"}, true},
		{"a file name before its folder", "tasks/7/i1042/cmd-output/i1043_out.txt", Ref{ID: "i1043"}, true},
		{"a file name and the task of its run folder", "tasks/7/i1042/i1042_plan.json", Ref{ID: "i1042", Task: "7"}, true},
		{"a file name with letters before the name", "out/wifi7.txt", Ref{}, false},
		{"a file name with letters after the name", "out/i18n.json", Ref{}, false},
		{"a file name that names an architecture", "i12/libc_i686.so", Ref{ID: "i12"}, true},
		{"a longer name", "i1042x/a.sh", Ref{}, false},
		{"a name that only ends like one", "ai1042/a.sh", Ref{}, false},
		{"an upper-case name", "I1042/a.sh", Ref{}, false},
		{"no digits", "i/a.sh", Ref{}, false},
		{"an architecture", "lib/i386/a.so", Ref{}, false},
		{"an architecture under an intent", "i12/lib/i686/a.so", Ref{ID: "i12"}, true},
		{"a session of another kind is a file name", "exp3-planner-i1042.jsonl", Ref{ID: "i1042"}, true},
		{"a session of another kind in a folder name", "exp3-planner-i1042/turn-1.json", Ref{}, false},
		{"a number too long to be one", "i12345678901234567890/a.sh", Ref{}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := table.Of(tt.path)
			if got != tt.want || ok != tt.found {
				t.Errorf("Of(%q) = %+v, %t, want %+v, %t", tt.path, got, ok, tt.want, tt.found)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, tt := range []struct{ name, doc, want string }{
		{"not JSON", `{`, "paths.json:"},
		{"an unknown field", `{"rules": [{"name": "a", "pattern": "(?P<id>i)", "extra": 1}]}`, "unknown field"},
		{"trailing data", `{"rules": [{"name": "a", "pattern": "(?P<id>i)"}]} {}`, "trailing data"},
		{"no rules", `{"rules": []}`, "no rules"},
		{"a rule without a name", `{"rules": [{"name": "", "pattern": "(?P<id>i)"}]}`, "empty or used twice"},
		{"a name twice", `{"rules": [{"name": "a", "pattern": "(?P<id>i)"}, {"name": "a", "pattern": "(?P<id>j)"}]}`, "empty or used twice"},
		{"a pattern that does not compile", `{"rules": [{"name": "a", "pattern": "(?P<id>i"}]}`, "paths.json: a:"},
		{"no id group", `{"rules": [{"name": "a", "pattern": "i[0-9]+"}]}`, "has no group named id"},
		{"an unknown group", `{"rules": [{"name": "a", "pattern": "(?P<id>i)(?P<run>r)"}]}`, `names the group "run"`},
		{"an empty rejected name", `{"rules": [{"name": "a", "pattern": "(?P<id>i)"}], "reject": [""]}`, "empty or listed twice"},
		{"a rejected name twice", `{"rules": [{"name": "a", "pattern": "(?P<id>i)"}], "reject": ["i1", "i1"]}`, "empty or listed twice"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decode([]byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("decode error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
