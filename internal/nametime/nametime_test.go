package nametime

import (
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	utc := func(y int, mo time.Month, d, h, mi, s int) time.Time {
		return time.Date(y, mo, d, h, mi, s, 0, time.UTC)
	}
	cases := []struct {
		name  string
		file  string
		found bool
		want  Stamp
	}{
		{"fixture script", "20250301_101500_step01_recon.sh", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301_101500", true}},
		{"fixture stamp at the end", "hosts_20250302_090030.csv", true,
			Stamp{utc(2025, 3, 2, 9, 0, 30), Second, "20250302_090030", true}},
		{"fixture stamp after an address", "sync_10.20.1.17_20250302_090530.txt", true,
			Stamp{utc(2025, 3, 2, 9, 5, 30), Second, "20250302_090530", true}},
		{"fixture epoch", "adsync_1740824625.txt", true,
			Stamp{utc(2025, 3, 1, 10, 23, 45), Second, "1740824625", false}},
		{"compact", "20250301101500.sh", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301101500", true}},
		{"dashes and T", "run-2025-03-01T10-15-00.log", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "2025-03-01T10-15-00", true}},
		{"dots and colons", "2025.03.01 10:15:00.txt", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "2025.03.01 10:15:00", true}},
		{"h and m separators", "2025-03-01_10h15m00.txt", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "2025-03-01_10h15m00", true}},
		{"capital H", "20250301-10H15.txt", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301-10H15", true}},
		{"no seconds keeps second precision", "20250301_1015_scan.txt", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301_1015", true}},
		{"trailing Z", "20250301T101500Z.json", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301T101500Z", false}},
		{"Z without seconds", "20250301T1015Z.json", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301T1015Z", false}},
		{"stamp is the whole name", "20250301_101500", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301_101500", true}},
		{"leftmost stamp wins", "20250301_101500_to_20250302_111500.txt", true,
			Stamp{utc(2025, 3, 1, 10, 15, 0), Second, "20250301_101500", true}},
		{"last second of a day", "20251231_235959.txt", true,
			Stamp{utc(2025, 12, 31, 23, 59, 59), Second, "20251231_235959", true}},
		{"epoch with milliseconds", "out_1740824625123.txt", true,
			Stamp{utc(2025, 3, 1, 10, 23, 45), Second, "1740824625123", false}},
		{"lowest epoch", "1500000000.log", true,
			Stamp{utc(2017, 7, 14, 2, 40, 0), Second, "1500000000", false}},
		{"highest epoch", "1999999999.log", true,
			Stamp{utc(2033, 5, 18, 3, 33, 19), Second, "1999999999", false}},
		{"date only", "report_2025-03-01.txt", true,
			Stamp{utc(2025, 3, 1, 0, 0, 0), Day, "2025-03-01", false}},
		{"compact date", "20250301.txt", true,
			Stamp{utc(2025, 3, 1, 0, 0, 0), Day, "20250301", false}},
		{"hour 24 leaves a date", "20250301_2460.txt", true,
			Stamp{utc(2025, 3, 1, 0, 0, 0), Day, "20250301", false}},
		{"impossible date and time falls to the epoch", "20250230_101500_1740824625.txt", true,
			Stamp{utc(2025, 3, 1, 10, 23, 45), Second, "1740824625", false}},
		{"impossible first match is not retried", "20250230_101500_20250301_101500.txt", false, Stamp{}},
		{"impossible date", "20250230.txt", false, Stamp{}},
		{"april has thirty days", "2025-04-31.txt", false, Stamp{}},
		{"leap day", "2024-02-29.txt", true,
			Stamp{utc(2024, 2, 29, 0, 0, 0), Day, "2024-02-29", false}},
		{"no leap day", "2025-02-29.txt", false, Stamp{}},
		{"digit before", "920250301_101500.txt", false, Stamp{}},
		{"digit after the time leaves a date", "20250301_1015009.txt", true,
			Stamp{utc(2025, 3, 1, 0, 0, 0), Day, "20250301", false}},
		{"digit after the date", "202503019.txt", false, Stamp{}},
		{"epoch below the range", "1499999999.log", false, Stamp{}},
		{"epoch above the range", "2000000000.log", false, Stamp{}},
		{"eleven digits", "17408246251.log", false, Stamp{}},
		{"year outside 20xx", "19990301_101500.txt", false, Stamp{}},
		{"month thirteen", "20251301.txt", false, Stamp{}},
		{"no stamp", "notes.txt", false, Stamp{}},
		{"empty", "", false, Stamp{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, found := Detect(c.file)
			if found != c.found {
				t.Fatalf("Detect(%q) found = %v, want %v", c.file, found, c.found)
			}
			if !got.Time.Equal(c.want.Time) || got.Precision != c.want.Precision ||
				got.Text != c.want.Text || got.Local != c.want.Local {
				t.Errorf("Detect(%q) = %+v, want %+v", c.file, got, c.want)
			}
			if found && got.Time.Location() != time.UTC {
				t.Errorf("Detect(%q) location = %v, want UTC", c.file, got.Time.Location())
			}
		})
	}
}
