package store

import "fmt"

// Files returns every file in the order of the timeline: by effective time,
// then by path. Turn counts the scripts up to and including each file.
func (d *DB) Files() ([]File, error) {
	rows, err := d.db.Query(`SELECT path,name,role,size,lines,sha256,note,stamped,stamptext,modified,stamp
		FROM files ORDER BY effsec, effnsec, path`)
	if err != nil {
		return nil, fmt.Errorf("store: files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var files []File
	turn := 0
	for rows.Next() {
		var f File
		var stamped int
		var modified, stamp []byte
		if err := rows.Scan(&f.Path, &f.Name, &f.Role, &f.Size, &f.Lines, &f.SHA256, &f.Note,
			&stamped, &f.StampText, &modified, &stamp); err != nil {
			return nil, fmt.Errorf("store: files scan: %w", err)
		}
		f.Stamped = stamped != 0
		if err := f.Modified.UnmarshalBinary(modified); err != nil {
			return nil, fmt.Errorf("store: files modified: %w", err)
		}
		if err := f.Stamp.UnmarshalBinary(stamp); err != nil {
			return nil, fmt.Errorf("store: files stamp: %w", err)
		}
		if f.Role == roleScript {
			turn++
		}
		f.Turn = turn
		files = append(files, f)
	}
	return files, rows.Err()
}

// roleScript is the role word the inventory gives a script; the timeline turn
// counts them.
const roleScript = "script"

// TypeCount is the number of distinct values of one indicator type.
type TypeCount struct {
	Type  string
	Count int
}

// IndicatorCounts returns the number of distinct values of each indicator
// type, by type. The distinct count is the database's, not a map in memory.
func (d *DB) IndicatorCounts() ([]TypeCount, error) {
	rows, err := d.db.Query(`SELECT type, COUNT(DISTINCT value) FROM indicators GROUP BY type ORDER BY type`)
	if err != nil {
		return nil, fmt.Errorf("store: indicator counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var counts []TypeCount
	for rows.Next() {
		var c TypeCount
		if err := rows.Scan(&c.Type, &c.Count); err != nil {
			return nil, fmt.Errorf("store: indicator counts scan: %w", err)
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// NameFiles is one activity and the files that show it, in timeline order.
type NameFiles struct {
	Name  string
	Files []string
}

// FilesByActivity lists, for each activity, the files that show it, both in
// the order they are first seen along the timeline. The grouping is the
// database's, so no per-activity list is scanned to keep it unique.
func (d *DB) FilesByActivity() ([]NameFiles, error) {
	rows, err := d.db.Query(`SELECT a.name, f.path FROM activities a JOIN files f ON a.file = f.id
		ORDER BY f.effsec, f.effnsec, f.path, a.seq`)
	if err != nil {
		return nil, fmt.Errorf("store: files by activity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	at := map[string]int{}
	seen := map[string]bool{}
	var out []NameFiles
	for rows.Next() {
		var name, path string
		if err := rows.Scan(&name, &path); err != nil {
			return nil, fmt.Errorf("store: files by activity scan: %w", err)
		}
		i, ok := at[name]
		if !ok {
			i = len(out)
			at[name] = i
			out = append(out, NameFiles{Name: name})
		}
		key := name + "\x00" + path
		if !seen[key] {
			seen[key] = true
			out[i].Files = append(out[i].Files, path)
		}
	}
	return out, rows.Err()
}
