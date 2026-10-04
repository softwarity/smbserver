// Command matrix turns the result files of the integration tests into the
// compatibility table of the README.
//
// Each result file is named after a client and holds one "<operation> ok" or
// "<operation> FAIL" line per check. The table is written between the two
// marker comments of the README, so the document states what the last test
// run observed rather than what someone remembered to write.
//
// usage: matrix <results-dir> [README.md]
//
// Without a README the table goes to standard output.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// columns fixes the order and the title of the known clients; a result file
// with another name is appended under its own name.
var columns = []struct{ file, title string }{
	{"smbclient", "smbclient"},
	{"linux-cifs", "Linux (cifs)"},
	{"docker-volume", "Docker volume (cifs)"},
	{"macos-smbfs", "macOS (mount_smbfs)"},
	{"windows", "Windows (redirector)"},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: matrix <results-dir> [README.md]")
		os.Exit(2)
	}
	files, _ := filepath.Glob(filepath.Join(os.Args[1], "*.txt"))
	sort.Strings(files)
	results := map[string]map[string]string{}
	var ops []string
	seen := map[string]bool{}
	read := func(name string) bool {
		data, err := os.ReadFile(filepath.Join(os.Args[1], name+".txt"))
		if err != nil {
			return false
		}
		results[name] = map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			op, outcome, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok {
				continue
			}
			results[name][op] = outcome
			if !seen[op] {
				seen[op] = true
				ops = append(ops, op)
			}
		}
		return true
	}
	var titles, names []string
	for _, c := range columns {
		if read(c.file) {
			names, titles = append(names, c.file), append(titles, c.title)
		}
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		if _, done := results[name]; !done && read(name) {
			names, titles = append(names, name), append(titles, name)
		}
	}
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "matrix: no result file in", os.Args[1])
		os.Exit(1)
	}

	var table bytes.Buffer
	fmt.Fprintf(&table, "| Operation | %s |\n|---|%s\n", strings.Join(titles, " | "), strings.Repeat(":-:|", len(titles)))
	for _, op := range ops {
		fmt.Fprintf(&table, "| %s |", op)
		for _, name := range names {
			switch results[name][op] {
			case "ok":
				table.WriteString(" ✅ |")
			case "":
				table.WriteString(" · |")
			default:
				table.WriteString(" ❌ |")
			}
		}
		table.WriteByte('\n')
	}

	if len(os.Args) < 3 {
		os.Stdout.Write(table.Bytes())
		return
	}
	readme, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrix:", err)
		os.Exit(1)
	}
	readme, ok := replace(readme, "matrix", table.Bytes())
	if !ok {
		fmt.Fprintln(os.Stderr, "matrix: markers not found in", os.Args[2])
		os.Exit(1)
	}
	// The timings against Samba, when the run produced them.
	if bench, err := os.ReadFile(filepath.Join(os.Args[1], "bench.md")); err == nil {
		readme, _ = replace(readme, "bench", bench)
	}
	if err := os.WriteFile(os.Args[2], readme, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "matrix:", err)
		os.Exit(1)
	}
}

// replace puts content between the two marker comments of a section.
func replace(doc []byte, section string, content []byte) ([]byte, bool) {
	startMarker, endMarker := "<!-- "+section+":start -->", "<!-- "+section+":end -->"
	start := bytes.Index(doc, []byte(startMarker))
	end := bytes.Index(doc, []byte(endMarker))
	if start < 0 || end < start {
		return doc, false
	}
	var out bytes.Buffer
	out.Write(doc[:start+len(startMarker)])
	out.WriteByte('\n')
	out.Write(content)
	out.Write(doc[end:])
	return out.Bytes(), true
}
