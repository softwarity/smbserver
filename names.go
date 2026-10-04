package smbserver

import (
	"os"
	"strings"
)

// Windows forbids in file names a handful of characters that POSIX allows.
// SMB clients on Linux and macOS carry those through the protocol by mapping
// them to the Unicode private range, a convention inherited from Services
// for Macintosh. The server undoes the mapping so that a file named "a:b" in
// the volume is "a:b" on the mounted side as well.
var sfmToPosix = map[rune]rune{
	0xF020: '"', 0xF021: '*', 0xF022: ':', 0xF023: '<', 0xF024: '>',
	0xF025: '?', 0xF026: '\\', 0xF027: '|', 0xF028: ' ', 0xF029: '.',
}

var posixToSFM = map[rune]rune{
	'"': 0xF020, '*': 0xF021, ':': 0xF022, '<': 0xF023, '>': 0xF024,
	'?': 0xF025, '\\': 0xF026, '|': 0xF027,
}

func nameFromWire(s string) string {
	return strings.Map(func(r rune) rune {
		if p, ok := sfmToPosix[r]; ok {
			return p
		}
		if r >= 0xF001 && r <= 0xF01F {
			return r - 0xF000
		}
		return r
	}, s)
}

func nameToWire(s string) string {
	if s == "" || s == "." || s == ".." {
		return s
	}
	r := []rune(s)
	for i, c := range r {
		if m, ok := posixToSFM[c]; ok {
			r[i] = m
		} else if c >= 0x01 && c <= 0x1F {
			r[i] = c + 0xF000
		}
	}
	// A trailing space or period cannot be expressed in a Windows name.
	switch last := len(r) - 1; r[last] {
	case ' ':
		r[last] = 0xF028
	case '.':
		r[last] = 0xF029
	}
	return string(r)
}

// parsePath turns the name of a CREATE or rename target into a slash
// separated path relative to the share root, "." being the root itself.
//
// It is the first of two barriers against path traversal: every component
// must be a plain name, so "..", absolute paths and embedded separators are
// refused here. The second barrier is os.Root, which resolves the path
// without ever leaving the root directory, symbolic links included.
func parsePath(name string) (string, ntStatus) {
	if name == "" {
		return ".", statusSuccess
	}
	parts := strings.Split(name, `\`)
	for i, p := range parts {
		// A colon introduces a named stream, which parseName has split
		// off already. A literal colon in a file name arrives mapped.
		if strings.ContainsRune(p, ':') {
			return "", statusObjectNameInvalid
		}
		p = nameFromWire(p)
		if p == "" || p == "." || p == ".." || len(p) > 255 || strings.ContainsAny(p, "/\x00") {
			return "", statusObjectNameInvalid
		}
		if os.PathSeparator != '/' && strings.ContainsRune(p, os.PathSeparator) {
			return "", statusObjectNameInvalid
		}
		parts[i] = p
	}
	return strings.Join(parts, "/"), statusSuccess
}

// wirePath is the reverse of parsePath, for the classes of information that
// return the full name of an open file.
func wirePath(p string) string {
	if p == "." {
		return `\`
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = nameToWire(s)
	}
	return `\` + strings.Join(parts, `\`)
}

// matchPattern implements the wildcard search of QUERY_DIRECTORY. Besides *
// and ?, the DOS wildcards <, > and " of [MS-FSCC] 2.1.4.4 are accepted and
// treated as their plain counterparts, which is how they behave for the
// names without 8.3 constraints that this server holds.
func matchPattern(pattern, name string) bool {
	p := []rune(strings.ToLower(pattern))
	for i, c := range p {
		switch c {
		case '<':
			p[i] = '*'
		case '>':
			p[i] = '?'
		case '"':
			p[i] = '.'
		}
	}
	n := []rune(strings.ToLower(name))
	// Iterative glob match with single backtrack point.
	pi, ni, star, mark := 0, 0, -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
