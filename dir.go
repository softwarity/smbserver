package smbserver

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// File information classes of QUERY_DIRECTORY ([MS-FSCC] 2.4).
const (
	classDirectory     = 1
	classFullDirectory = 2
	classBothDirectory = 3
	classNames         = 12
	classIDBoth        = 37
	classIDFull        = 38
)

// dirScan is the state of an enumeration: the names are read once, when the
// scan starts, and handed out across as many requests as the client needs.
type dirScan struct {
	names   []string
	pos     int
	pattern string
	// served tells the first request, which answers "no such file" when
	// nothing matches, from the following ones, which answer "no more".
	served bool
}

func (c *conn) queryDirectory(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 32 || le.Uint16(p) != 33 {
		return statusInvalidParameter, nil
	}
	class, flags := p[2], p[3]
	limit := le.Uint32(p[28:])
	raw, ok := sub(r.msg, uint32(le.Uint16(p[24:])), uint32(le.Uint16(p[26:])))
	if !ok || !c.charged(r, limit) {
		return statusInvalidParameter, nil
	}
	if trace {
		r.note = fmt.Sprintf("class %d flags %#x pattern %q", class, flags, decodeUTF16(raw))
	}
	o, st := c.lookup(r, p[8:24])
	if st != statusSuccess {
		return st, nil
	}
	if !o.isDir {
		return statusInvalidParameter, nil
	}
	if entrySize(class, "") == 0 {
		return statusInvalidInfoClass, nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return statusFileClosed, nil
	}
	const restart, single, reopen = 0x01, 0x02, 0x10
	if o.dir == nil || flags&(restart|reopen) != 0 {
		d, err := c.srv.root.Open(o.path)
		if err != nil {
			return errStatus(err), nil
		}
		names, err := d.Readdirnames(maxDirectoryEntries)
		d.Close()
		if err != nil && err != io.EOF && len(names) == 0 {
			return errStatus(err), nil
		}
		sort.Strings(names)
		o.dir = &dirScan{
			names:   append([]string{".", ".."}, names...),
			pattern: nameFromWire(decodeUTF16(raw)),
		}
	}
	scan := o.dir
	wild := strings.ContainsAny(scan.pattern, `*?<>"`)

	out := newMsg(8)
	last := -1
	for scan.pos < len(scan.names) {
		name := scan.names[scan.pos]
		if scan.pattern != "" && scan.pattern != "*" {
			if wild && !matchPattern(scan.pattern, name) || !wild && scan.pattern != name {
				scan.pos++
				continue
			}
		}
		wire := nameToWire(name)
		start := (len(out) + 7) &^ 7
		if uint32(start-headerSize-8+entrySize(class, wire)) > limit {
			if last < 0 {
				// Not even one entry fits.
				return statusInfoLengthMismatch, nil
			}
			break
		}
		// "." and ".." both describe the directory itself: the parent of
		// the share root is not something to report on.
		target := o.path
		if name != "." && name != ".." {
			target = path.Join(o.path, name)
		}
		fi, err := c.srv.root.Stat(target)
		if err != nil {
			// A dangling or escaping symbolic link is listed as the link
			// it is; a name that vanished since the scan is skipped.
			if fi, err = c.srv.root.Lstat(target); err != nil {
				scan.pos++
				continue
			}
		}
		info := c.srv.info(fi, target)
		if last >= 0 {
			out = pad8(out)
			le.PutUint32(out[last:], uint32(len(out)-last))
		}
		last = len(out)
		out = appendEntry(out, class, wire, &info, uint32(scan.pos))
		scan.pos++
		if flags&single != 0 {
			break
		}
	}
	if last < 0 {
		if !scan.served {
			scan.served = true
			return statusNoSuchFile, nil
		}
		return statusNoMoreFiles, nil
	}
	scan.served = true
	le.PutUint16(out[headerSize:], 9)
	le.PutUint16(out[headerSize+2:], headerSize+8)
	le.PutUint32(out[headerSize+4:], uint32(len(out)-headerSize-8))
	return statusSuccess, out
}

// entrySize returns the encoded size of a directory entry, or zero for a
// class the server does not know.
func entrySize(class byte, wire string) int {
	n := 2 * len([]rune(wire))
	for _, r := range wire {
		if r > 0xFFFF {
			n += 2
		}
	}
	switch class {
	case classDirectory:
		return 64 + n
	case classFullDirectory:
		return 68 + n
	case classBothDirectory:
		return 94 + n
	case classIDFull:
		return 80 + n
	case classIDBoth:
		return 104 + n
	case classNames:
		return 12 + n
	}
	return 0
}

func appendEntry(out []byte, class byte, wire string, in *fileInfo, index uint32) []byte {
	name := encodeUTF16(wire)
	base := len(out)
	out = append(out, make([]byte, entrySize(class, wire)-len(name))...)
	b := out[base:]
	le.PutUint32(b[4:], index)
	if class == classNames {
		le.PutUint32(b[8:], uint32(len(name)))
		return append(out, name...)
	}
	in.putTimes(b[8:])
	le.PutUint64(b[40:], in.size)
	le.PutUint64(b[48:], in.alloc)
	le.PutUint32(b[56:], in.attrs)
	le.PutUint32(b[60:], uint32(len(name)))
	// Offsets 64 and up hold, depending on the class, the EA size, an
	// empty 8.3 name and the file id; only the last is ever non-zero.
	switch class {
	case classIDFull:
		le.PutUint64(b[72:], in.ino)
	case classIDBoth:
		le.PutUint64(b[96:], in.ino)
	}
	return append(out, name...)
}
