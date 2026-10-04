package smbserver

import (
	"hash/fnv"
	"os"
	"path"
	"strings"
	"time"
)

// fileKey identifies a file independently of its name, so that two handles
// opened under different paths (a rename, a hard link) share their state.
// Where the platform exposes no inode, the path stands in.
type fileKey struct {
	dev, ino uint64
	path     string
}

// sysInfo is what the platform knows about a file beyond os.FileInfo.
type sysInfo struct {
	dev, ino uint64
	nlink    uint32
	alloc    uint64
	atime    time.Time
	ctime    time.Time
	btime    time.Time
}

// fileInfo is a file as the protocol describes it.
type fileInfo struct {
	size, alloc  uint64
	btime, atime time.Time
	mtime, ctime time.Time
	attrs        uint32
	dev, ino     uint64
	nlink        uint32
	isDir        bool
}

func keyOf(fi os.FileInfo, p string) fileKey {
	if st, ok := sysStat(fi); ok {
		return fileKey{dev: st.dev, ino: st.ino}
	}
	return fileKey{path: p}
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// info converts a stat result. p is the path of the file relative to the
// share root; its last element decides the hidden attribute.
func (s *server) info(fi os.FileInfo, p string) fileInfo {
	in := fileInfo{
		mtime: fi.ModTime(),
		isDir: fi.IsDir(),
		nlink: 1,
	}
	if st, ok := sysStat(fi); ok {
		in.dev, in.ino, in.nlink = st.dev, st.ino, st.nlink
		in.atime, in.ctime, in.btime = st.atime, st.ctime, st.btime
		in.alloc = st.alloc
	} else {
		in.ino = hash64(p)
		in.alloc = (uint64(fi.Size()) + 4095) &^ 4095
	}
	if in.atime.IsZero() {
		in.atime = in.mtime
	}
	if in.ctime.IsZero() {
		in.ctime = in.mtime
	}
	// Linux does not report a creation time through stat. The modification
	// time is the closest honest answer, and it is never in the future of
	// the other timestamps, which some clients check.
	if in.btime.IsZero() || in.btime.After(in.mtime) {
		in.btime = in.mtime
	}
	if in.isDir {
		in.attrs = attrDirectory
		in.alloc = 0
	} else {
		in.attrs = attrArchive
		in.size = uint64(fi.Size())
	}
	// A file nobody may write is read-only to a Windows client, which then
	// offers to clear the attribute before deleting; see setBasic.
	if !in.isDir && fi.Mode().Perm()&0o222 == 0 {
		in.attrs |= attrReadOnly
	}
	if base := path.Base(p); strings.HasPrefix(base, ".") && base != "." && base != ".." {
		in.attrs |= attrHidden
	}
	return in
}

// putTimes writes the four timestamps every information class starts with.
func (in *fileInfo) putTimes(b []byte) {
	le.PutUint64(b, filetime(in.btime))
	le.PutUint64(b[8:], filetime(in.atime))
	le.PutUint64(b[16:], filetime(in.mtime))
	le.PutUint64(b[24:], filetime(in.ctime))
}
