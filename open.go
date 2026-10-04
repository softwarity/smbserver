package smbserver

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Access mask bits ([MS-SMB2] 2.2.13.1).
const (
	fileReadData        uint32 = 0x00000001
	fileWriteData       uint32 = 0x00000002
	fileAppendData      uint32 = 0x00000004
	fileExecute         uint32 = 0x00000020
	accessDelete        uint32 = 0x00010000
	accessMaximum       uint32 = 0x02000000
	accessGenericAll    uint32 = 0x10000000
	accessGenericExec   uint32 = 0x20000000
	accessGenericWrite  uint32 = 0x40000000
	accessGenericRead   uint32 = 0x80000000
	accessAll           uint32 = 0x001F01FF
	accessReadOnly      uint32 = 0x001200A9
	accessModifying     uint32 = 0x000D0156 // write data, append, EAs, attributes, delete, DAC, owner
	optDirectory        uint32 = 0x00000001
	optNonDirectory     uint32 = 0x00000040
	optDeleteOnClose    uint32 = 0x00001000
	dispSupersede       uint32 = 0
	dispOpen            uint32 = 1
	dispCreate          uint32 = 2
	dispOpenIf          uint32 = 3
	dispOverwrite       uint32 = 4
	dispOverwriteIf     uint32 = 5
	actionSuperseded    uint32 = 0
	actionOpened        uint32 = 1
	actionCreated       uint32 = 2
	actionOverwritten   uint32 = 3
	attrReadOnly        uint32 = 0x00000001
	attrHidden          uint32 = 0x00000002
	attrDirectory       uint32 = 0x00000010
	attrArchive         uint32 = 0x00000020
	attrNormal          uint32 = 0x00000080
	maxDirectoryEntries        = 1 << 20
)

// open is a file handle held by a client.
type open struct {
	id     uint64
	sess   *session
	tree   *tree
	isDir  bool
	access uint32
	// shared is nil for a handle on a named stream, which has stream
	// and streamKey, the identity of its file, instead.
	shared    *sharedFile
	stream    *memStream
	streamKey fileKey

	mu     sync.Mutex
	closed bool
	// path is relative to the share root. It follows renames, including
	// those made through another handle.
	path string
	// f is nil when the handle was opened for attributes only, and for
	// directories, which are read by path.
	f             *os.File
	deleteOnClose bool
	dir           *dirScan
	// oplock tells that the handle holds a level II oplock. Guarded by
	// the server lock.
	oplock bool
}

// sharedFile is what the handles open on one file have in common: the
// pending deletion and the byte-range locks.
type sharedFile struct {
	key           fileKey
	opens         []*open
	deletePending bool
	locks         []rangeLock
	// holders counts the handles under oplock; size and mtime are what
	// the file looked like when the first of them was granted.
	holders atomic.Int32
	size    int64
	mtime   time.Time
}

func (o *open) location() (string, *os.File) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.path, o.f
}

// stat describes the file behind a handle.
func (s *server) stat(o *open) (fileInfo, ntStatus) {
	p, f := o.location()
	var fi os.FileInfo
	var err error
	if f != nil {
		fi, err = f.Stat()
	} else {
		fi, err = s.root.Stat(p)
	}
	if err != nil {
		return fileInfo{}, errStatus(err)
	}
	in := s.info(fi, p)
	if o.stream != nil {
		// A stream borrows the timestamps of its file and has a size
		// of its own.
		in.size = s.streamSize(o.stream)
		in.alloc = (in.size + 4095) &^ 4095
		in.isDir, in.attrs = false, attrNormal
	}
	return in, statusSuccess
}

// normalizeAccess expands the generic rights of a desired access into the
// specific ones.
func normalizeAccess(a uint32) uint32 {
	if a&(accessGenericAll|accessMaximum) != 0 {
		a |= accessAll
	}
	if a&accessGenericRead != 0 {
		a |= 0x00120089
	}
	if a&accessGenericWrite != 0 {
		a |= 0x00120116
	}
	if a&accessGenericExec != 0 {
		a |= 0x001200A0
	}
	return a & accessAll
}

// openFile implements CREATE for the disk share. The whole decision runs
// under the server lock so that a pending deletion is seen atomically with
// respect to other clients.
func (s *server) openFile(r *request, p string, desired, disp, opts uint32, wantOplock bool) (*open, uint32, ntStatus) {
	if disp > dispOverwriteIf {
		return nil, 0, statusInvalidParameter
	}
	access := normalizeAccess(desired)
	if s.cfg.ReadOnly {
		// "Whatever I may have" is answered with read access; an
		// explicit request to modify is refused.
		if desired&accessMaximum != 0 && desired&(accessGenericAll|accessGenericWrite) == 0 {
			access = normalizeAccess(desired&^accessMaximum) | accessReadOnly
		}
		if access&accessModifying != 0 || opts&optDeleteOnClose != 0 || (disp != dispOpen && disp != dispOpenIf) {
			return nil, 0, statusAccessDenied
		}
	}

	// The oplock holders to notify, once the server lock is released.
	var broken []*open
	defer func() { s.notifyBreak(r.sess.conn, broken) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nOpens >= maxOpens {
		return nil, 0, statusTooManyOpenedFiles
	}

	fi, err := s.root.Stat(p)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, 0, errStatus(err)
	}
	var (
		f      *os.File
		action = actionOpened
	)
	switch {
	case !exists:
		if disp == dispOpen || disp == dispOverwrite || s.cfg.ReadOnly {
			return nil, 0, s.missing(p)
		}
		// The Finder drops a .DS_Store in every folder it shows. The
		// volume is not a desktop: the file is refused, which the
		// Finder takes as it does on any read-only volume.
		if path.Base(p) == ".DS_Store" {
			return nil, 0, statusAccessDenied
		}
		if opts&optDirectory != 0 {
			err = s.root.Mkdir(p, 0o777)
		} else {
			// The mode is left to the umask of the process, like any
			// file the workload itself would create.
			f, err = s.root.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, 0, s.missing(p)
			}
			return nil, 0, errStatus(err)
		}
		action = actionCreated
	case disp == dispCreate:
		return nil, 0, statusObjectNameCollision
	case fi.IsDir():
		if opts&optNonDirectory != 0 {
			return nil, 0, statusFileIsADirectory
		}
		if disp != dispOpen && disp != dispOpenIf {
			return nil, 0, statusAccessDenied
		}
	default:
		if opts&optDirectory != 0 {
			return nil, 0, statusNotADirectory
		}
	}
	if f != nil {
		fi, err = f.Stat()
	} else if !exists {
		fi, err = s.root.Stat(p)
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		return nil, 0, errStatus(err)
	}

	key := keyOf(fi, p)
	sf := s.files[key]
	if sf == nil {
		sf = &sharedFile{key: key}
	}
	fail := func(st ntStatus) (*open, uint32, ntStatus) {
		if f != nil {
			f.Close()
		}
		return nil, 0, st
	}
	if sf.deletePending {
		return fail(statusDeletePending)
	}

	if exists && !fi.IsDir() {
		truncate := disp == dispSupersede || disp == dispOverwrite || disp == dispOverwriteIf
		if truncate {
			action = actionOverwritten
			if disp == dispSupersede {
				action = actionSuperseded
			}
		}
		write := truncate || access&(fileWriteData|fileAppendData) != 0
		read := access&(fileReadData|fileExecute) != 0
		// Opening a FIFO or a device could block or have side effects;
		// such files are visible but their content is not served.
		if (read || write) && !fi.Mode().IsRegular() {
			return fail(statusAccessDenied)
		}
		if read || write {
			flag := os.O_RDONLY
			if write {
				flag = os.O_RDWR
			}
			if truncate {
				flag |= os.O_TRUNC
			}
			f, err = s.root.OpenFile(p, flag, 0)
			if err != nil && write && errors.Is(err, fs.ErrPermission) {
				switch {
				case desired&accessMaximum != 0 && !truncate:
					// The client asked for whatever it can get:
					// settle for what the file permits.
					access &^= fileWriteData | fileAppendData
					if f, err = s.root.OpenFile(p, os.O_RDONLY, 0); err != nil {
						access &^= fileReadData | fileExecute
						f, err = nil, nil
					}
				case !read:
					f, err = s.root.OpenFile(p, flag&^os.O_RDWR|os.O_WRONLY, 0)
				}
			}
			if err != nil {
				return nil, 0, errStatus(err)
			}
			if truncate {
				broken = s.takeHolders(sf)
				if fi, err = f.Stat(); err != nil {
					return fail(errStatus(err))
				}
			}
		}
	}

	o := &open{
		id:            s.newID(),
		sess:          r.sess,
		tree:          r.tree,
		isDir:         fi.IsDir(),
		access:        access,
		shared:        sf,
		path:          p,
		f:             f,
		deleteOnClose: opts&optDeleteOnClose != 0,
	}
	sf.opens = append(sf.opens, o)
	s.files[key] = sf
	s.nOpens++
	// Readers only: a handle that can write would break its own oplock
	// with its first write.
	if wantOplock && fi.Mode().IsRegular() && access&(fileWriteData|fileAppendData) == 0 {
		s.grantOplock(o, fi.Size(), fi.ModTime())
	}
	return o, action, statusSuccess
}

// missing tells a missing file from a missing parent directory, a
// distinction clients rely on when they create a path recursively.
func (s *server) missing(p string) ntStatus {
	if dir := path.Dir(p); dir != "." {
		if fi, err := s.root.Stat(dir); err != nil || !fi.IsDir() {
			return statusObjectPathNotFound
		}
	}
	return statusObjectNameNotFound
}

// release closes a handle that has already been removed from its session.
func (s *server) release(o *open) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	f := o.f
	o.f = nil
	o.dir = nil
	o.mu.Unlock()

	if f != nil {
		f.Close()
	}
	if o.stream != nil {
		s.releaseStream(o)
		return
	}
	sf := o.shared
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nOpens--
	for i, other := range sf.opens {
		if other == o {
			sf.opens = append(sf.opens[:i], sf.opens[i+1:]...)
			break
		}
	}
	s.dropLocks(sf, o)
	s.dropOplock(o)
	if o.deleteOnClose {
		sf.deletePending = true
	}
	if len(sf.opens) == 0 {
		// The deletion requested through any handle takes effect when
		// the last one goes. Failure (a directory that filled up in
		// the meantime) has nobody left to be reported to.
		if sf.deletePending && s.root.Remove(o.path) == nil {
			s.dropStreams(sf.key)
		}
		delete(s.files, sf.key)
	}
}

// renamed updates the path of every handle at or below a renamed file.
// Called with s.mu held.
func (s *server) renamed(from, to string) {
	for _, sf := range s.files {
		for _, o := range sf.opens {
			o.mu.Lock()
			if o.path == from {
				o.path = to
			} else if strings.HasPrefix(o.path, from+"/") {
				o.path = to + o.path[len(from):]
			}
			o.mu.Unlock()
		}
	}
}

// lookup resolves the FileId of a request to a handle of its session and
// tree. In a related compound request the all-ones id stands for the file
// of the previous command.
func (c *conn) lookup(r *request, id []byte) (*open, ntStatus) {
	persistent, volatile := le.Uint64(id), le.Uint64(id[8:])
	if r.hdr.flags&flagRelated != 0 && persistent == ^uint64(0) && volatile == ^uint64(0) {
		if !r.chain.hasFile {
			if r.chain.status != statusSuccess {
				return nil, r.chain.status
			}
			return nil, statusFileClosed
		}
		volatile = r.chain.fileID
	}
	o := r.sess.open(volatile)
	if o == nil || o.tree != r.tree {
		return nil, statusFileClosed
	}
	r.chain.fileID, r.chain.hasFile = volatile, true
	return o, statusSuccess
}

func (c *conn) create(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 56 || le.Uint16(p) != 57 {
		return statusInvalidParameter, nil
	}
	desired := le.Uint32(p[24:])
	disp := le.Uint32(p[36:])
	opts := le.Uint32(p[40:])
	var raw []byte
	if n := uint32(le.Uint16(p[46:])); n > 0 {
		var ok bool
		if raw, ok = sub(r.msg, uint32(le.Uint16(p[44:])), n); !ok {
			return statusInvalidParameter, nil
		}
	}
	contexts, ok := parseCreateContexts(r.msg, le.Uint32(p[48:]), le.Uint32(p[52:]))
	if !ok {
		return statusInvalidParameter, nil
	}
	name := decodeUTF16(raw)
	if trace {
		r.note = fmt.Sprintf("%q access %#x disposition %d options %#x contexts %d", name, desired, disp, opts, len(contexts))
	}

	var (
		o      *open
		action uint32
	)
	// IPC$ is connectable because clients probe it, but it holds no pipe.
	if r.tree.ipc {
		return statusObjectNameNotFound, nil
	}
	rel, stream, st := parseName(name)
	switch {
	case st != statusSuccess:
	case stream != "":
		o, action, st = c.srv.openStream(r, rel, stream, desired, disp, opts)
	default:
		o, action, st = c.srv.openFile(r, rel, desired, disp, opts, p[3] != oplockNone && p[3] != 0xFF)
	}
	if st != statusSuccess {
		return st, nil
	}
	s := r.sess
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.opens[o.id] = o
	}
	s.mu.Unlock()
	if closed {
		c.srv.release(o)
		return statusUserSessionDeleted, nil
	}
	r.chain.fileID, r.chain.hasFile = o.id, true

	info, st := c.srv.stat(o)
	if st != statusSuccess {
		s.mu.Lock()
		delete(s.opens, o.id)
		s.mu.Unlock()
		c.srv.release(o)
		return st, nil
	}

	out := newMsg(88)
	p = out[headerSize:]
	le.PutUint16(p, 89)
	c.srv.mu.Lock()
	if o.oplock {
		p[2] = oplockLevelII
	}
	c.srv.mu.Unlock()
	le.PutUint32(p[4:], action)
	info.putTimes(p[8:])
	le.PutUint64(p[40:], info.alloc)
	le.PutUint64(p[48:], info.size)
	le.PutUint32(p[56:], info.attrs)
	le.PutUint64(p[64:], o.id)
	le.PutUint64(p[72:], o.id)

	var reply [][]byte
	if _, ok := contexts["MxAc"]; ok {
		d := make([]byte, 8)
		le.PutUint32(d[4:], o.access)
		reply = append(reply, createContext("MxAc", d))
	}
	if _, ok := contexts["QFid"]; ok {
		d := make([]byte, 32)
		le.PutUint64(d, info.ino)
		le.PutUint64(d[8:], info.dev)
		reply = append(reply, createContext("QFid", d))
	}
	if len(reply) == 0 {
		return statusSuccess, append(out, 0)
	}
	le.PutUint32(out[headerSize+80:], uint32(len(out)))
	start := len(out)
	for i, ctx := range reply {
		if i < len(reply)-1 {
			ctx = pad8(ctx)
			le.PutUint32(ctx, uint32(len(ctx)))
		}
		out = append(out, ctx...)
	}
	le.PutUint32(out[headerSize+84:], uint32(len(out)-start))
	return statusSuccess, out
}

// parseCreateContexts indexes the create contexts of a request by name.
func parseCreateContexts(msg []byte, off, n uint32) (map[string][]byte, bool) {
	if n == 0 {
		return nil, true
	}
	b, ok := sub(msg, off, n)
	if !ok {
		return nil, false
	}
	out := make(map[string][]byte)
	for len(out) < 64 {
		if len(b) < 16 {
			return nil, false
		}
		next := le.Uint32(b)
		name, ok1 := sub(b, uint32(le.Uint16(b[4:])), uint32(le.Uint16(b[6:])))
		data, ok2 := sub(b, uint32(le.Uint16(b[10:])), le.Uint32(b[12:]))
		if !ok1 || !ok2 {
			return nil, false
		}
		out[string(name)] = data
		if next == 0 {
			return out, true
		}
		if next < 16 || uint64(next) > uint64(len(b)) {
			return nil, false
		}
		b = b[next:]
	}
	return nil, false
}

func createContext(name string, data []byte) []byte {
	b := make([]byte, 24, 24+len(data))
	le.PutUint16(b[4:], 16)
	le.PutUint16(b[6:], 4)
	le.PutUint16(b[10:], 24)
	le.PutUint32(b[12:], uint32(len(data)))
	copy(b[16:], name)
	return append(b, data...)
}

func (c *conn) closeFile(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 24 || le.Uint16(p) != 24 {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[8:24])
	if st != statusSuccess {
		return st, nil
	}
	out := newMsg(60)
	q := out[headerSize:]
	le.PutUint16(q, 60)
	// Flag 1 asks for the attributes of the file as it is being closed.
	if le.Uint16(p[2:])&1 != 0 {
		if info, st := c.srv.stat(o); st == statusSuccess {
			le.PutUint16(q[2:], 1)
			info.putTimes(q[8:])
			le.PutUint64(q[40:], info.alloc)
			le.PutUint64(q[48:], info.size)
			le.PutUint32(q[56:], info.attrs)
		}
	}
	s := r.sess
	s.mu.Lock()
	delete(s.opens, o.id)
	s.mu.Unlock()
	c.srv.release(o)
	r.chain.hasFile = false
	return statusSuccess, out
}
