package smbserver

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
)

const (
	infoFile       = 1
	infoFilesystem = 2
	infoSecurity   = 3
)

// File information classes ([MS-FSCC] 2.4).
const (
	fileBasic          = 4
	fileStandard       = 5
	fileInternal       = 6
	fileEA             = 7
	fileAccess         = 8
	fileRename         = 10
	fileDisposition    = 13
	filePosition       = 14
	fileFullEA         = 15
	fileMode           = 16
	fileAlignment      = 17
	fileAll            = 18
	fileAllocation     = 19
	fileEndOfFile      = 20
	fileAlternateName  = 21
	fileStream         = 22
	fileNetworkOpen    = 34
	fileAttributeTag   = 35
	fileID             = 59
	fileDispositionEx  = 64
	fileRenameEx       = 65
	fsVolume           = 1
	fsSize             = 3
	fsDevice           = 4
	fsAttribute        = 5
	fsFullSize         = 7
	fsSectorSize       = 11
	fsCaseSensitive    = 0x00000001
	fsCasePreserved    = 0x00000002
	fsUnicodeOnDisk    = 0x00000004
	fsNamedStreams     = 0x00040000
	fakeCapacityBlocks = 1 << 28 // 1 TiB in 4 KiB blocks, where statfs is unavailable
)

func (c *conn) queryInfo(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 40 || le.Uint16(p) != 41 {
		return statusInvalidParameter, nil
	}
	kind, class := p[2], p[3]
	limit := le.Uint32(p[4:])
	additional := le.Uint32(p[16:])
	if !c.charged(r, limit) {
		return statusInvalidParameter, nil
	}
	if trace {
		r.note = fmt.Sprintf("type %d class %d", kind, class)
	}
	o, st := c.lookup(r, p[24:40])
	if st != statusSuccess {
		return st, nil
	}

	var data []byte
	switch {
	case kind == infoFile:
		data, st = c.fileInfo(o, class)
	case kind == infoFilesystem:
		data, st = c.filesystemInfo(class)
	case kind == infoSecurity:
		data = c.securityDescriptor(additional)
		if uint32(len(data)) > limit {
			// The one case where the error says how much room is needed.
			return statusBufferTooSmall, errorBody(le.AppendUint32(nil, uint32(len(data))))
		}
	default:
		st = statusNotSupported
	}
	if st != statusSuccess {
		return st, nil
	}
	if uint32(len(data)) > limit {
		data = data[:limit]
		st = statusBufferOverflow
	}
	out := newMsg(8)
	le.PutUint16(out[headerSize:], 9)
	le.PutUint16(out[headerSize+2:], headerSize+8)
	le.PutUint32(out[headerSize+4:], uint32(len(data)))
	out = append(out, data...)
	if len(data) == 0 {
		out = append(out, 0)
	}
	return st, out
}

func (c *conn) fileInfo(o *open, class byte) ([]byte, ntStatus) {
	in, st := c.srv.stat(o)
	if st != statusSuccess {
		return nil, st
	}
	basic := func() []byte {
		b := make([]byte, 40)
		in.putTimes(b)
		le.PutUint32(b[32:], in.attrs)
		return b
	}
	standard := func() []byte {
		b := make([]byte, 24)
		le.PutUint64(b, in.alloc)
		le.PutUint64(b[8:], in.size)
		le.PutUint32(b[16:], in.nlink)
		c.srv.mu.Lock()
		if o.shared != nil && o.shared.deletePending || o.stream != nil && o.deleteOnClose {
			b[20] = 1
		}
		c.srv.mu.Unlock()
		if in.isDir {
			b[21] = 1
		}
		return b
	}
	name := func() []byte {
		p, _ := o.location()
		n := encodeUTF16(wirePath(p))
		return append(le.AppendUint32(nil, uint32(len(n))), n...)
	}
	switch class {
	case fileBasic:
		return basic(), statusSuccess
	case fileStandard:
		return standard(), statusSuccess
	case fileInternal:
		return le.AppendUint64(nil, in.ino), statusSuccess
	case fileEA, fileMode, fileAlignment:
		return make([]byte, 4), statusSuccess
	case fileAccess:
		return le.AppendUint32(nil, o.access), statusSuccess
	case filePosition:
		return make([]byte, 8), statusSuccess
	case fileAll:
		b := append(basic(), standard()...)
		b = le.AppendUint64(b, in.ino)
		b = le.AppendUint32(b, 0)        // EA size
		b = le.AppendUint32(b, o.access) // access
		b = le.AppendUint64(b, 0)        // position
		b = le.AppendUint32(b, 0)        // mode
		b = le.AppendUint32(b, 0)        // alignment
		return append(b, name()...), statusSuccess
	case fileStream:
		key := o.streamKey
		if o.stream == nil {
			key = o.shared.key
		}
		return c.srv.streamInfo(&in, key), statusSuccess
	case fileNetworkOpen:
		b := make([]byte, 56)
		in.putTimes(b)
		le.PutUint64(b[32:], in.alloc)
		le.PutUint64(b[40:], in.size)
		le.PutUint32(b[48:], in.attrs)
		return b, statusSuccess
	case fileAttributeTag:
		b := make([]byte, 8)
		le.PutUint32(b, in.attrs)
		return b, statusSuccess
	case fileID:
		b := make([]byte, 24)
		le.PutUint64(b, in.dev)
		le.PutUint64(b[8:], in.ino)
		return b, statusSuccess
	case fileFullEA:
		return nil, statusNoEasOnFile
	case fileAlternateName:
		// No 8.3 names.
		return nil, statusObjectNameNotFound
	}
	return nil, statusInvalidInfoClass
}

func (c *conn) filesystemInfo(class byte) ([]byte, ntStatus) {
	s := c.srv
	switch class {
	case fsVolume:
		label := encodeUTF16(s.cfg.Share)
		b := make([]byte, 18, 18+len(label))
		le.PutUint64(b, filetime(s.start))
		le.PutUint32(b[8:], le.Uint32(s.guid[:]))
		le.PutUint32(b[12:], uint32(len(label)))
		return append(b, label...), statusSuccess
	case fsSize, fsFullSize:
		total, free, avail, unit, err := diskSpace(s.rootPath)
		if err != nil || unit == 0 {
			total, free, avail, unit = fakeCapacityBlocks, fakeCapacityBlocks/2, fakeCapacityBlocks/2, 4096
		}
		// Clients multiply units by sectors by bytes: a 512-byte sector
		// lets any block size that is a multiple of it come out exact.
		sectors := max(unit/512, 1)
		if class == fsSize {
			b := make([]byte, 24)
			le.PutUint64(b, total)
			le.PutUint64(b[8:], avail)
			le.PutUint32(b[16:], sectors)
			le.PutUint32(b[20:], 512)
			return b, statusSuccess
		}
		b := make([]byte, 32)
		le.PutUint64(b, total)
		le.PutUint64(b[8:], avail)
		le.PutUint64(b[16:], free)
		le.PutUint32(b[24:], sectors)
		le.PutUint32(b[28:], 512)
		return b, statusSuccess
	case fsDevice:
		b := make([]byte, 8)
		le.PutUint32(b, 7)        // FILE_DEVICE_DISK
		le.PutUint32(b[4:], 0x20) // FILE_DEVICE_IS_MOUNTED
		return b, statusSuccess
	case fsAttribute:
		// Names are stored as the client spells them, on a filesystem
		// that tells cases apart: saying so keeps a case-sensitive client
		// from being lied to. ACLs are not advertised because they are
		// not there.
		name := encodeUTF16("NTFS")
		b := make([]byte, 12, 12+len(name))
		le.PutUint32(b, fsCaseSensitive|fsCasePreserved|fsUnicodeOnDisk|fsNamedStreams)
		le.PutUint32(b[4:], 255)
		le.PutUint32(b[8:], uint32(len(name)))
		return append(b, name...), statusSuccess
	case fsSectorSize:
		b := make([]byte, 28)
		for i := 0; i < 16; i += 4 {
			le.PutUint32(b[i:], 512)
		}
		le.PutUint32(b[16:], 3) // aligned device, partition aligned on device
		return b, statusSuccess
	}
	return nil, statusInvalidInfoClass
}

// securityDescriptor is the minimal descriptor clients insist on reading:
// one owner, one group, and a DACL granting everyone full control. Access is
// really decided by the single account of the server and by the permissions
// of the files for the uid of the process.
func (c *conn) securityDescriptor(want uint32) []byte {
	// A machine-local SID derived from the server GUID, so that it is
	// stable for the life of the server and unique across servers.
	sid := func(rid uint32) []byte {
		b := []byte{1, 5, 0, 0, 0, 0, 0, 5}
		b = le.AppendUint32(b, 21)
		b = append(b, c.srv.guid[:12]...)
		return le.AppendUint32(b, rid)
	}
	everyone := []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}

	const selfRelative, daclPresent = 0x8000, 0x0004
	b := make([]byte, 20)
	b[0] = 1
	control := uint16(selfRelative)
	if want&1 != 0 {
		le.PutUint32(b[4:], uint32(len(b)))
		b = append(b, sid(1000)...)
	}
	if want&2 != 0 {
		le.PutUint32(b[8:], uint32(len(b)))
		b = append(b, sid(513)...)
	}
	if want&4 != 0 {
		control |= daclPresent
		le.PutUint32(b[16:], uint32(len(b)))
		ace := []byte{0, 0, 0, 0}
		le.PutUint16(ace[2:], uint16(8+len(everyone)))
		ace = le.AppendUint32(ace, accessAll)
		ace = append(ace, everyone...)
		acl := []byte{2, 0, 0, 0, 1, 0, 0, 0}
		le.PutUint16(acl[2:], uint16(8+len(ace)))
		b = append(append(b, acl...), ace...)
	}
	le.PutUint16(b[2:], control)
	return b
}

func (c *conn) setInfo(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 32 || le.Uint16(p) != 33 {
		return statusInvalidParameter, nil
	}
	kind, class := p[2], p[3]
	data, ok := sub(r.msg, uint32(le.Uint16(p[8:])), le.Uint32(p[4:]))
	if !ok {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[16:32])
	if st != statusSuccess {
		return st, nil
	}
	if c.srv.cfg.ReadOnly {
		return statusAccessDenied, nil
	}
	switch kind {
	case infoFile:
		st = c.setFileInfo(o, class, data)
	case infoSecurity:
		// Accepted and ignored: clients copying a file replay its ACL
		// and would report a failure the user can do nothing about.
	default:
		st = statusNotSupported
	}
	if st != statusSuccess {
		return st, nil
	}
	out := newMsg(2)
	le.PutUint16(out[headerSize:], 2)
	return statusSuccess, out
}

func (c *conn) setFileInfo(o *open, class byte, data []byte) ntStatus {
	s := c.srv
	p, f := o.location()
	if o.stream != nil {
		return c.setStreamInfo(o, class, data)
	}
	switch class {
	case fileBasic:
		if len(data) < 36 {
			return statusInfoLengthMismatch
		}
		return s.setBasic(p, data)
	case fileEndOfFile, fileAllocation:
		if len(data) < 8 {
			return statusInfoLengthMismatch
		}
		size := le.Uint64(data)
		if f == nil || o.access&(fileWriteData|fileAppendData) == 0 {
			return statusAccessDenied
		}
		if size > math.MaxInt64 {
			return statusInvalidParameter
		}
		s.breakOplocks(c, o.shared)
		if class == fileAllocation {
			// Allocation is advisory, except that shrinking it below the
			// end of the file truncates.
			fi, err := f.Stat()
			if err != nil {
				return errStatus(err)
			}
			if int64(size) >= fi.Size() {
				return statusSuccess
			}
		}
		return errStatus(f.Truncate(int64(size)))
	case fileDisposition, fileDispositionEx:
		if len(data) < 1 {
			return statusInfoLengthMismatch
		}
		if o.access&accessDelete == 0 {
			return statusAccessDenied
		}
		pending := data[0]&1 != 0
		if pending && o.isDir {
			if st := s.emptyDir(p); st != statusSuccess {
				return st
			}
		}
		s.mu.Lock()
		o.shared.deletePending = pending
		s.mu.Unlock()
		if !pending {
			o.mu.Lock()
			o.deleteOnClose = false
			o.mu.Unlock()
		}
		return statusSuccess
	case fileRename, fileRenameEx:
		if len(data) < 20 {
			return statusInfoLengthMismatch
		}
		raw, ok := sub(data, 20, le.Uint32(data[16:]))
		if !ok {
			return statusInvalidParameter
		}
		// A non-zero root directory handle would make the name relative
		// to it; no client uses that over SMB2.
		if le.Uint64(data[8:]) != 0 {
			return statusInvalidParameter
		}
		target, st := parsePath(decodeUTF16(raw))
		if st != statusSuccess {
			return st
		}
		if target == "." {
			return statusObjectNameInvalid
		}
		replace := data[0]&1 != 0
		if o.access&accessDelete == 0 {
			return statusAccessDenied
		}
		return s.rename(p, target, replace)
	case filePosition, fileMode:
		return statusSuccess
	case fileFullEA:
		return statusEasNotSupported
	}
	return statusInvalidInfoClass
}

// setStreamInfo is setFileInfo for a handle on a named stream: it has a
// length and can be deleted, the rest belongs to its file.
func (c *conn) setStreamInfo(o *open, class byte, data []byte) ntStatus {
	switch class {
	case fileEndOfFile, fileAllocation:
		if len(data) < 8 {
			return statusInfoLengthMismatch
		}
		if o.access&(fileWriteData|fileAppendData) == 0 {
			return statusAccessDenied
		}
		size := le.Uint64(data)
		if class == fileAllocation && size >= c.srv.streamSize(o.stream) {
			return statusSuccess
		}
		return c.srv.truncateStream(o.stream, size)
	case fileDisposition, fileDispositionEx:
		if len(data) < 1 {
			return statusInfoLengthMismatch
		}
		if o.access&accessDelete == 0 {
			return statusAccessDenied
		}
		c.srv.mu.Lock()
		o.deleteOnClose = data[0]&1 != 0
		c.srv.mu.Unlock()
		return statusSuccess
	case fileBasic, filePosition, fileMode:
		return statusSuccess
	}
	return statusNotSupported
}

// setBasic applies FileBasicInformation: the timestamps POSIX can set, and
// the read-only attribute, expressed as the write permission bits.
func (s *server) setBasic(p string, data []byte) ntStatus {
	atime, mtime := fromFiletime(le.Uint64(data[8:])), fromFiletime(le.Uint64(data[16:]))
	if !atime.IsZero() || !mtime.IsZero() {
		if err := s.root.Chtimes(p, atime, mtime); err != nil {
			return errStatus(err)
		}
	}
	// Zero attributes mean "leave them alone".
	if attrs := le.Uint32(data[32:]); attrs != 0 {
		fi, err := s.root.Stat(p)
		if err != nil {
			return errStatus(err)
		}
		if !fi.IsDir() {
			mode := fi.Mode().Perm()
			readOnly := mode&0o222 == 0
			switch {
			case attrs&attrReadOnly != 0 && !readOnly:
				err = s.root.Chmod(p, mode&^0o222)
			case attrs&attrReadOnly == 0 && readOnly:
				err = s.root.Chmod(p, mode|0o200)
			}
			if err != nil {
				return errStatus(err)
			}
		}
	}
	return statusSuccess
}

func (s *server) emptyDir(p string) ntStatus {
	d, err := s.root.Open(p)
	if err != nil {
		return errStatus(err)
	}
	defer d.Close()
	if names, _ := d.Readdirnames(1); len(names) > 0 {
		return statusDirectoryNotEmpty
	}
	return statusSuccess
}

// occupied reports whether the target of a rename or link is taken. The check
// and the operation that follows are not atomic with respect to processes
// outside the server, which POSIX gives no portable way to achieve.
func (s *server) occupied(target string, replace bool) ntStatus {
	fi, err := s.root.Lstat(target)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return statusSuccess
	case err != nil:
		return errStatus(err)
	case !replace:
		return statusObjectNameCollision
	case fi.IsDir():
		return statusAccessDenied
	}
	return statusSuccess
}

func (s *server) rename(from, to string, replace bool) ntStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from == to {
		return statusSuccess
	}
	if st := s.occupied(to, replace); st != statusSuccess {
		return st
	}
	if err := s.root.Rename(from, to); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s.missing(to)
		}
		return errStatus(err)
	}
	s.renamed(from, to)
	return statusSuccess
}
