package smbserver

import (
	"strings"
)

// Named streams, kept in memory.
//
// A macOS client attaches metadata to the files it copies: Finder
// information, a quarantine flag, any extended attribute. On a server
// without named streams it stores them in "._name" AppleDouble files next to
// the originals, which litters a volume that belongs to a workload and not
// to the developer's desktop. So the server offers named streams, and keeps
// what is written to them in memory: nothing reaches the volume, whatever
// its filesystem supports, and the metadata lives as long as the server
// does, which is as long as anyone could want desktop metadata on a cluster
// volume.

const (
	maxStreamSize     = 16 << 20
	maxStreamsTotal   = 64 << 20
	maxStreamsPerFile = 64
)

// memStream is the content of one named stream. The server lock guards it.
type memStream struct {
	name string
	data []byte
}

// parseName splits the name of a CREATE into the path of the file and the
// name of the stream, empty for the file itself. The syntax is
// "path:stream:$DATA", the type being optional.
func parseName(name string) (string, string, ntStatus) {
	file := name
	stream := ""
	if i := strings.IndexByte(name[strings.LastIndexByte(name, '\\')+1:], ':'); i >= 0 {
		i += strings.LastIndexByte(name, '\\') + 1
		file = name[:i]
		var kind string
		stream, kind, _ = strings.Cut(name[i+1:], ":")
		if kind != "" && !strings.EqualFold(kind, "$DATA") || len(stream) > 255 || strings.ContainsAny(stream, "\\/:\x00") {
			return "", "", statusObjectNameInvalid
		}
	}
	p, st := parsePath(file)
	return p, stream, st
}

// openStream implements CREATE for a named stream of an existing file.
func (s *server) openStream(r *request, p, name string, desired, disp uint32, opts uint32) (*open, uint32, ntStatus) {
	if disp > dispOverwriteIf {
		return nil, 0, statusInvalidParameter
	}
	access := normalizeAccess(desired)
	if s.cfg.ReadOnly {
		// Streams are not part of the volume, but a share announced as
		// read-only is read-only for them too.
		if desired&accessMaximum != 0 && desired&(accessGenericAll|accessGenericWrite) == 0 {
			access = normalizeAccess(desired&^accessMaximum) | accessReadOnly
		}
		if access&accessModifying != 0 || opts&optDeleteOnClose != 0 || disp != dispOpen {
			return nil, 0, statusAccessDenied
		}
	}
	if opts&optDirectory != 0 {
		return nil, 0, statusNotADirectory
	}
	fi, err := s.root.Stat(p)
	if err != nil {
		return nil, 0, errStatus(err)
	}
	key := keyOf(fi, p)
	id := strings.ToLower(name)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nOpens >= maxOpens {
		return nil, 0, statusTooManyOpenedFiles
	}
	ms := s.streams[key][id]
	action := actionOpened
	switch {
	case ms == nil:
		if disp == dispOpen || disp == dispOverwrite {
			return nil, 0, statusObjectNameNotFound
		}
		if len(s.streams[key]) >= maxStreamsPerFile {
			return nil, 0, statusInsufficientResources
		}
		if s.streams[key] == nil {
			s.streams[key] = make(map[string]*memStream)
		}
		ms = &memStream{name: name}
		s.streams[key][id] = ms
		action = actionCreated
	case disp == dispCreate:
		return nil, 0, statusObjectNameCollision
	case disp == dispSupersede || disp == dispOverwrite || disp == dispOverwriteIf:
		s.streamBytes -= int64(len(ms.data))
		ms.data = nil
		action = actionOverwritten
	}
	s.nOpens++
	return &open{
		id:            s.newID(),
		sess:          r.sess,
		tree:          r.tree,
		access:        access,
		path:          p,
		stream:        ms,
		streamKey:     key,
		deleteOnClose: opts&optDeleteOnClose != 0,
	}, action, statusSuccess
}

// releaseStream closes a handle on a stream.
func (s *server) releaseStream(o *open) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nOpens--
	if !o.deleteOnClose {
		return
	}
	id := strings.ToLower(o.stream.name)
	if s.streams[o.streamKey][id] == o.stream {
		s.streamBytes -= int64(len(o.stream.data))
		delete(s.streams[o.streamKey], id)
		if len(s.streams[o.streamKey]) == 0 {
			delete(s.streams, o.streamKey)
		}
	}
}

// dropStreams forgets the streams of a file that is gone. Called with s.mu
// held.
func (s *server) dropStreams(key fileKey) {
	for _, ms := range s.streams[key] {
		s.streamBytes -= int64(len(ms.data))
	}
	delete(s.streams, key)
}

func (s *server) streamSize(ms *memStream) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(ms.data))
}

func (s *server) readStream(ms *memStream, b []byte, off uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if off >= uint64(len(ms.data)) {
		return 0
	}
	return copy(b, ms.data[off:])
}

// resizeStream sets the length of a stream, within the memory the server
// grants to streams. Called with s.mu held.
func (s *server) resizeStream(ms *memStream, size uint64) ntStatus {
	if size > maxStreamSize || s.streamBytes+int64(size)-int64(len(ms.data)) > maxStreamsTotal {
		return statusDiskFull
	}
	s.streamBytes += int64(size) - int64(len(ms.data))
	if size <= uint64(len(ms.data)) {
		ms.data = ms.data[:size]
	} else {
		ms.data = append(ms.data, make([]byte, size-uint64(len(ms.data)))...)
	}
	return statusSuccess
}

func (s *server) writeStream(ms *memStream, b []byte, off uint64) ntStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if off > maxStreamSize {
		return statusDiskFull
	}
	if end := off + uint64(len(b)); end > uint64(len(ms.data)) {
		if st := s.resizeStream(ms, end); st != statusSuccess {
			return st
		}
	}
	copy(ms.data[off:], b)
	return statusSuccess
}

func (s *server) truncateStream(ms *memStream, size uint64) ntStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resizeStream(ms, size)
}

// streamInfo builds FileStreamInformation: the data stream of a file, then
// its named streams.
func (s *server) streamInfo(in *fileInfo, key fileKey) []byte {
	type entry struct {
		name        string
		size, alloc uint64
	}
	var entries []entry
	if !in.isDir {
		entries = append(entries, entry{"::$DATA", in.size, in.alloc})
	}
	s.mu.Lock()
	for _, ms := range s.streams[key] {
		n := uint64(len(ms.data))
		entries = append(entries, entry{":" + ms.name + ":$DATA", n, (n + 4095) &^ 4095})
	}
	s.mu.Unlock()
	var out []byte
	last := 0
	for i, e := range entries {
		if i > 0 {
			out = pad8(out)
			le.PutUint32(out[last:], uint32(len(out)-last))
		}
		last = len(out)
		name := encodeUTF16(e.name)
		out = append(out, make([]byte, 24)...)
		le.PutUint32(out[last+4:], uint32(len(name)))
		le.PutUint64(out[last+8:], e.size)
		le.PutUint64(out[last+16:], e.alloc)
		out = append(out, name...)
	}
	return out
}
