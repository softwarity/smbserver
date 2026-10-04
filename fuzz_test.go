package smbserver

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fuzz targets feed the decoders what a hostile client could send. The
// property is the same everywhere: no panic, and for the paths, no way out
// of the root.

// sink is the network side of a connection under fuzzing: it accepts and
// forgets whatever the server writes.
type sink struct{}

func (sink) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (sink) Write(b []byte) (int, error)      { return len(b), nil }
func (sink) Close() error                     { return nil }
func (sink) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (sink) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (sink) SetDeadline(time.Time) error      { return nil }
func (sink) SetReadDeadline(time.Time) error  { return nil }
func (sink) SetWriteDeadline(time.Time) error { return nil }

func fuzzServer(f *testing.F) *server {
	root := f.TempDir()
	os.WriteFile(filepath.Join(root, "file"), []byte("some content"), 0o644)
	os.MkdirAll(filepath.Join(root, "dir", "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "dir", "inner"), []byte("inner"), 0o644)
	s, err := newServer(Config{Root: root, Share: testShare, User: testUser, NTHash: NTHash(testPassword)})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { s.root.Close() })
	return s
}

// FuzzPreAuth sends arbitrary frames to a connection that has not logged in.
func FuzzPreAuth(f *testing.F) {
	s := fuzzServer(f)
	c := &testClient{t: f}
	body := make([]byte, 36)
	le.PutUint16(body, 36)
	le.PutUint16(body[2:], 2)
	body = le.AppendUint16(le.AppendUint16(body, dialect202), dialect210)
	f.Add(c.request(cmdNegotiate, body))
	f.Add(smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???"))
	f.Add(c.request(cmdSessionSetup, sessionSetupBody(negTokenInit())))
	f.Add(c.request(cmdSessionSetup, sessionSetupBody(append([]byte(ntlmSignature), 1, 0, 0, 0, 0, 0, 0, 0))))
	f.Add(c.request(cmdEcho, []byte{4, 0, 0, 0}))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Each input is a sequence of frames on one connection, split
		// the way the transport would: negotiate first, then the rest.
		c := s.newConn(sink{})
		defer c.close()
		for _, msg := range [][]byte{f0(data), data} {
			if len(msg) < 4 {
				return
			}
			if c.handleFrame(msg) != nil {
				return
			}
		}
	})
}

// f0 is a valid NEGOTIATE, so that half of the fuzzing effort goes to the
// state that follows it.
func f0(data []byte) []byte {
	if len(data) == 0 || data[0]&1 == 0 {
		return data
	}
	body := make([]byte, 36)
	le.PutUint16(body, 36)
	le.PutUint16(body[2:], 1)
	return (&testClient{}).request(cmdNegotiate, le.AppendUint16(body, dialect210))
}

// FuzzMessage sends arbitrary messages on an authenticated session. The
// harness signs them, since the point is to reach the command decoders and
// not to forge a signature.
func FuzzMessage(f *testing.F) {
	s := fuzzServer(f)
	key := bytes.Repeat([]byte{7}, 16)
	c := &testClient{t: f, key: key, sessionID: 1, treeID: 1}
	related := bytes.Repeat([]byte{0xFF}, 16)

	// One seed per command, each as a related chain behind a CREATE so
	// that it operates on a real handle.
	file := createBody("file", accessRW, dispOpenIf, 0)
	openDir := createBody("dir", accessRead, dispOpen, optDirectory)
	lock := make([]byte, 24)
	le.PutUint16(lock, 48)
	le.PutUint16(lock[2:], 1)
	copy(lock[8:], related)
	lock = append(lock, make([]byte, 24)...)
	lock[24+8], lock[24+16] = 10, lockExclusive
	ioctl := make([]byte, 57)
	le.PutUint16(ioctl, 57)
	le.PutUint32(ioctl[4:], fsctlDFSGetReferrals)
	notify := make([]byte, 32)
	le.PutUint16(notify, 32)
	copy(notify[8:], related)
	flush := closeBody(related)
	seeds := []struct {
		cmds   []uint16
		bodies [][]byte
	}{
		{[]uint16{cmdCreate, cmdRead, cmdClose}, [][]byte{file, readBody(related, 0, 100), closeBody(related)}},
		{[]uint16{cmdCreate, cmdWrite, cmdFlush}, [][]byte{file, writeBody(related, 3, []byte("data")), flush}},
		{[]uint16{cmdCreate, cmdQueryDirectory}, [][]byte{openDir, queryDirectoryBody(related, classIDBoth, "*", 65536)}},
		{[]uint16{cmdCreate, cmdQueryDirectory}, [][]byte{openDir, queryDirectoryBody(related, classNames, "in*", 200)}},
		{[]uint16{cmdCreate, cmdQueryInfo}, [][]byte{file, queryInfoBody(related, infoFile, fileAll, 4096)}},
		{[]uint16{cmdCreate, cmdQueryInfo}, [][]byte{file, queryInfoBody(related, infoFilesystem, fsAttribute, 4096)}},
		{[]uint16{cmdCreate, cmdQueryInfo}, [][]byte{file, queryInfoBody(related, infoSecurity, 0, 4096)}},
		{[]uint16{cmdCreate, cmdSetInfo}, [][]byte{file, setInfoBody(related, fileRename, renameData(`dir\moved`, true))}},
		{[]uint16{cmdCreate, cmdSetInfo}, [][]byte{file, setInfoBody(related, fileEndOfFile, make([]byte, 8))}},
		{[]uint16{cmdCreate, cmdSetInfo}, [][]byte{file, setInfoBody(related, fileBasic, make([]byte, 40))}},
		{[]uint16{cmdCreate, cmdSetInfo}, [][]byte{file, setInfoBody(related, fileDisposition, []byte{1})}},
		{[]uint16{cmdCreate, cmdLock}, [][]byte{file, lock}},
		{[]uint16{cmdCreate, cmdWrite, cmdRead}, [][]byte{createBody("file:meta:$DATA", accessRW, dispOpenIf, 0), writeBody(related, 2, []byte("stream")), readBody(related, 0, 100)}},
		{[]uint16{cmdCreate, cmdQueryInfo}, [][]byte{file, queryInfoBody(related, infoFile, fileStream, 4096)}},
		{[]uint16{cmdCreate, cmdChangeNotify}, [][]byte{openDir, notify}},
		{[]uint16{cmdIoctl}, [][]byte{ioctl}},
		{[]uint16{cmdEcho, cmdTreeDisconnect, cmdLogoff}, [][]byte{{4, 0, 0, 0}, {4, 0, 0, 0}, {4, 0, 0, 0}}},
		{[]uint16{cmdTreeConnect}, [][]byte{append([]byte{9, 0, 0, 0, 72, 0, 10, 0}, encodeUTF16(`\\s\vol`)...)}},
	}
	for _, seed := range seeds {
		f.Add(c.compound(seed.cmds, seed.bodies))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		c := s.newConn(sink{})
		defer c.close()
		c.setDialect(dialect210)
		c.authenticated = true
		c.credits = maxCredits
		sess := &session{id: 1, conn: c, authenticated: true, signingKey: key,
			trees: map[uint32]*tree{1: {id: 1}, 2: {id: 2, ipc: true}}, opens: map[uint64]*open{}}
		c.sessions[1] = sess

		// Sign every command of the chain, following the same links the
		// server follows.
		msg := bytes.Clone(data)
		for off := 0; len(msg)-off >= headerSize; {
			next := int(le.Uint32(msg[off+20:]))
			end := len(msg)
			if next >= headerSize && next <= len(msg)-off-headerSize {
				end = off + next
			}
			le.PutUint64(msg[off+40:], 1)
			sign(key, msg[off:end])
			if end == len(msg) {
				break
			}
			off = end
		}
		if len(msg) < 4 {
			return
		}
		c.handleFrame(msg)

		// Whatever the message did, it did it inside the root.
		if entries, err := os.ReadDir(filepath.Dir(s.rootPath)); err == nil && len(entries) != 1 {
			t.Fatalf("something appeared next to the root: %v", entries)
		}
	})
}

func FuzzSPNEGO(f *testing.F) {
	f.Add(negTokenInit())
	f.Add(negTokenResp(negAcceptIncomplete, true, []byte(ntlmSignature), []byte("mic")))
	f.Add([]byte(ntlmSignature))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseSPNEGO(data)
	})
}

func FuzzNTLM(f *testing.F) {
	hash := NTHash(testPassword)
	f.Add(append([]byte(ntlmSignature), 1, 0, 0, 0, 1, 2, 3, 4), authenticateMessage(testUser, "D", make([]byte, 60), make([]byte, 16)))
	f.Fuzz(func(t *testing.T, negotiate, authenticate []byte) {
		var a ntlmAuth
		a.start(negotiate, time.Unix(0, 0))
		if a.authenticate(authenticate, testUser, hash) {
			// Guessing a valid response is not something a fuzzer
			// does; if it happens the check is broken.
			t.Fatal("random data authenticated")
		}
		avFlags(authenticate)
	})
}

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{"", "a", `a\b`, `..\x`, "a", "", `a\..\..\b`, "x:y", `\\server\share`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		p, st := parsePath(name)
		if st != statusSuccess {
			return
		}
		// An accepted path is local: relative, and without any element
		// that could climb out.
		if p != "." && !filepath.IsLocal(filepath.FromSlash(p)) {
			t.Fatalf("parsePath(%q) = %q, which is not local", name, p)
		}
		for _, part := range strings.Split(p, "/") {
			if part == ".." || part == "" {
				t.Fatalf("parsePath(%q) = %q", name, p)
			}
		}
		matchPattern(name, p)
		nameToWire(p)
	})
}
