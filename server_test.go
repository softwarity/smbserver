package smbserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// This file drives the server over a real socket with a minimal SMB 2.1
// client written for the purpose. It covers what must hold whatever the
// client: authentication, signing, confinement to the root, read-only mode,
// the source filter and the resource bounds. The behaviour of the native
// clients is covered by the integration scripts under test/.

const (
	testUser     = "tester"
	testPassword = "correct horse"
	testShare    = "vol"
)

// startServer serves root on a loopback port until the test ends.
func startServer(t *testing.T, cfg Config) string {
	t.Helper()
	if cfg.Root == "" {
		cfg.Root = t.TempDir()
	}
	cfg.Share, cfg.User, cfg.NTHash = testShare, testUser, NTHash(testPassword)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

type testClient struct {
	t         testing.TB
	nc        net.Conn
	messageID uint64
	sessionID uint64
	treeID    uint32
	key       []byte
	// breaks counts the oplock break notifications received.
	breaks int
}

func dial(t testing.TB, addr string) *testClient {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	nc.SetDeadline(time.Now().Add(20 * time.Second))
	return &testClient{t: t, nc: nc}
}

// request builds a command: header, then body. It is signed when the client
// holds a session key.
func (c *testClient) request(cmd uint16, body []byte) []byte {
	msg := make([]byte, headerSize, headerSize+len(body))
	h := header{
		creditCharge: uint16(max((len(body)-1)/0x10000+1, 1)),
		command:      cmd,
		credits:      64,
		messageID:    c.messageID,
		treeID:       c.treeID,
		sessionID:    c.sessionID,
	}
	c.messageID += uint64(h.creditCharge)
	h.put(msg)
	msg = append(msg, body...)
	if c.key != nil {
		sign(c.key, msg)
	}
	return msg
}

func (c *testClient) send(msg []byte) {
	c.t.Helper()
	frame := []byte{0, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	if _, err := c.nc.Write(append(frame, msg...)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *testClient) recv() ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c.nc, h[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, int(h[1])<<16|int(h[2])<<8|int(h[3]))
	_, err := io.ReadFull(c.nc, msg)
	return msg, err
}

// do sends one command and returns the status and the whole response. The
// signature of a signed response is checked.
func (c *testClient) do(cmd uint16, body []byte) (ntStatus, []byte) {
	c.t.Helper()
	c.send(c.request(cmd, body))
	resp, err := c.recv()
	// Oplock breaks arrive unsolicited, ahead of the response.
	for err == nil && isBreak(resp) {
		c.breaks++
		resp, err = c.recv()
	}
	if err != nil {
		c.t.Fatalf("command %d: %v", cmd, err)
	}
	h, ok := parseHeader(resp)
	if !ok || h.command != cmd || h.flags&flagResponse == 0 {
		c.t.Fatalf("command %d: unexpected response %x", cmd, resp)
	}
	if h.flags&flagSigned != 0 && c.key != nil && !verify(c.key, bytes.Clone(resp)) {
		c.t.Fatalf("command %d: bad response signature", cmd)
	}
	if c.key != nil && h.flags&flagSigned == 0 && h.status == statusSuccess {
		c.t.Fatalf("command %d: successful response is not signed", cmd)
	}
	return h.status, resp
}

func isBreak(msg []byte) bool {
	h, ok := parseHeader(msg)
	return ok && h.command == cmdOplockBreak && h.messageID == ^uint64(0)
}

func (c *testClient) negotiate(dialects ...uint16) (ntStatus, []byte) {
	body := make([]byte, 36)
	le.PutUint16(body, 36)
	le.PutUint16(body[2:], uint16(len(dialects)))
	le.PutUint16(body[4:], secModeSigningEnabled)
	for _, d := range dialects {
		body = le.AppendUint16(body, d)
	}
	return c.do(cmdNegotiate, body)
}

func sessionSetupBody(token []byte) []byte {
	body := make([]byte, 24)
	le.PutUint16(body, 25)
	le.PutUint16(body[12:], headerSize+24)
	le.PutUint16(body[14:], uint16(len(token)))
	return append(body, token...)
}

// login runs the NTLMv2 exchange inside SPNEGO, as the native clients do.
func (c *testClient) login(user, password string) ntStatus {
	c.t.Helper()
	negotiate := append([]byte(ntlmSignature), 1, 0, 0, 0)
	negotiate = le.AppendUint32(negotiate, ntlmUnicode|ntlmNTLM|ntlmExtendedSession|ntlmSign|ntlm128)
	mechs := derTLV(0x30, derTLV(0x06, oidNTLM))
	init := derTLV(0x60, derTLV(0x06, oidSPNEGO), derTLV(0xA0, derTLV(0x30,
		derTLV(0xA0, mechs), derTLV(0xA2, derTLV(0x04, negotiate)))))

	st, resp := c.do(cmdSessionSetup, sessionSetupBody(init))
	if st != statusMoreProcessingRequired {
		return st
	}
	h, _ := parseHeader(resp)
	c.sessionID = h.sessionID
	p := resp[headerSize:]
	blob, _ := sub(resp, uint32(le.Uint16(p[4:])), uint32(le.Uint16(p[6:])))
	tok, ok := parseSPNEGO(blob)
	if !ok || !isNTLM(tok.mechToken, 2) {
		c.t.Fatalf("no NTLM challenge in %x", blob)
	}
	challenge := tok.mechToken
	nonce := challenge[24:32]
	info, _ := sub(challenge, le.Uint32(challenge[44:]), uint32(le.Uint16(challenge[40:])))

	hash := NTHash(password)
	owf := hmacMD5(hash[:], encodeUTF16("TESTER"+"WORKGROUP"))
	if user != testUser {
		owf = hmacMD5(hash[:], encodeUTF16(user+"WORKGROUP"))
	}
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = le.AppendUint64(temp, filetime(time.Now()))
	temp = append(temp, 1, 2, 3, 4, 5, 6, 7, 8)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, info...)
	temp = append(temp, 0, 0, 0, 0)
	proof := hmacMD5(owf, nonce, temp)
	auth := authenticateMessage(user, "WORKGROUP", append(proof, temp...), nil)

	st, _ = c.do(cmdSessionSetup, sessionSetupBody(negTokenResp(negAcceptIncomplete, false, auth, nil)))
	if st == statusSuccess {
		c.key = hmacMD5(owf, proof)
	} else {
		c.sessionID = 0
	}
	return st
}

func (c *testClient) treeConnect(share string) ntStatus {
	path := encodeUTF16(`\\server\` + share)
	body := make([]byte, 8)
	le.PutUint16(body, 9)
	le.PutUint16(body[4:], headerSize+8)
	le.PutUint16(body[6:], uint16(len(path)))
	st, resp := c.do(cmdTreeConnect, append(body, path...))
	if st == statusSuccess {
		h, _ := parseHeader(resp)
		c.treeID = h.treeID
	}
	return st
}

// connect returns a client logged in and connected to the share.
func connect(t testing.TB, addr string) *testClient {
	t.Helper()
	c := dial(t, addr)
	if st, _ := c.negotiate(dialect202, dialect210, dialect300, dialect311); st != statusSuccess {
		t.Fatalf("negotiate: %#x", uint32(st))
	}
	if st := c.login(testUser, testPassword); st != statusSuccess {
		t.Fatalf("login: %#x", uint32(st))
	}
	if st := c.treeConnect(testShare); st != statusSuccess {
		t.Fatalf("tree connect: %#x", uint32(st))
	}
	return c
}

func createBody(name string, access, disposition, options uint32) []byte {
	n := encodeUTF16(name)
	body := make([]byte, 56)
	le.PutUint16(body, 57)
	le.PutUint32(body[24:], access)
	le.PutUint32(body[32:], 7)
	le.PutUint32(body[36:], disposition)
	le.PutUint32(body[40:], options)
	le.PutUint16(body[44:], headerSize+56)
	le.PutUint16(body[46:], uint16(len(n)))
	if len(n) == 0 {
		return append(body, 0)
	}
	return append(body, n...)
}

// create opens a file and returns its id, or the failure status.
func (c *testClient) create(name string, access, disposition, options uint32) ([]byte, ntStatus) {
	c.t.Helper()
	st, resp := c.do(cmdCreate, createBody(name, access, disposition, options))
	if st != statusSuccess {
		return nil, st
	}
	return resp[headerSize+64 : headerSize+80], st
}

func closeBody(id []byte) []byte {
	body := make([]byte, 24)
	le.PutUint16(body, 24)
	copy(body[8:], id)
	return body
}

func (c *testClient) close(id []byte) ntStatus {
	st, _ := c.do(cmdClose, closeBody(id))
	return st
}

func writeBody(id []byte, off uint64, data []byte) []byte {
	body := make([]byte, 48)
	le.PutUint16(body, 49)
	le.PutUint16(body[2:], headerSize+48)
	le.PutUint32(body[4:], uint32(len(data)))
	le.PutUint64(body[8:], off)
	copy(body[16:], id)
	return append(body, data...)
}

func (c *testClient) write(id []byte, off uint64, data []byte) ntStatus {
	st, _ := c.do(cmdWrite, writeBody(id, off, data))
	return st
}

func readBody(id []byte, off uint64, n uint32) []byte {
	body := make([]byte, 49)
	le.PutUint16(body, 49)
	le.PutUint32(body[4:], n)
	le.PutUint64(body[8:], off)
	copy(body[16:], id)
	return body
}

func (c *testClient) read(id []byte, off uint64, n uint32) ([]byte, ntStatus) {
	st, resp := c.do(cmdRead, readBody(id, off, n))
	if st != statusSuccess {
		return nil, st
	}
	p := resp[headerSize:]
	data, _ := sub(resp, uint32(p[2]), le.Uint32(p[4:]))
	return data, st
}

func queryDirectoryBody(id []byte, class byte, pattern string, limit uint32) []byte {
	n := encodeUTF16(pattern)
	body := make([]byte, 32)
	le.PutUint16(body, 33)
	body[2] = class
	copy(body[8:], id)
	le.PutUint16(body[24:], headerSize+32)
	le.PutUint16(body[26:], uint16(len(n)))
	le.PutUint32(body[28:], limit)
	return append(body, n...)
}

// list returns the names in a directory.
func (c *testClient) list(dir string) []string {
	c.t.Helper()
	id, st := c.create(dir, 0x00100081, dispOpen, optDirectory)
	if st != statusSuccess {
		c.t.Fatalf("open directory %q: %#x", dir, uint32(st))
	}
	defer c.close(id)
	var names []string
	for {
		st, resp := c.do(cmdQueryDirectory, queryDirectoryBody(id, classIDBoth, "*", 4096))
		if st == statusNoMoreFiles {
			return names
		}
		if st != statusSuccess {
			c.t.Fatalf("query directory: %#x", uint32(st))
		}
		p := resp[headerSize:]
		buf, _ := sub(resp, uint32(le.Uint16(p[2:])), le.Uint32(p[4:]))
		for {
			n := le.Uint32(buf[60:])
			names = append(names, nameFromWire(decodeUTF16(buf[104:104+n])))
			next := le.Uint32(buf)
			if next == 0 {
				break
			}
			buf = buf[next:]
		}
	}
}

func queryInfoBody(id []byte, kind, class byte, limit uint32) []byte {
	body := make([]byte, 41)
	le.PutUint16(body, 41)
	body[2], body[3] = kind, class
	le.PutUint32(body[4:], limit)
	copy(body[24:], id)
	return body
}

func setInfoBody(id []byte, class byte, data []byte) []byte {
	body := make([]byte, 32)
	le.PutUint16(body, 33)
	body[2], body[3] = infoFile, class
	le.PutUint32(body[4:], uint32(len(data)))
	le.PutUint16(body[8:], headerSize+32)
	copy(body[16:], id)
	return append(body, data...)
}

func renameData(target string, replace bool) []byte {
	n := encodeUTF16(target)
	data := make([]byte, 20)
	if replace {
		data[0] = 1
	}
	le.PutUint32(data[16:], uint32(len(n)))
	return append(data, n...)
}

const (
	accessRead  = 0x00120089
	accessWrite = 0x00120116
	accessRW    = accessRead | accessWrite | accessDelete
)

func TestNegotiate(t *testing.T) {
	addr := startServer(t, Config{})

	// The ceiling is SMB 2.1, whatever else is offered.
	c := dial(t, addr)
	st, resp := c.negotiate(dialect202, dialect210, dialect300, dialect302, dialect311)
	if st != statusSuccess {
		t.Fatalf("negotiate: %#x", uint32(st))
	}
	p := resp[headerSize:]
	if d := le.Uint16(p[4:]); d != dialect210 {
		t.Errorf("dialect = %#x, want 2.1", d)
	}
	if mode := le.Uint16(p[2:]); mode&secModeSigningRequired == 0 {
		t.Errorf("security mode %#x does not require signing", mode)
	}

	c = dial(t, addr)
	if st, resp := c.negotiate(dialect202); st != statusSuccess || le.Uint16(resp[headerSize+4:]) != dialect202 {
		t.Errorf("SMB 2.0.2 only client: %#x", uint32(st))
	}

	// A client that only knows SMB 3 has nothing in common.
	c = dial(t, addr)
	if st, _ := c.negotiate(dialect300, dialect311); st != statusNotSupported {
		t.Errorf("SMB 3 only client: %#x", uint32(st))
	}
}

func smb1Negotiate(dialects ...string) []byte {
	msg := make([]byte, 35)
	copy(msg, "\xffSMB\x72")
	for _, d := range dialects {
		msg = append(msg, 2)
		msg = append(msg, d...)
		msg = append(msg, 0)
	}
	le.PutUint16(msg[33:], uint16(len(msg)-35))
	return msg
}

func TestSMB1Negotiate(t *testing.T) {
	addr := startServer(t, Config{})

	// A multi-protocol negotiate is steered to SMB2.
	c := dial(t, addr)
	c.send(smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???"))
	resp, err := c.recv()
	if err != nil {
		t.Fatal(err)
	}
	h, ok := parseHeader(resp)
	if !ok || h.command != cmdNegotiate || le.Uint16(resp[headerSize+4:]) != dialectAny {
		t.Fatalf("unexpected answer to the SMB1 negotiate: %x", resp)
	}
	c.messageID = 1
	if st, _ := c.negotiate(dialect202, dialect210); st != statusSuccess {
		t.Fatalf("SMB2 negotiate after the switch: %#x", uint32(st))
	}
	if st := c.login(testUser, testPassword); st != statusSuccess {
		t.Fatalf("login after the switch: %#x", uint32(st))
	}

	// A client that only speaks SMB1 is disconnected.
	c = dial(t, addr)
	c.send(smb1Negotiate("NT LM 0.12"))
	if _, err := c.recv(); err == nil {
		t.Fatal("an SMB1 only client got an answer")
	}
}

func TestAuthentication(t *testing.T) {
	addr := startServer(t, Config{})

	for _, bad := range []struct{ user, password string }{
		{testUser, "wrong"},
		{testUser, ""},
		{"somebody", testPassword},
		{"", ""},
	} {
		c := dial(t, addr)
		c.negotiate(dialect210)
		if st := c.login(bad.user, bad.password); st != statusLogonFailure {
			t.Errorf("login %q/%q: %#x", bad.user, bad.password, uint32(st))
		}
		// And no session exists to connect a tree with.
		if st := c.treeConnect(testShare); st != statusUserSessionDeleted {
			t.Errorf("tree connect after a failed login: %#x", uint32(st))
		}
	}

	// The user name is not case sensitive, as on Windows.
	c := dial(t, addr)
	c.negotiate(dialect210)
	if st := c.login(testUser, testPassword); st != statusSuccess {
		t.Fatalf("login: %#x", uint32(st))
	}
	if st := c.treeConnect("nosuchshare"); st != statusBadNetworkName {
		t.Errorf("unknown share: %#x", uint32(st))
	}
	if st := c.treeConnect("VOL"); st != statusSuccess {
		t.Errorf("share name in another case: %#x", uint32(st))
	}
}

// Nothing but NEGOTIATE, SESSION_SETUP and a bare ECHO is served to a peer
// that has not logged in.
func TestNoOperationBeforeAuthentication(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "secret"), []byte("x"), 0o644)
	addr := startServer(t, Config{Root: root})

	c := dial(t, addr)
	c.negotiate(dialect210)
	for cmd := cmdLogoff; cmd <= cmdOplockBreak; cmd++ {
		if cmd == cmdCancel || cmd == cmdEcho {
			continue
		}
		body := createBody("secret", accessRead, dispOpen, 0)
		if st, _ := c.do(cmd, body); st != statusUserSessionDeleted {
			t.Errorf("command %d before login: %#x", cmd, uint32(st))
		}
	}

	// A command before NEGOTIATE closes the connection.
	c = dial(t, addr)
	c.send(c.request(cmdTreeConnect, make([]byte, 9)))
	c.recv()
	if _, err := c.recv(); err == nil {
		t.Error("the connection survived a command before NEGOTIATE")
	}
}

func TestSigningRequired(t *testing.T) {
	addr := startServer(t, Config{})
	c := connect(t, addr)

	// The same request, unsigned, then with a wrong signature.
	key := c.key
	c.key = nil
	if st, _ := c.do(cmdCreate, createBody("", accessRead, dispOpen, 0)); st != statusAccessDenied {
		t.Errorf("unsigned request: %#x", uint32(st))
	}
	c.key = bytes.Repeat([]byte{1}, 16)
	msg := c.request(cmdCreate, createBody("", accessRead, dispOpen, 0))
	c.key = nil
	c.send(msg)
	resp, _ := c.recv()
	if h, _ := parseHeader(resp); h.status != statusAccessDenied {
		t.Errorf("badly signed request: %#x", uint32(h.status))
	}
	c.key = key
	if _, st := c.create("", accessRead, dispOpen, 0); st != statusSuccess {
		t.Errorf("properly signed request: %#x", uint32(st))
	}
}

func TestFileOperations(t *testing.T) {
	root := t.TempDir()
	addr := startServer(t, Config{Root: root})
	c := connect(t, addr)

	// Create, write, read back.
	id, st := c.create("a.txt", accessRW, dispCreate, optNonDirectory)
	if st != statusSuccess {
		t.Fatalf("create: %#x", uint32(st))
	}
	if st := c.write(id, 0, []byte("hello world")); st != statusSuccess {
		t.Fatalf("write: %#x", uint32(st))
	}
	if data, st := c.read(id, 6, 100); st != statusSuccess || string(data) != "world" {
		t.Fatalf("read: %q %#x", data, uint32(st))
	}
	if _, st := c.read(id, 11, 10); st != statusEndOfFile {
		t.Errorf("read at the end: %#x", uint32(st))
	}
	if got, _ := os.ReadFile(filepath.Join(root, "a.txt")); string(got) != "hello world" {
		t.Errorf("on disk: %q", got)
	}

	// Truncate through the end-of-file information.
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileEndOfFile, le.AppendUint64(nil, 5))); st != statusSuccess {
		t.Fatalf("truncate: %#x", uint32(st))
	}
	if fi, _ := os.Stat(filepath.Join(root, "a.txt")); fi.Size() != 5 {
		t.Errorf("size after truncate: %d", fi.Size())
	}

	// Timestamps.
	when := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	basic := make([]byte, 40)
	le.PutUint64(basic[16:], filetime(when))
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileBasic, basic)); st != statusSuccess {
		t.Fatalf("set times: %#x", uint32(st))
	}
	if fi, _ := os.Stat(filepath.Join(root, "a.txt")); !fi.ModTime().Equal(when) {
		t.Errorf("mtime = %v", fi.ModTime())
	}
	st, resp := c.do(cmdQueryInfo, queryInfoBody(id, infoFile, fileBasic, 40))
	if st != statusSuccess || le.Uint64(resp[headerSize+8+16:]) != filetime(when) {
		t.Errorf("query basic information: %#x", uint32(st))
	}

	// Exclusive creation of something that exists.
	if _, st := c.create("a.txt", accessRW, dispCreate, 0); st != statusObjectNameCollision {
		t.Errorf("create over an existing file: %#x", uint32(st))
	}
	if _, st := c.create("missing", accessRead, dispOpen, 0); st != statusObjectNameNotFound {
		t.Errorf("open a missing file: %#x", uint32(st))
	}
	if _, st := c.create(`nodir\file`, accessRW, dispCreate, 0); st != statusObjectPathNotFound {
		t.Errorf("create under a missing directory: %#x", uint32(st))
	}

	// Directories.
	dir, st := c.create("d", accessRW, dispCreate, optDirectory)
	if st != statusSuccess {
		t.Fatalf("mkdir: %#x", uint32(st))
	}
	if _, st := c.create("d", accessRead, dispOpen, optNonDirectory); st != statusFileIsADirectory {
		t.Errorf("open a directory as a file: %#x", uint32(st))
	}
	if _, st := c.create("a.txt", accessRead, dispOpen, optDirectory); st != statusNotADirectory {
		t.Errorf("open a file as a directory: %#x", uint32(st))
	}

	// Rename into the directory, through the handle.
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileRename, renameData(`d\b.txt`, false))); st != statusSuccess {
		t.Fatalf("rename: %#x", uint32(st))
	}
	if _, err := os.Stat(filepath.Join(root, "d", "b.txt")); err != nil {
		t.Errorf("after rename: %v", err)
	}
	if got := c.list("d"); len(got) != 3 || got[2] != "b.txt" {
		t.Errorf("listing: %q", got)
	}

	// A directory that is not empty cannot be deleted.
	if st, _ := c.do(cmdSetInfo, setInfoBody(dir, fileDisposition, []byte{1})); st != statusDirectoryNotEmpty {
		t.Errorf("delete a non-empty directory: %#x", uint32(st))
	}
	// Delete the file: the handle follows the rename.
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileDisposition, []byte{1})); st != statusSuccess {
		t.Fatalf("delete: %#x", uint32(st))
	}
	c.close(id)
	if _, err := os.Stat(filepath.Join(root, "d", "b.txt")); !os.IsNotExist(err) {
		t.Errorf("after delete: %v", err)
	}
	if st, _ := c.do(cmdSetInfo, setInfoBody(dir, fileDisposition, []byte{1})); st != statusSuccess {
		t.Fatalf("rmdir: %#x", uint32(st))
	}
	c.close(dir)
	if _, err := os.Stat(filepath.Join(root, "d")); !os.IsNotExist(err) {
		t.Errorf("after rmdir: %v", err)
	}

	// Delete on close, as a create option.
	id, _ = c.create("tmp", accessRW, dispCreate, optDeleteOnClose)
	c.close(id)
	if _, err := os.Stat(filepath.Join(root, "tmp")); !os.IsNotExist(err) {
		t.Errorf("delete on close: %v", err)
	}
	if st := c.close(id); st != statusFileClosed {
		t.Errorf("close twice: %#x", uint32(st))
	}

	// Filesystem size.
	id, _ = c.create("", accessRead, dispOpen, 0)
	st, resp = c.do(cmdQueryInfo, queryInfoBody(id, infoFilesystem, fsFullSize, 32))
	if st != statusSuccess || le.Uint64(resp[headerSize+8:]) == 0 {
		t.Errorf("filesystem size: %#x", uint32(st))
	}
}

// compound sends several commands as one related chain.
func (c *testClient) compound(cmds []uint16, bodies [][]byte) []byte {
	var msg []byte
	for i, body := range bodies {
		one := make([]byte, headerSize, headerSize+len(body)+8)
		h := header{creditCharge: 1, command: cmds[i], credits: 8, messageID: c.messageID, treeID: c.treeID, sessionID: c.sessionID}
		c.messageID++
		if i > 0 {
			h.flags = flagRelated
		}
		h.put(one)
		one = append(one, body...)
		if i < len(bodies)-1 {
			one = pad8(one)
			le.PutUint32(one[20:], uint32(len(one)))
		}
		sign(c.key, one)
		msg = append(msg, one...)
	}
	return msg
}

func TestCompound(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("content"), 0o644)
	addr := startServer(t, Config{Root: root})
	c := connect(t, addr)
	related := bytes.Repeat([]byte{0xFF}, 16)

	statuses := func(resp []byte) (out []ntStatus) {
		for {
			h, ok := parseHeader(resp)
			if !ok {
				t.Fatalf("bad compound response")
			}
			out = append(out, h.status)
			if h.next == 0 {
				return out
			}
			resp = resp[h.next:]
		}
	}

	// Create, read and close in one message, the shape every client uses.
	c.send(c.compound([]uint16{cmdCreate, cmdRead, cmdClose},
		[][]byte{createBody("f", accessRead, dispOpen, 0), readBody(related, 0, 100), closeBody(related)}))
	resp, err := c.recv()
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(resp); len(got) != 3 || got[0] != 0 || got[1] != 0 || got[2] != 0 {
		t.Fatalf("statuses: %#x", got)
	}
	if !bytes.Contains(resp, []byte("content")) {
		t.Error("the read of the chain did not return the file")
	}

	// When the create fails, what depended on it fails the same way.
	c.send(c.compound([]uint16{cmdCreate, cmdRead, cmdClose},
		[][]byte{createBody("nope", accessRead, dispOpen, 0), readBody(related, 0, 100), closeBody(related)}))
	resp, _ = c.recv()
	if got := statuses(resp); len(got) != 3 || got[0] != statusObjectNameNotFound || got[1] != got[0] || got[2] != got[0] {
		t.Fatalf("statuses after a failed create: %#x", got)
	}
}

// The share root is a hard boundary: no name, however spelled, and no
// symbolic link reaches outside of it.
func TestConfinement(t *testing.T) {
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644)
	root := filepath.Join(outside, "root")
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "sub", "inside"), []byte("inside"), 0o644)

	links := runtime.GOOS != "windows"
	if links {
		for name, target := range map[string]string{
			"escape-dir":  outside,
			"escape-rel":  filepath.Join("..", "secret"),
			"escape-file": filepath.Join(outside, "secret"),
			"good":        filepath.Join("sub", "inside"),
			"chain":       "escape-dir",
		} {
			if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	addr := startServer(t, Config{Root: root})
	c := connect(t, addr)

	names := []string{
		`..`, `..\secret`, `sub\..\..\secret`, `\..\secret`, `..\..\..\..\etc\passwd`,
		`/etc/passwd`, `\etc\passwd`, `sub/../../secret`, `sub\..`, `.`, `.\secret`,
		"\uF029\uF029\\secret", ".\uF029\\secret", `C:\secret`, "..\x00",
	}
	if links {
		names = append(names, "escape-file", "escape-rel", `escape-dir\secret`, `chain\secret`, "escape-dir", "chain")
	}
	for _, name := range names {
		for _, disp := range []uint32{dispOpen, dispOpenIf, dispCreate, dispOverwriteIf} {
			id, st := c.create(name, accessRW, disp, 0)
			if st == statusSuccess {
				data, _ := c.read(id, 0, 100)
				t.Errorf("create %q (disposition %d) succeeded and read %q", name, disp, data)
				c.close(id)
			}
		}
	}
	if got, _ := os.ReadFile(filepath.Join(outside, "secret")); string(got) != "secret" {
		t.Fatalf("the file outside the root was modified: %q", got)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 2 {
		t.Fatalf("something was created outside the root: %v", entries)
	}

	// A rename cannot move a file out either.
	id, st := c.create(`sub\inside`, accessRW, dispOpen, 0)
	if st != statusSuccess {
		t.Fatalf("open: %#x", uint32(st))
	}
	targets := []string{`..\stolen`, `sub\..\..\stolen`, `\stolen`, "/stolen"}
	if links {
		targets = append(targets, `escape-dir\stolen`)
	}
	for _, target := range targets {
		if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileRename, renameData(target, true))); st == statusSuccess {
			t.Errorf("rename to %q succeeded", target)
		}
	}
	c.close(id)
	if entries, _ := os.ReadDir(outside); len(entries) != 2 {
		t.Fatalf("a rename escaped the root: %v", entries)
	}

	if links {
		// A link that stays inside the root is followed.
		id, st := c.create("good", accessRead, dispOpen, 0)
		if st != statusSuccess {
			t.Fatalf("open through an inner link: %#x", uint32(st))
		}
		if data, _ := c.read(id, 0, 100); string(data) != "inside" {
			t.Errorf("read through an inner link: %q", data)
		}
		c.close(id)
		// Escaping links are listed, as names only.
		if got := c.list(""); len(got) != 8 {
			t.Errorf("listing of the root: %q", got)
		}
	}
}

func TestReadOnly(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("content"), 0o644)
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	addr := startServer(t, Config{Root: root, ReadOnly: true})
	c := connect(t, addr)

	for _, try := range []struct {
		name            string
		access, disp, o uint32
	}{
		{"f", accessRW, dispOpen, 0},
		{"f", accessWrite, dispOpen, 0},
		{"f", accessRead, dispOverwrite, 0},
		{"f", accessRead, dispOverwriteIf, 0},
		{"f", accessRead, dispSupersede, 0},
		{"f", accessRead, dispOpen, optDeleteOnClose},
		{"f", accessRead | accessDelete, dispOpen, 0},
		{"f", accessGenericAll, dispOpen, 0},
		{"new", accessRead, dispCreate, 0},
		{"new", accessRead, dispOpenIf, 0},
		{"newdir", accessRead, dispCreate, optDirectory},
	} {
		if id, st := c.create(try.name, try.access, try.disp, try.o); st == statusSuccess {
			t.Errorf("create %+v succeeded on a read-only share", try)
			c.close(id)
		}
	}

	// Reading works, including with "maximum allowed", which must be
	// answered with read access only.
	id, st := c.create("f", accessMaximum, dispOpen, 0)
	if st != statusSuccess {
		t.Fatalf("open: %#x", uint32(st))
	}
	if data, _ := c.read(id, 0, 100); string(data) != "content" {
		t.Errorf("read: %q", data)
	}
	if st := c.write(id, 0, []byte("x")); st != statusAccessDenied {
		t.Errorf("write: %#x", uint32(st))
	}
	for class, data := range map[byte][]byte{
		fileEndOfFile:   le.AppendUint64(nil, 0),
		fileDisposition: {1},
		fileRename:      renameData("g", true),
		fileBasic:       make([]byte, 40),
	} {
		if st, _ := c.do(cmdSetInfo, setInfoBody(id, class, data)); st != statusAccessDenied {
			t.Errorf("set information class %d: %#x", class, uint32(st))
		}
	}
	c.close(id)
	if got, _ := os.ReadFile(filepath.Join(root, "f")); string(got) != "content" {
		t.Errorf("the file changed: %q", got)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 2 {
		t.Errorf("the root changed: %v", entries)
	}
}

func TestAllow(t *testing.T) {
	addr := startServer(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	c := dial(t, addr)
	c.send(c.request(cmdNegotiate, make([]byte, 38)))
	if _, err := c.recv(); err == nil {
		t.Fatal("a source outside the allowed prefixes was served")
	}

	addr = startServer(t, Config{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	c = dial(t, addr)
	if st, _ := c.negotiate(dialect210); st != statusSuccess {
		t.Fatalf("an allowed source was refused: %#x", uint32(st))
	}
}

func TestBounds(t *testing.T) {
	addr := startServer(t, Config{})

	// A frame larger than what an unauthenticated peer may send.
	c := dial(t, addr)
	c.nc.Write([]byte{0, 0x7F, 0xFF, 0xFF})
	if _, err := c.recv(); err == nil {
		t.Error("an oversized frame before login was accepted")
	}

	// More credits than granted: the first request holds one credit.
	c = dial(t, addr)
	msg := c.request(cmdNegotiate, make([]byte, 38))
	le.PutUint16(msg[6:], 100)
	c.send(msg)
	if _, err := c.recv(); err == nil {
		t.Error("a request charged beyond the granted credits was accepted")
	}

	// A read larger than the negotiated maximum.
	c = connect(t, addr)
	id, _ := c.create("big", accessRW, dispCreate, 0)
	msg = c.request(cmdRead, readBody(id, 0, maxIO+1))
	c.send(msg)
	resp, err := c.recv()
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := parseHeader(resp); h.status != statusInvalidParameter {
		t.Errorf("oversized read: %#x", uint32(h.status))
	}
	// A multi-credit read that is not paid for.
	body := readBody(id, 0, 1<<20)
	one := make([]byte, headerSize)
	(&header{creditCharge: 1, command: cmdRead, credits: 8, messageID: c.messageID, treeID: c.treeID, sessionID: c.sessionID}).put(one)
	c.messageID++
	one = append(one, body...)
	sign(c.key, one)
	c.send(one)
	resp, _ = c.recv()
	if h, _ := parseHeader(resp); h.status != statusInvalidParameter {
		t.Errorf("underpaid read: %#x", uint32(h.status))
	}

	// Sessions per connection.
	c = dial(t, addr)
	c.negotiate(dialect210)
	var last ntStatus
	for i := 0; i <= maxSessionsPerConn; i++ {
		c.sessionID, c.key = 0, nil
		last = c.login(testUser, testPassword)
	}
	if last != statusInsufficientResources {
		t.Errorf("session %d on one connection: %#x", maxSessionsPerConn+1, uint32(last))
	}

	// Deep compound chains.
	c = connect(t, addr)
	cmds := make([]uint16, maxCompound+1)
	bodies := make([][]byte, maxCompound+1)
	echo := make([]byte, 4)
	le.PutUint16(echo, 4)
	for i := range cmds {
		cmds[i], bodies[i] = cmdEcho, echo
	}
	c.send(c.compound(cmds, bodies))
	if _, err := c.recv(); err == nil {
		t.Error("a compound chain beyond the limit was served")
	}
}

func TestLocks(t *testing.T) {
	addr := startServer(t, Config{})
	a, b := connect(t, addr), connect(t, addr)
	ida, _ := a.create("f", accessRW, dispCreate, 0)
	idb, st := b.create("f", accessRW, dispOpen, 0)
	if st != statusSuccess {
		t.Fatalf("second open: %#x", uint32(st))
	}
	lock := func(c *testClient, id []byte, off, n uint64, flags uint32) ntStatus {
		body := make([]byte, 24)
		le.PutUint16(body, 48)
		le.PutUint16(body[2:], 1)
		copy(body[8:], id)
		body = le.AppendUint64(body, off)
		body = le.AppendUint64(body, n)
		body = le.AppendUint32(body, flags)
		body = le.AppendUint32(body, 0)
		st, _ := c.do(cmdLock, body)
		return st
	}
	if st := lock(a, ida, 0, 100, lockExclusive); st != statusSuccess {
		t.Fatalf("lock: %#x", uint32(st))
	}
	if st := lock(b, idb, 50, 10, lockExclusive); st != statusLockNotGranted {
		t.Errorf("conflicting lock: %#x", uint32(st))
	}
	if st := lock(b, idb, 100, 10, lockExclusive); st != statusSuccess {
		t.Errorf("adjacent lock: %#x", uint32(st))
	}
	if st := lock(b, idb, 0, 100, lockUnlock); st != statusRangeNotLocked {
		t.Errorf("unlock of a range held by someone else: %#x", uint32(st))
	}
	if st := lock(a, ida, 0, 100, lockUnlock); st != statusSuccess {
		t.Errorf("unlock: %#x", uint32(st))
	}
	if st := lock(b, idb, 50, 10, lockShared); st != statusSuccess {
		t.Errorf("lock after unlock: %#x", uint32(st))
	}
	// Closing a handle, here by dropping the connection, frees its locks.
	b.nc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for lock(a, ida, 0, 200, lockExclusive) != statusSuccess {
		if time.Now().After(deadline) {
			t.Fatal("the locks of a dead connection were never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client that reconnects names its previous session, which the server
// then retires along with what it held.
func TestPreviousSession(t *testing.T) {
	addr := startServer(t, Config{})
	old := connect(t, addr)
	id, _ := old.create("f", accessRW, dispCreate, optDeleteOnClose)
	_ = id

	c := dial(t, addr)
	c.negotiate(dialect210)
	// The login helper does not set the previous session; do the last
	// leg by hand through a second login carrying it.
	if st := c.loginReplacing(old.sessionID); st != statusSuccess {
		t.Fatalf("login: %#x", uint32(st))
	}
	old.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := old.recv(); err == nil {
		t.Error("the replaced connection is still served")
	}
}

func (c *testClient) loginReplacing(previous uint64) ntStatus {
	c.t.Helper()
	negotiate := append([]byte(ntlmSignature), 1, 0, 0, 0)
	negotiate = le.AppendUint32(negotiate, ntlmUnicode|ntlmNTLM|ntlmExtendedSession)
	st, resp := c.do(cmdSessionSetup, sessionSetupBody(negotiate))
	if st != statusMoreProcessingRequired {
		return st
	}
	h, _ := parseHeader(resp)
	c.sessionID = h.sessionID
	p := resp[headerSize:]
	challenge, _ := sub(resp, uint32(le.Uint16(p[4:])), uint32(le.Uint16(p[6:])))
	if !isNTLM(challenge, 2) {
		c.t.Fatalf("a raw NTLMSSP negotiate was not answered in kind: %x", challenge)
	}
	hash := NTHash(testPassword)
	owf := hmacMD5(hash[:], encodeUTF16("TESTER"))
	temp := append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, make([]byte, 24)...)
	rand.Read(temp[16:24])
	proof := hmacMD5(owf, challenge[24:32], temp)
	body := sessionSetupBody(authenticateMessage(testUser, "", append(proof, temp...), nil))
	le.PutUint64(body[16:], previous)
	st, _ = c.do(cmdSessionSetup, body)
	if st == statusSuccess {
		c.key = hmacMD5(owf, proof)
	}
	return st
}

func TestOplocks(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("content"), 0o644)
	addr := startServer(t, Config{Root: root})
	reader, writer := connect(t, addr), connect(t, addr)

	open := func(c *testClient, access uint32) ([]byte, byte) {
		body := createBody("f", access, dispOpen, 0)
		body[3] = 0x09 // batch oplock requested, as clients do
		st, resp := c.do(cmdCreate, body)
		if st != statusSuccess {
			t.Fatalf("create: %#x", uint32(st))
		}
		return resp[headerSize+64 : headerSize+80], resp[headerSize+2]
	}
	// A reader gets level II, never more; a writer gets nothing.
	rid, level := open(reader, accessRead)
	if level != oplockLevelII {
		t.Fatalf("oplock granted to a reader: %d", level)
	}
	wid, level := open(writer, accessRW)
	if level != oplockNone {
		t.Fatalf("oplock granted to a writer: %d", level)
	}
	// No request, no oplock.
	if _, st := reader.create("f", accessRead, dispOpen, 0); st != statusSuccess {
		t.Fatal(st)
	}

	// A write through another connection breaks the oplock of the reader.
	if st := writer.write(wid, 0, []byte("CHANGED")); st != statusSuccess {
		t.Fatalf("write: %#x", uint32(st))
	}
	msg, err := reader.recv()
	if err != nil || !isBreak(msg) {
		t.Fatalf("no oplock break after a write: %x %v", msg, err)
	}
	if msg[headerSize+2] != oplockNone || !bytes.Equal(msg[headerSize+8:headerSize+24], rid) {
		t.Errorf("break body: %x", msg[headerSize:])
	}
	// Once broken there is nothing left to break.
	writer.write(wid, 0, []byte("again"))
	if data, _ := reader.read(rid, 0, 100); string(data) != "againED" || reader.breaks != 0 {
		t.Errorf("read %q after %d more breaks", data, reader.breaks)
	}
	// A client may acknowledge; the server answers.
	ack := make([]byte, 24)
	le.PutUint16(ack, 24)
	copy(ack[8:], rid)
	if st, _ := reader.do(cmdOplockBreak, ack); st != statusSuccess {
		t.Errorf("acknowledgement: %#x", uint32(st))
	}
	reader.close(rid)

	// A change made in the directory, behind the server, breaks too.
	rid, level = open(reader, accessRead)
	if level != oplockLevelII {
		t.Fatalf("second oplock: %d", level)
	}
	os.WriteFile(filepath.Join(root, "f"), []byte("written by the workload"), 0o644)
	reader.nc.SetReadDeadline(time.Now().Add(5 * watchInterval))
	if msg, err := reader.recv(); err != nil || !isBreak(msg) {
		t.Fatalf("no oplock break after an outside change: %v", err)
	}
	reader.nc.SetDeadline(time.Now().Add(20 * time.Second))

	// Truncating through a create breaks as well.
	rid, _ = open(reader, accessRead)
	if _, st := writer.create("f", accessRW, dispOverwrite, 0); st != statusSuccess {
		t.Fatal(st)
	}
	if msg, err := reader.recv(); err != nil || !isBreak(msg) {
		t.Fatalf("no oplock break after a truncating open: %v", err)
	}
	_ = rid
}

// Named streams hold what a client writes to them without anything reaching
// the directory.
func TestStreams(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "f"), []byte("content"), 0o644)
	os.Mkdir(filepath.Join(root, "d"), 0o755)
	addr := startServer(t, Config{Root: root})
	c := connect(t, addr)

	if _, st := c.create("f:meta", accessRead, dispOpen, 0); st != statusObjectNameNotFound {
		t.Errorf("open a stream that does not exist: %#x", uint32(st))
	}
	if _, st := c.create("missing:meta", accessRW, dispOpenIf, 0); st != statusObjectNameNotFound {
		t.Errorf("stream of a missing file: %#x", uint32(st))
	}
	id, st := c.create("f:com.apple.quarantine:$DATA", accessRW, dispOpenIf, 0)
	if st != statusSuccess {
		t.Fatalf("create a stream: %#x", uint32(st))
	}
	if st := c.write(id, 0, []byte("0081;flag")); st != statusSuccess {
		t.Fatalf("write: %#x", uint32(st))
	}
	c.close(id)
	// Reopened, in another case: stream names are not case sensitive.
	id, st = c.create("f:COM.APPLE.QUARANTINE", accessRW, dispOpen, 0)
	if st != statusSuccess {
		t.Fatalf("reopen: %#x", uint32(st))
	}
	if data, _ := c.read(id, 5, 100); string(data) != "flag" {
		t.Errorf("read: %q", data)
	}
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileEndOfFile, le.AppendUint64(nil, 4))); st != statusSuccess {
		t.Errorf("truncate: %#x", uint32(st))
	}
	if data, _ := c.read(id, 0, 100); string(data) != "0081" {
		t.Errorf("read after truncate: %q", data)
	}
	// Streams on a directory too, which is where the Finder keeps its
	// view settings.
	did, st := c.create("d:AFP_AfpInfo", accessRW, dispCreate, 0)
	if st != statusSuccess {
		t.Fatalf("stream on a directory: %#x", uint32(st))
	}
	c.close(did)

	// The file lists its streams.
	fid, _ := c.create("f", accessRead, dispOpen, 0)
	st, resp := c.do(cmdQueryInfo, queryInfoBody(fid, infoFile, fileStream, 4096))
	listing := decodeUTF16(resp[headerSize+8:])
	if st != statusSuccess || !bytes.Contains([]byte(listing), []byte("::$DATA")) || !bytes.Contains([]byte(listing), []byte(":com.apple.quarantine:$DATA")) {
		t.Errorf("stream listing: %#x %q", uint32(st), listing)
	}

	// Memory is bounded.
	if st := c.write(id, maxStreamSize, []byte("x")); st != statusDiskFull {
		t.Errorf("write beyond the stream limit: %#x", uint32(st))
	}

	// Deleting the stream, then the file with the stream that remains.
	if st, _ := c.do(cmdSetInfo, setInfoBody(id, fileDisposition, []byte{1})); st != statusSuccess {
		t.Errorf("delete a stream: %#x", uint32(st))
	}
	c.close(id)
	if _, st := c.create("f:com.apple.quarantine", accessRead, dispOpen, 0); st != statusObjectNameNotFound {
		t.Errorf("open a deleted stream: %#x", uint32(st))
	}
	c.close(fid)

	// Nothing of all this is in the directory.
	entries, _ := os.ReadDir(root)
	if len(entries) != 2 {
		t.Errorf("the directory holds %v", entries)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "f")); string(got) != "content" {
		t.Errorf("the file changed: %q", got)
	}

	// The Finder's folder settings file is refused, an existing one is
	// left alone.
	if _, st := c.create(".DS_Store", accessRW, dispOpenIf, 0); st != statusAccessDenied {
		t.Errorf("create .DS_Store: %#x", uint32(st))
	}
	if _, st := c.create(`d\.DS_Store`, accessRW, dispCreate, 0); st != statusAccessDenied {
		t.Errorf("create .DS_Store in a directory: %#x", uint32(st))
	}
}
