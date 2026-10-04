package smbserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// conn is one TCP connection. Its requests are handled one at a time, in
// order, by the goroutine that reads them.
type conn struct {
	srv *server
	nc  net.Conn
	// wmu serialises the writes: besides the responses, a connection
	// carries the oplock breaks caused by other clients.
	wmu sync.Mutex

	negotiated bool
	smb1Seen   bool
	dialect    uint16
	maxIO      uint32
	// What the client said in NEGOTIATE, for its later validation.
	clientGUID    [16]byte
	clientCaps    uint32
	clientSecMode uint16

	// credits is the number of credits the client currently holds.
	credits       int
	authenticated bool

	// mu guards sessions, which another connection reaches when a client
	// that reconnected retires its previous session.
	mu       sync.Mutex
	sessions map[uint64]*session
}

// request is one command of a message, with what the connection resolved
// about it before calling the handler.
type request struct {
	hdr header
	// msg is the command, header included, so that the offsets of the
	// protocol index it directly.
	msg   []byte
	sess  *session
	tree  *tree
	chain *chain
	// sign tells that the response must be signed: the request was, or
	// this is the response that concludes a session setup.
	sign bool
	// fatal makes the connection close once the response is sent.
	fatal bool
	// silent suppresses the response (CANCEL has none).
	silent bool
	// note is what a handler wants the trace to say about the request.
	note string
}

// chain is the state shared by the commands of a compound request: a related
// command inherits the session, tree and file of its predecessor.
type chain struct {
	sessionID uint64
	treeID    uint32
	fileID    uint64
	hasFile   bool
	// status is why there is no file, when a CREATE of the chain failed.
	status ntStatus
}

var errProtocol = errors.New("protocol violation")

// trace logs every command and its status through Config.Logf. It exists to
// diagnose a client from the outside, in CI for instance.
var trace = os.Getenv("SMBSERVER_TRACE") != ""

func (c *conn) serve() {
	defer c.close()
	defer func() {
		// Last line of defence: a bug in a decoder must cost the
		// offending connection, never the process embedding the server.
		if p := recover(); p != nil {
			c.srv.logf("panic serving %v: %v\n%s", c.nc.RemoteAddr(), p, debug.Stack())
		}
	}()
	for {
		if !c.authenticated {
			c.nc.SetReadDeadline(time.Now().Add(preAuthTimeout))
		}
		msg, err := c.readFrame()
		if err == nil {
			err = c.handleFrame(msg)
		}
		if err != nil {
			if errors.Is(err, errProtocol) {
				c.srv.logf("closing %v: %v", c.nc.RemoteAddr(), err)
			}
			return
		}
	}
}

func (c *conn) readFrame() ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c.nc, h[:]); err != nil {
		return nil, err
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	limit := preAuthFrame
	if c.authenticated {
		limit = maxIO + 0x10000
	}
	// The first byte is the NetBIOS session message type, zero on the
	// direct TCP transport, which is the only one served.
	if h[0] != 0 || n < 4 || n > limit {
		return nil, fmt.Errorf("%w: frame type %d of %d bytes", errProtocol, h[0], n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(c.nc, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *conn) handleFrame(msg []byte) error {
	if msg[0] == 0xFF && msg[1] == 'S' && msg[2] == 'M' && msg[3] == 'B' {
		return c.smb1Negotiate(msg)
	}
	return c.handleMessage(msg)
}

// handleMessage processes a message, which is one command or a compound
// chain of them, and sends the responses as one message.
func (c *conn) handleMessage(msg []byte) error {
	var (
		payload []byte
		ch      chain
		fatal   bool
	)
	for off, n := 0, 0; ; n++ {
		hdr, ok := parseHeader(msg[off:])
		if !ok || n >= maxCompound {
			return errProtocol
		}
		end := len(msg)
		if hdr.next != 0 {
			if hdr.next < headerSize || hdr.next%8 != 0 || int(hdr.next) > len(msg)-off-headerSize {
				return errProtocol
			}
			end = off + int(hdr.next)
		}
		r := &request{hdr: hdr, msg: msg[off:end], chain: &ch}
		out, err := c.process(r)
		if err != nil {
			return err
		}
		fatal = fatal || r.fatal
		if out != nil {
			// Each response of a compound is padded to eight bytes,
			// linked to the next one, and signed on its own.
			if hdr.next != 0 {
				out = pad8(out)
				le.PutUint32(out[20:], uint32(len(out)))
			}
			if r.sign && r.sess != nil && r.sess.signingKey != nil {
				signWith(r.sess.mac, out)
			}
			if payload == nil {
				payload = out
			} else {
				payload = append(payload, out...)
			}
		}
		if hdr.next == 0 {
			break
		}
		off = end
	}
	if payload != nil {
		if err := c.send(payload); err != nil {
			return err
		}
	}
	if fatal {
		return errProtocol
	}
	return nil
}

// process runs one command and returns its response, header included, or nil
// when the command has none.
func (c *conn) process(r *request) ([]byte, error) {
	h := &r.hdr
	if h.flags&flagResponse != 0 {
		return nil, errProtocol
	}
	// CANCEL is the one command that consumes no credit.
	if h.command != cmdCancel {
		charge := max(int(h.creditCharge), 1)
		if charge > c.credits {
			return nil, fmt.Errorf("%w: credit charge %d exceeds the %d granted", errProtocol, charge, c.credits)
		}
		c.credits -= charge
	}

	st, out := c.route(r)
	if trace {
		c.srv.logf("%v: command %d message %d flags %#x %s: status %#x", c.nc.RemoteAddr(), h.command, h.messageID, h.flags, r.note, uint32(st))
	}
	if r.silent {
		return nil, nil
	}
	// A response carries its body only on success and on the warnings
	// that return data; everything else gets the error body.
	if out == nil {
		out = errorBody(nil)
	}

	rh := header{
		creditCharge: h.creditCharge,
		status:       st,
		command:      h.command,
		flags:        flagResponse | h.flags&flagRelated,
		messageID:    h.messageID,
		sessionID:    h.sessionID,
		treeID:       h.treeID,
	}
	if r.sess != nil {
		rh.sessionID = r.sess.id
	}
	if r.tree != nil {
		rh.treeID = r.tree.id
	}
	// Grant what the client asks, within the window, and never leave it
	// without a credit to send its next request.
	grant := min(max(int(h.credits), 1), maxCredits-c.credits)
	c.credits += grant
	rh.credits = uint16(grant)
	rh.put(out)

	r.chain.sessionID = rh.sessionID
	r.chain.treeID = rh.treeID
	return out, nil
}

// route authenticates the command and dispatches it. Nothing below the
// session lookup runs for a peer that has not logged in.
func (c *conn) route(r *request) (ntStatus, []byte) {
	h := &r.hdr
	if !c.negotiated {
		if h.command != cmdNegotiate {
			r.fatal = true
			return statusInvalidParameter, nil
		}
		return c.negotiate(r)
	}
	switch h.command {
	case cmdNegotiate:
		// A second NEGOTIATE on a connection is a protocol violation.
		r.fatal = true
		return statusInvalidParameter, nil
	case cmdSessionSetup:
		return c.sessionSetup(r)
	case cmdEcho:
		// Clients send keepalive echoes outside of any session.
		if h.sessionID == 0 {
			return statusSuccess, emptyBody()
		}
	}

	sid, tid := h.sessionID, h.treeID
	if h.flags&flagRelated != 0 {
		sid, tid = r.chain.sessionID, r.chain.treeID
	}
	sess := c.session(sid)
	if sess == nil || !sess.authenticated {
		return statusUserSessionDeleted, nil
	}
	// Signing is required: an unsigned or badly signed request is refused
	// whatever the client negotiated.
	if h.flags&flagSigned == 0 || !verifyWith(sess.mac, r.msg) {
		return statusAccessDenied, nil
	}
	r.sess = sess
	r.sign = true

	switch h.command {
	case cmdLogoff:
		sess.close()
		return statusSuccess, emptyBody()
	case cmdTreeConnect:
		return c.treeConnect(r)
	case cmdEcho:
		return statusSuccess, emptyBody()
	case cmdCancel:
		// No request ever stays pending, so there is nothing to cancel.
		r.silent = true
		return statusSuccess, nil
	}

	tree := sess.tree(tid)
	if tree == nil {
		return statusNetworkNameDeleted, nil
	}
	r.tree = tree

	switch h.command {
	case cmdTreeDisconnect:
		sess.removeTree(tree)
		return statusSuccess, emptyBody()
	case cmdCreate:
		st, out := c.create(r)
		if st != statusSuccess {
			r.chain.hasFile = false
			r.chain.status = st
		}
		return st, out
	case cmdClose:
		return c.closeFile(r)
	case cmdFlush:
		return c.flush(r)
	case cmdRead:
		return c.read(r)
	case cmdWrite:
		return c.write(r)
	case cmdLock:
		return c.lock(r)
	case cmdIoctl:
		return c.ioctl(r)
	case cmdQueryDirectory:
		return c.queryDirectory(r)
	case cmdQueryInfo:
		return c.queryInfo(r)
	case cmdSetInfo:
		return c.setInfo(r)
	case cmdOplockBreak:
		return c.oplockBreak(r)
	}
	// CHANGE_NOTIFY lands here: directories are not watched.
	return statusNotSupported, nil
}

// errorBody is the SMB2 ERROR response body, with optional error data.
func errorBody(data []byte) []byte {
	out := newMsg(8 + max(len(data), 1))
	le.PutUint16(out[headerSize:], 9)
	le.PutUint32(out[headerSize+4:], uint32(len(data)))
	copy(out[headerSize+8:], data)
	return out
}

// emptyBody is the four-byte body shared by the responses that carry no
// data (ECHO, LOGOFF, TREE_DISCONNECT, FLUSH, LOCK).
func emptyBody() []byte {
	out := newMsg(4)
	le.PutUint16(out[headerSize:], 4)
	return out
}

func (c *conn) send(payload []byte) error {
	var h [4]byte
	h[1], h[2], h[3] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	bufs := net.Buffers{h[:], payload}
	_, err := bufs.WriteTo(c.nc)
	return err
}

// mac is the SMB 2 signature: the first 16 bytes of the HMAC-SHA256 of the
// message, computed with its signature field zeroed.
func mac(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)[:16]
}

// signWith sets the signed flag of a response and fills its signature.
func signWith(mac func([]byte) []byte, msg []byte) {
	le.PutUint32(msg[16:], le.Uint32(msg[16:])|flagSigned)
	clear(msg[48:64])
	copy(msg[48:64], mac(msg))
}

// verifyWith checks the signature of a request. It zeroes the signature
// field of msg, which nothing reads afterwards.
func verifyWith(mac func([]byte) []byte, msg []byte) bool {
	var got [16]byte
	copy(got[:], msg[48:64])
	clear(msg[48:64])
	return hmac.Equal(got[:], mac(msg))
}

func sign(key, msg []byte) {
	signWith(func(b []byte) []byte { return mac(key, b) }, msg)
}

func verify(key, msg []byte) bool {
	return verifyWith(func(b []byte) []byte { return mac(key, b) }, msg)
}

func (c *conn) session(id uint64) *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[id]
}

func (c *conn) close() {
	c.nc.Close()
	c.mu.Lock()
	sessions := make([]*session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	c.srv.mu.Lock()
	delete(c.srv.conns, c)
	c.srv.mu.Unlock()
}
