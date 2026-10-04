package smbserver

import (
	"strings"
	"sync"
	"time"
)

// session is an authenticated logon on one connection.
type session struct {
	id   uint64
	conn *conn

	// auth is the exchange in progress; nil once it has concluded.
	auth          *authState
	authenticated bool

	// signingKey is the NTLM session key, which SMB 2 signs with as is.
	signingKey []byte

	mu       sync.Mutex
	closed   bool
	trees    map[uint32]*tree
	opens    map[uint64]*open
	nextTree uint32
}

// tree is a connection to the share or to IPC$.
type tree struct {
	id  uint32
	ipc bool
}

type authState struct {
	ntlm      ntlmAuth
	rounds    int
	raw       bool
	mechTypes []byte
	wantMIC   bool
}

func (c *conn) sessionSetup(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 24 || le.Uint16(p) != 25 {
		return statusInvalidParameter, nil
	}
	// Binding an existing session to a new connection is multichannel,
	// which is not offered.
	if p[2]&1 != 0 {
		return statusRequestNotAccepted, nil
	}
	token, ok := sub(r.msg, uint32(le.Uint16(p[12:])), uint32(le.Uint16(p[14:])))
	if !ok {
		return statusInvalidParameter, nil
	}
	previous := le.Uint64(p[16:])

	var sess *session
	if r.hdr.sessionID == 0 {
		sess = &session{
			id:    c.srv.newID(),
			conn:  c,
			auth:  &authState{},
			trees: make(map[uint32]*tree),
			opens: make(map[uint64]*open),
		}
		c.mu.Lock()
		full := len(c.sessions) >= maxSessionsPerConn
		if !full {
			c.sessions[sess.id] = sess
		}
		c.mu.Unlock()
		if full {
			return statusInsufficientResources, nil
		}
	} else if sess = c.session(r.hdr.sessionID); sess == nil {
		return statusUserSessionDeleted, nil
	}
	r.sess = sess
	if sess.authenticated {
		// Re-authentication of a live session: the credentials are
		// checked again and the keys are kept.
		if sess.auth == nil {
			sess.auth = &authState{}
		}
	}

	st, blob := sess.step(token)
	switch st {
	case statusMoreProcessingRequired:
	case statusSuccess:
		key := sess.auth.ntlm.sessionKey
		sess.auth = nil
		if !sess.authenticated {
			sess.signingKey = key
			sess.authenticated = true
			c.authenticated = true
			c.nc.SetReadDeadline(time.Time{})
			c.srv.register(sess, previous)
			c.srv.logf("session opened from %v", c.nc.RemoteAddr())
		}
		r.sign = true
	default:
		c.srv.logf("authentication failed from %v", c.nc.RemoteAddr())
		if sess.authenticated {
			sess.auth = nil
		} else {
			sess.close()
		}
		r.sess = nil
		return st, nil
	}

	out := newMsg(8)
	le.PutUint16(out[headerSize:], 9)
	le.PutUint16(out[headerSize+4:], headerSize+8)
	le.PutUint16(out[headerSize+6:], uint16(len(blob)))
	return st, append(out, blob...)
}

// step advances the SPNEGO and NTLM exchange by one client token.
func (s *session) step(token []byte) (ntStatus, []byte) {
	a := s.auth
	// A legitimate exchange takes two or three legs.
	if a.rounds++; a.rounds > 4 {
		return statusLogonFailure, nil
	}
	tok, ok := parseSPNEGO(token)
	if !ok {
		return statusLogonFailure, nil
	}
	if tok.raw {
		a.raw = true
	}
	if tok.init {
		a.mechTypes = tok.mechTypes
		// RFC 4178 makes the MIC mandatory when the mechanism that ends
		// up used was not the first choice of the client.
		a.wantMIC = !tok.ntlmFirst
	}
	wrap := func(state byte, withMech bool, t, mic []byte) []byte {
		if a.raw {
			return t
		}
		return negTokenResp(state, withMech, t, mic)
	}
	switch {
	case isNTLM(tok.mechToken, 1):
		challenge, ok := a.ntlm.start(tok.mechToken, time.Now())
		if !ok {
			return statusLogonFailure, nil
		}
		return statusMoreProcessingRequired, wrap(negAcceptIncomplete, true, challenge, nil)
	case isNTLM(tok.mechToken, 3):
		cfg := &s.conn.srv.cfg
		if !a.ntlm.authenticate(tok.mechToken, cfg.User, cfg.NTHash) {
			return statusLogonFailure, nil
		}
		var mic []byte
		if a.mechTypes != nil && (tok.mic != nil || a.wantMIC) {
			// The MIC of the client is not verified: with a single
			// mechanism on offer there is no negotiation it could
			// have been protecting.
			mic = a.ntlm.mechListMIC(a.mechTypes)
		}
		return statusSuccess, wrap(negAcceptCompleted, false, nil, mic)
	case tok.init && !tok.raw:
		// The client led with a token for a mechanism the server does
		// not have (Kerberos, NEGOEX). Point it at NTLMSSP.
		return statusMoreProcessingRequired, negTokenResp(negAcceptIncomplete, true, nil, nil)
	}
	return statusLogonFailure, nil
}

func (s *session) tree(id uint32) *tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trees[id]
}

func (s *session) open(id uint64) *open {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens[id]
}

func (s *session) removeTree(t *tree) {
	s.mu.Lock()
	delete(s.trees, t.id)
	var opens []*open
	for id, o := range s.opens {
		if o.tree == t {
			opens = append(opens, o)
			delete(s.opens, id)
		}
	}
	s.mu.Unlock()
	for _, o := range opens {
		s.conn.srv.release(o)
	}
}

// close ends the session and releases every file it holds. The keys stay,
// so that the response to a LOGOFF can still be signed.
func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.authenticated = false
	opens := s.opens
	s.opens = map[uint64]*open{}
	s.trees = map[uint32]*tree{}
	s.mu.Unlock()
	for _, o := range opens {
		s.conn.srv.release(o)
	}
	c := s.conn
	c.mu.Lock()
	delete(c.sessions, s.id)
	c.mu.Unlock()
	c.srv.mu.Lock()
	delete(c.srv.sessions, s.id)
	c.srv.mu.Unlock()
}

// register records a freshly authenticated session and retires the one it
// replaces. A client that reconnects after a network cut names its previous
// session; closing it releases the handles and locks the dead connection
// would otherwise hold until TCP notices.
func (srv *server) register(s *session, previous uint64) {
	srv.mu.Lock()
	srv.sessions[s.id] = s
	old := srv.sessions[previous]
	srv.mu.Unlock()
	if old != nil && old != s {
		old.close()
		if old.conn != s.conn {
			old.conn.nc.Close()
		}
	}
}

func (c *conn) treeConnect(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 8 || le.Uint16(p) != 9 {
		return statusInvalidParameter, nil
	}
	raw, ok := sub(r.msg, uint32(le.Uint16(p[4:])), uint32(le.Uint16(p[6:])))
	if !ok {
		return statusInvalidParameter, nil
	}
	// The path is \\server\share; the server part is whatever name the
	// client reached us by and is not checked.
	name := decodeUTF16(raw)
	name = name[strings.LastIndexByte(name, '\\')+1:]
	t := &tree{}
	switch {
	case strings.EqualFold(name, "IPC$"):
		t.ipc = true
	case strings.EqualFold(name, c.srv.cfg.Share):
	default:
		return statusBadNetworkName, nil
	}
	s := r.sess
	s.mu.Lock()
	full := len(s.trees) >= maxTreesPerSession || s.closed
	if !full {
		s.nextTree++
		t.id = s.nextTree
		s.trees[t.id] = t
	}
	s.mu.Unlock()
	if full {
		return statusInsufficientResources, nil
	}
	r.tree = t

	out := newMsg(16)
	p = out[headerSize:]
	le.PutUint16(p, 16)
	access := uint32(0x001F01FF)
	switch {
	case t.ipc:
		p[2] = 2 // pipe
		access = accessReadOnly
	default:
		p[2] = 1 // disk
		if c.srv.cfg.ReadOnly {
			access = accessReadOnly
		}
	}
	le.PutUint32(p[12:], access)
	return statusSuccess, out
}
