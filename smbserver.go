// Package smbserver is an SMB 2 and 3 file server in pure Go.
//
// It serves one directory as one share to one user, on a listener the caller
// provides. It needs no privilege, no account database and no file on disk
// besides the directory it serves: the files it creates belong to the uid of
// the process, whatever that uid is.
package smbserver

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config describes the share to serve.
type Config struct {
	// Root is the directory to serve. Nothing outside of it is reachable,
	// including through symbolic links.
	Root string
	// Share is the name clients connect to, as in //host/Share.
	Share string
	// User is the only account that may log in.
	User string
	// NTHash is the NT hash of the password of User. See NTHash.
	NTHash [16]byte
	// Allow restricts the source addresses accepted. Empty means any.
	Allow []netip.Prefix
	// ReadOnly refuses every operation that would modify the share.
	ReadOnly bool
	// Logf, when set, receives one line per notable event.
	Logf func(format string, args ...any)
}

// Limits on what a client may ask of the server. They bound the memory and
// the descriptors a peer can pin, before and after authentication.
const (
	maxConns           = 256
	maxSessionsPerConn = 16
	maxTreesPerSession = 16
	maxOpens           = 16384
	maxCompound        = 32
	maxCredits         = 8192
	// maxIO is the largest read, write or transact payload.
	maxIO = 8 << 20
	// preAuthFrame bounds a message from a peer that has not logged in.
	preAuthFrame = 128 << 10
	// preAuthTimeout is how long a peer may stay connected without
	// completing authentication.
	preAuthTimeout = 30 * time.Second
	writeTimeout   = 2 * time.Minute
)

type server struct {
	cfg      Config
	root     *os.Root
	rootPath string
	guid     [16]byte
	start    time.Time

	nextID atomic.Uint64

	mu       sync.Mutex
	closed   bool
	conns    map[*conn]struct{}
	sessions map[uint64]*session
	files    map[fileKey]*sharedFile
	nOpens   int
}

// Serve accepts SMB connections on ln until ctx is cancelled, then closes
// the listener and every connection and returns nil. It returns an error if
// the configuration is invalid or the listener fails.
func Serve(ctx context.Context, ln net.Listener, cfg Config) error {
	s, err := newServer(cfg)
	if err != nil {
		return err
	}
	defer s.root.Close()

	stop := context.AfterFunc(ctx, func() {
		ln.Close()
		s.shutdown()
	})
	defer stop()

	var wg sync.WaitGroup
	defer wg.Wait()
	defer s.shutdown()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("smbserver: %w", err)
			}
			// Running out of descriptors is transient: back off and
			// keep serving the connections already established.
			s.logf("accept: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if !s.allowed(nc.RemoteAddr()) {
			s.logf("refused connection from %v: source not allowed", nc.RemoteAddr())
			nc.Close()
			continue
		}
		c := s.newConn(nc)
		if c == nil {
			nc.Close()
			continue
		}
		wg.Go(c.serve)
	}
}

func newServer(cfg Config) (*server, error) {
	if cfg.Share == "" || strings.EqualFold(cfg.Share, "IPC$") || strings.ContainsAny(cfg.Share, `\/`) {
		return nil, fmt.Errorf("smbserver: invalid share name %q", cfg.Share)
	}
	if cfg.User == "" {
		return nil, errors.New("smbserver: empty user name")
	}
	abs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("smbserver: %w", err)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("smbserver: %w", err)
	}
	s := &server{
		cfg:      cfg,
		root:     root,
		rootPath: abs,
		start:    time.Now(),
		conns:    make(map[*conn]struct{}),
		sessions: make(map[uint64]*session),
		files:    make(map[fileKey]*sharedFile),
	}
	rand.Read(s.guid[:])
	var seed [8]byte
	rand.Read(seed[:])
	// Identifiers start at a random point so that they are not guessable
	// across restarts; the top bit is cleared to leave room to count.
	s.nextID.Store(le.Uint64(seed[:]) >> 1)
	return s, nil
}

func (s *server) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

func (s *server) allowed(addr net.Addr) bool {
	if len(s.cfg.Allow) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range s.cfg.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *server) newConn(nc net.Conn) *conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= maxConns {
		return nil
	}
	if tc, ok := nc.(*net.TCPConn); ok {
		// A tunnel that drops without closing leaves the server side
		// half open; keepalives reclaim the handles and locks it holds.
		tc.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3})
	}
	c := &conn{
		srv:      s,
		nc:       nc,
		credits:  1,
		sessions: make(map[uint64]*session),
	}
	s.conns[c] = struct{}{}
	return c
}

func (s *server) shutdown() {
	s.mu.Lock()
	s.closed = true
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.nc.Close()
	}
}

// newID returns a non-zero identifier unique for the life of the server. It
// names sessions and open files alike.
func (s *server) newID() uint64 {
	for {
		if id := s.nextID.Add(1); id != 0 && id != ^uint64(0) {
			return id
		}
	}
}
