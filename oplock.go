package smbserver

import (
	"context"
	"time"
)

// Level II oplocks, and only those.
//
// Without any oplock a client may cache nothing: reading a small file costs
// it an extra round trip to find the end of the file, which measured at up
// to four times the time Samba takes on a tree of small files. A level II
// oplock lets every holder cache what it reads, and costs the server one
// thing: telling the holders when the file changes. That notification needs
// no acknowledgement, unlike the break of an exclusive oplock or of a lease,
// which is why the server stops at this level.
//
// The file can also change behind the server, written by the workload that
// owns the volume. A client holding an oplock would never look again, so the
// server watches the files under oplock and breaks when one moves.

const (
	oplockNone    = 0x00
	oplockLevelII = 0x01

	// watchInterval is how often files under oplock are checked for a
	// change made outside the server, hence how stale a cached read of
	// a file the workload is writing can be.
	watchInterval = time.Second
)

// grantOplock records o as a level II holder. Called with s.mu held.
func (s *server) grantOplock(o *open, size int64, mtime time.Time) {
	sf := o.shared
	if sf.holders.Load() == 0 {
		sf.size, sf.mtime = size, mtime
	}
	o.oplock = true
	sf.holders.Add(1)
	s.oplocks.Add(1)
}

// takeHolders ends every oplock on a file and returns the handles to
// notify. Called with s.mu held.
func (s *server) takeHolders(sf *sharedFile) []*open {
	var out []*open
	for _, o := range sf.opens {
		if o.oplock {
			s.dropOplock(o)
			out = append(out, o)
		}
	}
	return out
}

// dropOplock forgets the oplock of a handle. Called with s.mu held.
func (s *server) dropOplock(o *open) {
	if o.oplock {
		o.oplock = false
		o.shared.holders.Add(-1)
		s.oplocks.Add(-1)
	}
}

// breakOplocks tells the holders of a file that it is about to change. from
// is the connection whose request causes the change, or nil.
func (s *server) breakOplocks(from *conn, sf *sharedFile) {
	// Writes come by the thousand and oplocked files are few: the common
	// case must not take the server lock.
	if sf.holders.Load() == 0 {
		return
	}
	s.mu.Lock()
	holders := s.takeHolders(sf)
	s.mu.Unlock()
	s.notifyBreak(from, holders)
}

// notifyBreak sends the oplock break notifications. It must be called
// without s.mu, since it writes to the network.
func (s *server) notifyBreak(from *conn, holders []*open) {
	for _, o := range holders {
		msg := newMsg(24)
		h := header{command: cmdOplockBreak, flags: flagResponse, messageID: ^uint64(0)}
		h.put(msg)
		le.PutUint16(msg[headerSize:], 24)
		msg[headerSize+2] = oplockNone
		le.PutUint64(msg[headerSize+8:], o.id)
		le.PutUint64(msg[headerSize+16:], o.id)
		c := o.sess.conn
		if c == from {
			// Ahead of the response to the request that broke it.
			c.send(msg)
		} else {
			// Another client, which may be slow to read: it must
			// not hold up this one.
			go c.send(msg)
		}
	}
}

// watch breaks the oplocks of the files that changed without the server
// being involved.
func (s *server) watch(ctx context.Context) {
	type probe struct {
		sf    *sharedFile
		path  string
		size  int64
		mtime time.Time
	}
	tick := time.NewTicker(watchInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if s.oplocks.Load() == 0 {
			continue
		}
		var probes []probe
		s.mu.Lock()
		for _, sf := range s.files {
			if sf.holders.Load() > 0 && len(sf.opens) > 0 {
				probes = append(probes, probe{sf, sf.opens[0].path, sf.size, sf.mtime})
			}
		}
		s.mu.Unlock()
		for _, p := range probes {
			fi, err := s.root.Stat(p.path)
			if err == nil && fi.Size() == p.size && fi.ModTime().Equal(p.mtime) {
				continue
			}
			s.breakOplocks(nil, p.sf)
		}
	}
}

// oplockBreak answers the acknowledgement some clients send to a break,
// though a break to "none" does not call for one.
func (c *conn) oplockBreak(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 24 || le.Uint16(p) != 24 {
		return statusInvalidParameter, nil
	}
	if _, st := c.lookup(r, p[8:24]); st != statusSuccess {
		return st, nil
	}
	out := newMsg(24)
	le.PutUint16(out[headerSize:], 24)
	copy(out[headerSize+8:], p[8:24])
	return statusSuccess, out
}
