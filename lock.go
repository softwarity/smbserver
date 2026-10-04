package smbserver

// Byte-range locks are kept in the server and arbitrate between its clients
// only: they are not pushed down to the filesystem, so a process working on
// the volume directly does not see them. A lock that cannot be taken is
// refused at once; the server never makes a request wait.

const (
	lockShared    = 0x01
	lockExclusive = 0x02
	lockUnlock    = 0x04
)

type rangeLock struct {
	owner     *open
	off, n    uint64
	exclusive bool
}

func (l *rangeLock) overlaps(off, n uint64) bool {
	// Empty ranges never conflict. The subtractions avoid overflowing on
	// ranges that reach the top of the 64-bit space, which Windows
	// applications use as advisory lock areas.
	if l.n == 0 || n == 0 {
		return false
	}
	return off-l.off < l.n || l.off-off < n
}

func (c *conn) lock(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 24 || le.Uint16(p) != 48 {
		return statusInvalidParameter, nil
	}
	count := int(le.Uint16(p[2:]))
	if count == 0 || count > 64 || len(p) < 24+24*count {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[8:24])
	if st != statusSuccess {
		return st, nil
	}
	if o.isDir {
		return statusInvalidDeviceRequest, nil
	}

	s := c.srv
	s.mu.Lock()
	defer s.mu.Unlock()
	sf := o.shared
	taken := len(sf.locks)
	for i := 0; i < count; i++ {
		e := p[24+24*i:]
		off, n, flags := le.Uint64(e), le.Uint64(e[8:]), le.Uint32(e[16:])
		if flags&lockUnlock != 0 {
			found := false
			for j, l := range sf.locks {
				if l.owner == o && l.off == off && l.n == n {
					sf.locks = append(sf.locks[:j], sf.locks[j+1:]...)
					found = true
					break
				}
			}
			if !found {
				return statusRangeNotLocked, nil
			}
			taken = len(sf.locks)
			continue
		}
		exclusive := flags&lockExclusive != 0
		if !exclusive && flags&lockShared == 0 {
			sf.locks = sf.locks[:taken]
			return statusInvalidParameter, nil
		}
		for _, l := range sf.locks {
			if (exclusive || l.exclusive) && l.overlaps(off, n) {
				// A request takes all its ranges or none.
				sf.locks = sf.locks[:taken]
				return statusLockNotGranted, nil
			}
		}
		sf.locks = append(sf.locks, rangeLock{o, off, n, exclusive})
	}
	return statusSuccess, emptyBody()
}

// dropLocks removes every lock a handle holds. Called with s.mu held.
func (s *server) dropLocks(sf *sharedFile, o *open) {
	kept := sf.locks[:0]
	for _, l := range sf.locks {
		if l.owner != o {
			kept = append(kept, l)
		}
	}
	sf.locks = kept
}
