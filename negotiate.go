package smbserver

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

const (
	secModeSigningEnabled  uint16 = 1
	secModeSigningRequired uint16 = 2

	capLargeMTU uint32 = 0x00000004
)

// dialects lists what the server speaks, preferred first. SMB 2.1 is what
// every native client is served: it leaves out the whole of SMB 3
// (encryption, negotiate contexts, pre-authentication integrity) that a
// single share behind a tunnel has no use for. SMB 3.0 comes last, so it is
// only chosen for a client that offers nothing lower, which is one mounted
// with an explicit "vers=3.0"; it is then served without encryption nor
// multichannel, the difference being the signing algorithm.
var dialects = []uint16{dialect210, dialect202, dialect300}

func pickDialect(offered []uint16) uint16 {
	for _, d := range dialects {
		if slices.Contains(offered, d) {
			return d
		}
	}
	return 0
}

// smb1Negotiate answers the SMB1 NEGOTIATE that older clients open with.
// SMB1 itself is never spoken: the only acceptable outcome is the client
// offering an SMB2 dialect, in which case the reply is an SMB2 NEGOTIATE
// response telling it to carry on in SMB2. Anything else closes the
// connection.
func (c *conn) smb1Negotiate(msg []byte) error {
	if c.negotiated || c.smb1Seen || len(msg) < 35 || msg[4] != 0x72 {
		return errProtocol
	}
	c.smb1Seen = true
	// After the 32-byte header: word count (zero), byte count, then the
	// dialect strings, each introduced by 0x02 and NUL terminated.
	var wildcard, smb202 bool
	for _, d := range bytes.Split(msg[35:], []byte{0}) {
		switch string(bytes.TrimPrefix(d, []byte{2})) {
		case "SMB 2.???":
			wildcard = true
		case "SMB 2.002":
			smb202 = true
		}
	}
	dialect := dialectAny
	switch {
	case wildcard:
	case smb202:
		dialect = dialect202
		c.setDialect(dialect202)
	default:
		return fmt.Errorf("%w: SMB1 only client", errProtocol)
	}
	out := c.negotiateResponse(dialect)
	rh := header{command: cmdNegotiate, flags: flagResponse, credits: 1}
	rh.put(out)
	return c.send(out)
}

func (c *conn) setDialect(d uint16) {
	c.negotiated = true
	c.dialect = d
	c.maxIO = maxIO
	if d == dialect202 {
		// SMB 2.0.2 has no multi-credit requests: 64 KiB is its ceiling.
		c.maxIO = 0x10000
	}
}

func (c *conn) negotiate(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 36 || le.Uint16(p) != 36 {
		return statusInvalidParameter, nil
	}
	count := int(le.Uint16(p[2:]))
	if count == 0 || count > 64 || len(p) < 36+2*count {
		return statusInvalidParameter, nil
	}
	offered := make([]uint16, count)
	for i := range offered {
		offered[i] = le.Uint16(p[36+2*i:])
	}
	dialect := pickDialect(offered)
	if dialect == 0 {
		return statusNotSupported, nil
	}
	// Kept for the validation an SMB 3.0 client asks for once signed.
	c.clientSecMode = le.Uint16(p[4:])
	c.clientCaps = le.Uint32(p[8:])
	copy(c.clientGUID[:], p[12:28])
	c.setDialect(dialect)
	return statusSuccess, c.negotiateResponse(dialect)
}

func (c *conn) negotiateResponse(dialect uint16) []byte {
	token := negTokenInit()
	out := newMsg(64)
	p := out[headerSize:]
	le.PutUint16(p, 65)
	le.PutUint16(p[2:], secModeSigningEnabled|secModeSigningRequired)
	le.PutUint16(p[4:], dialect)
	copy(p[8:], c.srv.guid[:])
	size := uint32(0x10000)
	if dialect != dialect202 {
		le.PutUint32(p[24:], capLargeMTU)
		size = maxIO
	}
	le.PutUint32(p[28:], size)
	le.PutUint32(p[32:], size)
	le.PutUint32(p[36:], size)
	le.PutUint64(p[40:], filetime(time.Now()))
	le.PutUint64(p[48:], filetime(c.srv.start))
	le.PutUint16(p[56:], headerSize+64)
	le.PutUint16(p[58:], uint16(len(token)))
	return append(out, token...)
}
