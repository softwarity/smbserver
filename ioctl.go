package smbserver

import "fmt"

const (
	fsctlDFSGetReferrals       uint32 = 0x00060194
	fsctlValidateNegotiateInfo uint32 = 0x00140204
)

// ioctl refuses nearly every control code. None is needed to serve files;
// the ones clients send on their own initiative (DFS referrals, network
// interface queries, resume keys for server-side copy) all have a documented
// fallback when the server declines.
func (c *conn) ioctl(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 56 || le.Uint16(p) != 57 {
		return statusInvalidParameter, nil
	}
	code := le.Uint32(p[4:])
	if trace {
		r.note = fmt.Sprintf("code %#x", code)
	}
	switch {
	case code == fsctlDFSGetReferrals:
		// What a server without a DFS namespace answers; clients then
		// carry on with a plain tree connect.
		return statusNotFound, nil
	case code == fsctlValidateNegotiateInfo && c.dialect == dialect300:
		// SMB 3.0 clients require it; on SMB 2 they do without.
		input, ok := sub(r.msg, le.Uint32(p[24:]), le.Uint32(p[28:]))
		if !ok {
			return statusInvalidParameter, nil
		}
		data, st := c.validateNegotiate(r, input)
		if st != statusSuccess {
			return st, nil
		}
		if uint32(len(data)) > le.Uint32(p[44:]) {
			return statusBufferTooSmall, nil
		}
		out := newMsg(48)
		q := out[headerSize:]
		le.PutUint16(q, 49)
		le.PutUint32(q[4:], code)
		copy(q[8:24], p[8:24])
		le.PutUint32(q[24:], headerSize+48)
		le.PutUint32(q[32:], headerSize+48)
		le.PutUint32(q[36:], uint32(len(data)))
		return statusSuccess, append(out, data...)
	}
	return statusNotSupported, nil
}

// validateNegotiate answers FSCTL_VALIDATE_NEGOTIATE_INFO: the client
// repeats, under the protection of its signature, what it sent in the
// unprotected NEGOTIATE. A mismatch means someone tampered with the
// negotiation, and the connection is dropped.
func (c *conn) validateNegotiate(r *request, in []byte) ([]byte, ntStatus) {
	if len(in) < 24 {
		return nil, statusInvalidParameter
	}
	count := int(le.Uint16(in[22:]))
	if len(in) < 24+2*count {
		return nil, statusInvalidParameter
	}
	offered := make([]uint16, count)
	for i := range offered {
		offered[i] = le.Uint16(in[24+2*i:])
	}
	if le.Uint32(in) != c.clientCaps || string(in[4:20]) != string(c.clientGUID[:]) ||
		le.Uint16(in[20:]) != c.clientSecMode || pickDialect(offered) != c.dialect {
		r.fatal = true
		return nil, statusAccessDenied
	}
	out := make([]byte, 24)
	le.PutUint32(out, capLargeMTU)
	copy(out[4:], c.srv.guid[:])
	le.PutUint16(out[20:], secModeSigningEnabled|secModeSigningRequired)
	le.PutUint16(out[22:], c.dialect)
	return out, statusSuccess
}
