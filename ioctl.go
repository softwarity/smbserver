package smbserver

import "fmt"

const fsctlDFSGetReferrals uint32 = 0x00060194

// ioctl refuses every control code. None is needed to serve files; the ones
// clients send on their own initiative (DFS referrals, negotiate validation,
// network interface queries, resume keys for server-side copy) all have a
// documented fallback when the server declines.
func (c *conn) ioctl(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 56 || le.Uint16(p) != 57 {
		return statusInvalidParameter, nil
	}
	code := le.Uint32(p[4:])
	if trace {
		r.note = fmt.Sprintf("code %#x", code)
	}
	if code == fsctlDFSGetReferrals {
		// What a server without a DFS namespace answers; clients then
		// carry on with a plain tree connect.
		return statusNotFound, nil
	}
	return statusNotSupported, nil
}
