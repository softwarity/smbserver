package smbserver

import (
	"io"
	"math"
)

// charged reports whether the credit charge of a request covers a payload of
// n bytes: one credit per 64 KiB, on the dialects that have multi-credit
// requests ([MS-SMB2] 3.3.5.2.5).
func (c *conn) charged(r *request, n uint32) bool {
	if n > c.maxIO {
		return false
	}
	if c.dialect == dialect202 || n <= 0x10000 {
		return true
	}
	return uint32(r.hdr.creditCharge) >= (n-1)/0x10000+1
}

func (c *conn) read(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 48 || le.Uint16(p) != 49 {
		return statusInvalidParameter, nil
	}
	length := le.Uint32(p[4:])
	offset := le.Uint64(p[8:])
	minimum := le.Uint32(p[32:])
	if !c.charged(r, length) || offset > math.MaxInt64 {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[16:32])
	if st != statusSuccess {
		return st, nil
	}
	// The file is read straight into the response, after the header and
	// the 16 bytes of fixed fields.
	const dataOff = headerSize + 16
	out := newMsg(16 + max(int(length), 1))
	_, f := o.location()
	switch {
	case o.isDir:
		return statusInvalidDeviceRequest, nil
	case f == nil || o.access&(fileReadData|fileExecute) == 0:
		return statusAccessDenied, nil
	}
	n, err := f.ReadAt(out[dataOff:], int64(offset))
	if err != nil && err != io.EOF {
		return errStatus(err), nil
	}
	if length > 0 && (n == 0 || uint32(n) < minimum) {
		return statusEndOfFile, nil
	}
	q := out[headerSize:]
	le.PutUint16(q, 17)
	q[2] = dataOff
	le.PutUint32(q[4:], uint32(n))
	return statusSuccess, out[:max(dataOff+n, dataOff+1)]
}

func (c *conn) write(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 48 || le.Uint16(p) != 49 {
		return statusInvalidParameter, nil
	}
	length := le.Uint32(p[4:])
	offset := le.Uint64(p[8:])
	data, ok := sub(r.msg, uint32(le.Uint16(p[2:])), length)
	if !ok || !c.charged(r, length) {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[16:32])
	if st != statusSuccess {
		return st, nil
	}
	_, f := o.location()
	switch {
	case o.isDir:
		return statusInvalidDeviceRequest, nil
	case f == nil || o.access&(fileWriteData|fileAppendData) == 0 || c.srv.cfg.ReadOnly:
		return statusAccessDenied, nil
	}
	// An offset of all ones means "at the end of the file".
	if offset == math.MaxUint64 {
		fi, err := f.Stat()
		if err != nil {
			return errStatus(err), nil
		}
		offset = uint64(fi.Size())
	}
	if offset > math.MaxInt64-uint64(length) {
		return statusInvalidParameter, nil
	}
	if _, err := f.WriteAt(data, int64(offset)); err != nil {
		return errStatus(err), nil
	}
	out := newMsg(17)
	le.PutUint16(out[headerSize:], 17)
	le.PutUint32(out[headerSize+4:], length)
	return statusSuccess, out
}

func (c *conn) flush(r *request) (ntStatus, []byte) {
	p := r.msg[headerSize:]
	if len(p) < 24 || le.Uint16(p) != 24 {
		return statusInvalidParameter, nil
	}
	o, st := c.lookup(r, p[8:24])
	if st != statusSuccess {
		return st, nil
	}
	// A handle without write access has nothing of its own to flush.
	if _, f := o.location(); f != nil && o.access&(fileWriteData|fileAppendData) != 0 {
		if err := f.Sync(); err != nil {
			return errStatus(err), nil
		}
	}
	return statusSuccess, emptyBody()
}
