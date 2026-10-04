package smbserver

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

var le = binary.LittleEndian

// SMB2 command codes ([MS-SMB2] 2.2.1).
const (
	cmdNegotiate uint16 = iota
	cmdSessionSetup
	cmdLogoff
	cmdTreeConnect
	cmdTreeDisconnect
	cmdCreate
	cmdClose
	cmdFlush
	cmdRead
	cmdWrite
	cmdLock
	cmdIoctl
	cmdCancel
	cmdEcho
	cmdQueryDirectory
	cmdChangeNotify
	cmdQueryInfo
	cmdSetInfo
	cmdOplockBreak
)

const (
	headerSize = 64

	flagResponse uint32 = 0x00000001
	flagAsync    uint32 = 0x00000002
	flagRelated  uint32 = 0x00000004
	flagSigned   uint32 = 0x00000008
)

const (
	dialect202 uint16 = 0x0202
	dialect210 uint16 = 0x0210
	dialect300 uint16 = 0x0300
	dialect302 uint16 = 0x0302
	dialect311 uint16 = 0x0311
	// dialectAny is the wildcard a server answers to an SMB1 multi-protocol
	// negotiate, telling the client to continue with an SMB2 NEGOTIATE.
	dialectAny uint16 = 0x02FF
)

// header is the decoded 64-byte SMB2 packet header. In a request the status
// field carries the channel sequence, which this server ignores.
type header struct {
	creditCharge uint16
	status       ntStatus
	command      uint16
	credits      uint16
	flags        uint32
	next         uint32
	messageID    uint64
	asyncID      uint64
	treeID       uint32
	sessionID    uint64
}

func parseHeader(b []byte) (h header, ok bool) {
	if len(b) < headerSize || b[0] != 0xFE || b[1] != 'S' || b[2] != 'M' || b[3] != 'B' || le.Uint16(b[4:]) != headerSize {
		return h, false
	}
	h.creditCharge = le.Uint16(b[6:])
	h.status = ntStatus(le.Uint32(b[8:]))
	h.command = le.Uint16(b[12:])
	h.credits = le.Uint16(b[14:])
	h.flags = le.Uint32(b[16:])
	h.next = le.Uint32(b[20:])
	h.messageID = le.Uint64(b[24:])
	if h.flags&flagAsync != 0 {
		h.asyncID = le.Uint64(b[32:])
	} else {
		h.treeID = le.Uint32(b[36:])
	}
	h.sessionID = le.Uint64(b[40:])
	return h, true
}

// put writes the header into the first 64 bytes of b, leaving the signature
// zeroed.
func (h *header) put(b []byte) {
	clear(b[:headerSize])
	b[0], b[1], b[2], b[3] = 0xFE, 'S', 'M', 'B'
	le.PutUint16(b[4:], headerSize)
	le.PutUint16(b[6:], h.creditCharge)
	le.PutUint32(b[8:], uint32(h.status))
	le.PutUint16(b[12:], h.command)
	le.PutUint16(b[14:], h.credits)
	le.PutUint32(b[16:], h.flags)
	le.PutUint32(b[20:], h.next)
	le.PutUint64(b[24:], h.messageID)
	if h.flags&flagAsync != 0 {
		le.PutUint64(b[32:], h.asyncID)
	} else {
		le.PutUint32(b[36:], h.treeID)
	}
	le.PutUint64(b[40:], h.sessionID)
}

// sub returns b[off:off+n] when that range lies inside b. Every offset and
// length a client sends goes through it, so a malformed packet yields an
// error status instead of a panic.
func sub(b []byte, off, n uint32) ([]byte, bool) {
	if uint64(off)+uint64(n) > uint64(len(b)) {
		return nil, false
	}
	return b[off : off+n], true
}

// newMsg allocates a response with room for the header in front of an n-byte
// body, so that offsets inside handlers match the offsets of the protocol,
// which all count from the start of the header.
func newMsg(n int) []byte {
	return make([]byte, headerSize+n)
}

func encodeUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		le.PutUint16(b[2*i:], v)
	}
	return b
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// filetimeEpoch is the number of 100ns intervals between 1601-01-01 and the
// Unix epoch.
const filetimeEpoch = 116444736000000000

func filetime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return uint64(t.Unix()*10000000 + int64(t.Nanosecond()/100) + filetimeEpoch)
}

// fromFiletime converts a FILETIME sent by a client. Zero and the negative
// sentinels of [MS-FSCC] ("do not change") map to the zero time.
func fromFiletime(v uint64) time.Time {
	if v == 0 || int64(v) < 0 || v < filetimeEpoch {
		return time.Time{}
	}
	v -= filetimeEpoch
	return time.Unix(int64(v/10000000), int64(v%10000000)*100)
}

func pad8(b []byte) []byte {
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}
