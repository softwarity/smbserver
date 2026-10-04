package smbserver

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"strings"
	"time"

	"golang.org/x/crypto/md4"
)

// NTLMv2 server side, from [MS-NLMP]. Only version 2 responses are accepted:
// LM and NTLMv1 are refused outright.

const (
	ntlmSignature = "NTLMSSP\x00"

	ntlmUnicode         uint32 = 0x00000001
	ntlmRequestTarget   uint32 = 0x00000004
	ntlmSign            uint32 = 0x00000010
	ntlmSeal            uint32 = 0x00000020
	ntlmNTLM            uint32 = 0x00000200
	ntlmAlwaysSign      uint32 = 0x00008000
	ntlmTargetServer    uint32 = 0x00020000
	ntlmExtendedSession uint32 = 0x00080000
	ntlmTargetInfo      uint32 = 0x00800000
	ntlmVersion         uint32 = 0x02000000
	ntlm128             uint32 = 0x20000000
	ntlmKeyExch         uint32 = 0x40000000
	ntlm56              uint32 = 0x80000000
)

// serverName is what the server calls itself in the NTLM challenge. It is a
// constant so that nothing about the host (a pod name, for instance) reaches
// an unauthenticated peer.
const serverName = "SMBSERVER"

// NTHash returns the NT hash of a password: MD4 over its UTF-16LE encoding.
// It is the secret Config.NTHash expects.
func NTHash(password string) [16]byte {
	h := md4.New()
	h.Write(encodeUTF16(password))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func hmacMD5(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// ntlmAuth carries one NTLM exchange from NEGOTIATE to AUTHENTICATE.
type ntlmAuth struct {
	negotiate []byte
	challenge []byte
	nonce     [8]byte
	flags     uint32

	// Set by authenticate on success.
	sessionKey []byte
	authFlags  uint32
}

func isNTLM(b []byte, msgType uint32) bool {
	return len(b) >= 12 && string(b[:8]) == ntlmSignature && le.Uint32(b[8:]) == msgType
}

// start answers a NEGOTIATE message with a CHALLENGE.
func (a *ntlmAuth) start(negotiate []byte, now time.Time) ([]byte, bool) {
	if !isNTLM(negotiate, 1) || len(negotiate) < 16 {
		return nil, false
	}
	a.negotiate = append([]byte(nil), negotiate...)
	client := le.Uint32(negotiate[12:])
	a.flags = ntlmUnicode | ntlmRequestTarget | ntlmNTLM | ntlmAlwaysSign | ntlmTargetServer |
		ntlmExtendedSession | ntlmTargetInfo | ntlmVersion |
		client&(ntlmSign|ntlmSeal|ntlmKeyExch|ntlm128|ntlm56)
	rand.Read(a.nonce[:])

	name := encodeUTF16(serverName)
	var info []byte
	av := func(id uint16, v []byte) {
		info = le.AppendUint16(info, id)
		info = le.AppendUint16(info, uint16(len(v)))
		info = append(info, v...)
	}
	av(2, name) // MsvAvNbDomainName
	av(1, name) // MsvAvNbComputerName
	av(4, name) // MsvAvDnsDomainName
	av(3, name) // MsvAvDnsComputerName
	// The timestamp is what makes clients include a MIC in AUTHENTICATE.
	av(7, le.AppendUint64(nil, filetime(now)))
	av(0, nil)

	msg := make([]byte, 56, 56+len(name)+len(info))
	copy(msg, ntlmSignature)
	le.PutUint32(msg[8:], 2)
	le.PutUint16(msg[12:], uint16(len(name)))
	le.PutUint16(msg[14:], uint16(len(name)))
	le.PutUint32(msg[16:], 56)
	le.PutUint32(msg[20:], a.flags)
	copy(msg[24:], a.nonce[:])
	le.PutUint16(msg[40:], uint16(len(info)))
	le.PutUint16(msg[42:], uint16(len(info)))
	le.PutUint32(msg[44:], uint32(56+len(name)))
	// Version: 6.1 build 7600, NTLM revision 15.
	copy(msg[48:], []byte{6, 1, 0xb0, 0x1d, 0, 0, 0, 15})
	msg = append(msg, name...)
	msg = append(msg, info...)
	a.challenge = msg
	return msg, true
}

// authenticate checks an AUTHENTICATE message against the single account of
// the server. On success a.sessionKey holds the exported session key.
func (a *ntlmAuth) authenticate(msg []byte, user string, ntHash [16]byte) bool {
	if a.challenge == nil || !isNTLM(msg, 3) || len(msg) < 64 {
		return false
	}
	field := func(off int) []byte {
		b, _ := sub(msg, le.Uint32(msg[off+4:]), uint32(le.Uint16(msg[off:])))
		return b
	}
	nt, domain, name, encKey := field(20), field(28), field(36), field(52)
	flags := le.Uint32(msg[60:])

	// An NTLMv2 response is the 16-byte proof followed by a blob of at
	// least 32 bytes. The 24-byte NTLMv1 response fails this test.
	if len(nt) < 48 || nt[16] != 1 || nt[17] != 1 {
		return false
	}
	text := func(b []byte) string {
		if flags&ntlmUnicode != 0 {
			return decodeUTF16(b)
		}
		return string(b)
	}
	userName := text(name)
	if !strings.EqualFold(userName, user) {
		return false
	}
	proof, blob := nt[:16], nt[16:]

	// Clients disagree on the domain they fold into the hash (their own
	// workgroup, the server name from the challenge, or nothing), so the
	// one they sent is used, as [MS-NLMP] 3.3.2 specifies.
	owf := hmacMD5(ntHash[:], encodeUTF16(strings.ToUpper(userName)+text(domain)))
	if !hmac.Equal(hmacMD5(owf, a.nonce[:], blob), proof) {
		return false
	}
	key := hmacMD5(owf, proof)
	if flags&ntlmKeyExch != 0 {
		if len(encKey) != 16 {
			return false
		}
		c, _ := rc4.NewCipher(key)
		key = make([]byte, 16)
		c.XORKeyStream(key, encKey)
	}

	// When the blob says a MIC is present, it protects the three messages
	// of the exchange against tampering and must verify.
	if avFlags(blob[28:])&2 != 0 {
		if len(msg) < 88 {
			return false
		}
		clean := append([]byte(nil), msg...)
		clear(clean[72:88])
		if !hmac.Equal(hmacMD5(key, a.negotiate, a.challenge, clean), msg[72:88]) {
			return false
		}
	}
	a.sessionKey = key
	a.authFlags = flags
	return true
}

// avFlags returns the MsvAvFlags value of an AV pair list, or zero.
func avFlags(av []byte) uint32 {
	for len(av) >= 4 {
		id, n := le.Uint16(av), int(le.Uint16(av[2:]))
		av = av[4:]
		if id == 0 || len(av) < n {
			return 0
		}
		if id == 6 && n >= 4 {
			return le.Uint32(av)
		}
		av = av[n:]
	}
	return 0
}

// mechListMIC signs the SPNEGO mechanism list with the server-to-client NTLM
// signing key ([MS-NLMP] 3.4.4.2, sequence number zero). Windows expects it
// back whenever it sent its own.
func (a *ntlmAuth) mechListMIC(mechTypes []byte) []byte {
	if a.authFlags&ntlmExtendedSession == 0 {
		return nil
	}
	const signMagic = "session key to server-to-client signing key magic constant\x00"
	const sealMagic = "session key to server-to-client sealing key magic constant\x00"
	signKey := md5.Sum(append(append([]byte(nil), a.sessionKey...), signMagic...))
	sum := hmacMD5(signKey[:], []byte{0, 0, 0, 0}, mechTypes)[:8]
	if a.authFlags&ntlmKeyExch != 0 {
		k := a.sessionKey
		switch {
		case a.authFlags&ntlm128 != 0:
		case a.authFlags&ntlm56 != 0:
			k = k[:7]
		default:
			k = k[:5]
		}
		sealKey := md5.Sum(append(append([]byte(nil), k...), sealMagic...))
		c, _ := rc4.NewCipher(sealKey[:])
		c.XORKeyStream(sum, sum)
	}
	out := []byte{1, 0, 0, 0}
	out = append(out, sum...)
	return append(out, 0, 0, 0, 0)
}
