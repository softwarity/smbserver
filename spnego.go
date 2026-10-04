package smbserver

import "bytes"

// This file holds the small subset of DER and SPNEGO ([MS-SPNG], RFC 4178)
// that wraps NTLMSSP during session setup. It is hand-written rather than
// built on encoding/asn1 because the structures are few, and a decoder that
// only slices is easy to fuzz.

var (
	oidSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLM   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

func derTLV(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// derRead splits the first TLV off b. raw is the whole element, header
// included.
func derRead(b []byte) (tag byte, content, raw, rest []byte, ok bool) {
	if len(b) < 2 {
		return
	}
	tag = b[0]
	n := int(b[1])
	hdr := 2
	if n >= 0x80 {
		k := n & 0x7f
		if k == 0 || k > 3 || len(b) < 2+k {
			return
		}
		n = 0
		for _, v := range b[2 : 2+k] {
			n = n<<8 | int(v)
		}
		hdr += k
	}
	if len(b)-hdr < n {
		return
	}
	return tag, b[hdr : hdr+n], b[:hdr+n], b[hdr+n:], true
}

// spnegoToken is what the server needs out of a client security blob.
type spnegoToken struct {
	// raw is set when the client sent bare NTLMSSP without SPNEGO.
	raw bool
	// init is set for a NegTokenInit, the first token of an exchange.
	init bool
	// mechTypes is the DER encoding of the client's mechanism list, which
	// the mechListMIC covers.
	mechTypes []byte
	// ntlmFirst reports whether NTLMSSP is the client's preferred
	// mechanism.
	ntlmFirst bool
	mechToken []byte
	mic       []byte
}

func parseSPNEGO(b []byte) (t spnegoToken, ok bool) {
	if bytes.HasPrefix(b, []byte(ntlmSignature)) {
		return spnegoToken{raw: true, mechToken: b}, true
	}
	tag, content, _, _, ok := derRead(b)
	if !ok {
		return t, false
	}
	switch tag {
	case 0x60: // GSS-API InitialContextToken
		otag, oid, _, rest, ok := derRead(content)
		if !ok || otag != 0x06 || !bytes.Equal(oid, oidSPNEGO) {
			return t, false
		}
		tag, content, _, _, ok = derRead(rest)
		if !ok || tag != 0xA0 {
			return t, false
		}
		t.init = true
	case 0xA0:
		t.init = true
	case 0xA1:
	default:
		return t, false
	}
	stag, seq, _, _, ok := derRead(content)
	if !ok || stag != 0x30 {
		return t, false
	}
	for len(seq) > 0 {
		var field []byte
		tag, field, _, seq, ok = derRead(seq)
		if !ok {
			return t, false
		}
		itag, inner, raw, _, ok := derRead(field)
		if !ok {
			return t, false
		}
		switch {
		case t.init && tag == 0xA0 && itag == 0x30:
			t.mechTypes = raw
			if ftag, first, _, _, ok := derRead(inner); ok && ftag == 0x06 {
				t.ntlmFirst = bytes.Equal(first, oidNTLM)
			}
		case tag == 0xA2 && itag == 0x04:
			t.mechToken = inner
		case tag == 0xA3 && itag == 0x04:
			t.mic = inner
		}
	}
	return t, true
}

// negTokenInit is the security blob of the NEGOTIATE response: the server
// announces NTLMSSP as its only mechanism.
func negTokenInit() []byte {
	mechs := derTLV(0xA0, derTLV(0x30, derTLV(0x06, oidNTLM)))
	return derTLV(0x60, derTLV(0x06, oidSPNEGO), derTLV(0xA0, derTLV(0x30, mechs)))
}

const (
	negAcceptCompleted  = 0
	negAcceptIncomplete = 1
)

func negTokenResp(state byte, withMech bool, token, mic []byte) []byte {
	seq := derTLV(0xA0, derTLV(0x0A, []byte{state}))
	if withMech {
		seq = append(seq, derTLV(0xA1, derTLV(0x06, oidNTLM))...)
	}
	if token != nil {
		seq = append(seq, derTLV(0xA2, derTLV(0x04, token))...)
	}
	if mic != nil {
		seq = append(seq, derTLV(0xA3, derTLV(0x04, mic))...)
	}
	return derTLV(0xA1, derTLV(0x30, seq))
}
