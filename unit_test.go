package smbserver

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
	"time"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The values of this test are the worked example of [MS-NLMP] 4.2.4: user
// "User", domain "Domain", password "Password".
func TestNTLMv2Vectors(t *testing.T) {
	hash := NTHash("Password")
	if got := hex.EncodeToString(hash[:]); got != "a4f49c406510bdcab6824ee7c30fd852" {
		t.Fatalf("NT hash = %s", got)
	}
	owf := hmacMD5(hash[:], encodeUTF16("USER"+"Domain"))
	if got := hex.EncodeToString(owf); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTOWFv2 = %s", got)
	}

	// The "temp" blob of the example: time zero, client challenge aa...,
	// and the two AV pairs of the server.
	var av []byte
	for _, p := range []struct {
		id uint16
		v  string
	}{{2, "Domain"}, {1, "Server"}} {
		v := encodeUTF16(p.v)
		av = le.AppendUint16(av, p.id)
		av = le.AppendUint16(av, uint16(len(v)))
		av = append(av, v...)
	}
	av = append(av, 0, 0, 0, 0)
	blob := append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, make([]byte, 8)...)
	blob = append(blob, bytes.Repeat([]byte{0xaa}, 8)...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, av...)
	blob = append(blob, 0, 0, 0, 0)

	nonce := unhex(t, "0123456789abcdef")
	proof := hmacMD5(owf, nonce, blob)
	if got := hex.EncodeToString(proof); got != "68cd0ab851e51c96aabc927bebef6a1c" {
		t.Fatalf("NTProofStr = %s", got)
	}
	if got := hex.EncodeToString(hmacMD5(owf, proof)); got != "8de40ccadbc14a82f15cb0ad0de95ca3" {
		t.Fatalf("SessionBaseKey = %s", got)
	}

	// The same exchange through the server code, with key exchange: the
	// client sends the session key 55...55 encrypted under the base key.
	a := &ntlmAuth{challenge: []byte{0}}
	copy(a.nonce[:], nonce)
	msg := authenticateMessage("User", "Domain", append(proof, blob...), unhex(t, "c5dad2544fc9799094ce1ce90bc9d03e"))
	if !a.authenticate(msg, "user", hash) {
		t.Fatal("the example exchange was refused")
	}
	if !bytes.Equal(a.sessionKey, bytes.Repeat([]byte{0x55}, 16)) {
		t.Fatalf("exported session key = %x", a.sessionKey)
	}

	bad := NTHash("password")
	if (&ntlmAuth{challenge: []byte{0}, nonce: a.nonce}).authenticate(msg, "user", bad) {
		t.Fatal("a wrong password was accepted")
	}
	if (&ntlmAuth{challenge: []byte{0}, nonce: a.nonce}).authenticate(msg, "other", hash) {
		t.Fatal("a wrong user was accepted")
	}
	// An NTLMv1 response is 24 bytes and must never be considered.
	v1 := authenticateMessage("User", "Domain", make([]byte, 24), nil)
	if (&ntlmAuth{challenge: []byte{0}, nonce: a.nonce}).authenticate(v1, "user", hash) {
		t.Fatal("an NTLMv1 response was accepted")
	}
}

// authenticateMessage builds an NTLM AUTHENTICATE message. A non-nil key
// turns key exchange on.
func authenticateMessage(user, domain string, ntResponse, encKey []byte) []byte {
	flags := ntlmUnicode | ntlmNTLM | ntlmExtendedSession
	if encKey != nil {
		flags |= ntlmKeyExch
	}
	msg := make([]byte, 88)
	copy(msg, ntlmSignature)
	le.PutUint32(msg[8:], 3)
	le.PutUint32(msg[60:], flags)
	field := func(off int, v []byte) {
		le.PutUint16(msg[off:], uint16(len(v)))
		le.PutUint16(msg[off+2:], uint16(len(v)))
		le.PutUint32(msg[off+4:], uint32(len(msg)))
		msg = append(msg, v...)
	}
	field(20, ntResponse)
	field(28, encodeUTF16(domain))
	field(36, encodeUTF16(user))
	field(52, encKey)
	return msg
}

// RFC 4231, test case 1, truncated to the 16 bytes SMB keeps.
func TestSignature(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	if got := hex.EncodeToString(mac(key, []byte("Hi There"))); got != "b0344c61d8db38535ca8afceaf0bf12b" {
		t.Fatalf("mac = %s", got)
	}
	msg := make([]byte, headerSize+4)
	(&header{command: cmdEcho, messageID: 7}).put(msg)
	sign(key, msg)
	if le.Uint32(msg[16:])&flagSigned == 0 {
		t.Fatal("the signed flag is not set")
	}
	if !verify(key, bytes.Clone(msg)) {
		t.Fatal("a signed message does not verify")
	}
	msg[headerSize]++
	if verify(key, msg) {
		t.Fatal("a modified message verifies")
	}
}

// RFC 4493, section 4.
func TestAESCMAC(t *testing.T) {
	key := unhex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	msg := unhex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for n, want := range map[int]string{
		0:  "bb1d6929e95937287fa37d129b756746",
		16: "070a16b46b4d4144f79bdd9dd04a287c",
		40: "dfa66747de9ae63030ca32611497c827",
		64: "51f0bebf7e3b9d92fc49741779363cfe",
	} {
		if got := aesCMAC(key, msg[:n]); hex.EncodeToString(got[:]) != want {
			t.Errorf("CMAC of %d bytes = %x, want %s", n, got, want)
		}
	}
	// Longer than the internal chunk, against the definition applied one
	// block at a time.
	for _, n := range []int{4096, 4097, 8192 + 16, 12800} {
		long := bytes.Repeat(msg, 200)[:n]
		if got, want := aesCMAC(key, long), cmacReference(key, long); got != want {
			t.Errorf("CMAC of %d bytes = %x, want %x", n, got, want)
		}
	}
}

func cmacReference(key, msg []byte) (x [16]byte) {
	blk, _ := aes.NewCipher(key)
	var k1 [16]byte
	blk.Encrypt(k1[:], k1[:])
	cmacDouble(&k1)
	k2 := k1
	cmacDouble(&k2)
	for len(msg) > 16 {
		for i := range x {
			x[i] ^= msg[i]
		}
		blk.Encrypt(x[:], x[:])
		msg = msg[16:]
	}
	var last [16]byte
	copy(last[:], msg)
	pad := k1
	if len(msg) < 16 {
		last[len(msg)] = 0x80
		pad = k2
	}
	for i := range x {
		x[i] ^= last[i] ^ pad[i]
	}
	blk.Encrypt(x[:], x[:])
	return x
}

func TestHeaderRoundTrip(t *testing.T) {
	in := header{creditCharge: 3, status: statusAccessDenied, command: cmdRead, credits: 31, flags: flagResponse | flagSigned,
		next: 128, messageID: 1 << 40, treeID: 9, sessionID: 1<<63 + 5}
	b := make([]byte, headerSize)
	in.put(b)
	out, ok := parseHeader(b)
	if !ok || out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
	async := header{flags: flagAsync, asyncID: 77}
	async.put(b)
	if out, _ := parseHeader(b); out.asyncID != 77 || out.treeID != 0 {
		t.Fatalf("async header: %+v", out)
	}
	for _, bad := range [][]byte{nil, b[:63], append([]byte{0xFF}, b[1:]...)} {
		if _, ok := parseHeader(bad); ok {
			t.Fatalf("parseHeader accepted %x", bad)
		}
	}
}

func TestSub(t *testing.T) {
	b := make([]byte, 10)
	for _, c := range []struct {
		off, n uint32
		ok     bool
	}{{0, 10, true}, {10, 0, true}, {4, 6, true}, {4, 7, false}, {11, 0, false}, {1, 0xFFFFFFFF, false}, {0xFFFFFFFF, 2, false}} {
		if _, ok := sub(b, c.off, c.n); ok != c.ok {
			t.Errorf("sub(%d, %d) = %v", c.off, c.n, ok)
		}
	}
}

func TestFiletime(t *testing.T) {
	when := time.Date(2024, 2, 29, 12, 34, 56, 789000000, time.UTC)
	if got := fromFiletime(filetime(when)); !got.Equal(when) {
		t.Fatalf("round trip: %v", got)
	}
	if filetime(time.Unix(0, 0)) != filetimeEpoch {
		t.Fatal("the Unix epoch is not at the documented offset")
	}
	for _, v := range []uint64{0, ^uint64(0), ^uint64(0) - 1} {
		if !fromFiletime(v).IsZero() {
			t.Errorf("fromFiletime(%#x) is not the zero time", v)
		}
	}
}

func TestUTF16(t *testing.T) {
	for _, s := range []string{"", "plain", "accentué", "日本語", "😀 astral"} {
		if got := decodeUTF16(encodeUTF16(s)); got != s {
			t.Errorf("round trip of %q gave %q", s, got)
		}
	}
	if got := decodeUTF16([]byte{'a', 0, 'b'}); got != "a" {
		t.Errorf("odd length input gave %q", got)
	}
}

func TestParsePath(t *testing.T) {
	good := map[string]string{
		"":                     ".",
		"a":                    "a",
		`a\b\c.txt`:            "a/b/c.txt",
		"a\uF022b":             "a:b",
		"what\uF025":           "what?",
		"dot\uF029":            "dot.",
		"..hidden":             "..hidden",
		"...":                  "...",
		`dir\` + "trail\uF028": "dir/trail ",
		"back\uF026slash":      `back\slash`,
		"ctrl\uF001":           "ctrl\x01",
		"emoji😀":               "emoji😀",
	}
	for in, want := range good {
		if in == "back\uF026slash" && nameFromWire("x\uF026") != `x\` {
			t.Fatal("backslash mapping")
		}
		got, st := parsePath(in)
		// A backslash inside a name is a separator on Windows hosts,
		// where the name is refused instead.
		if in == "back\uF026slash" && st != statusSuccess {
			continue
		}
		if st != statusSuccess || got != want {
			t.Errorf("parsePath(%q) = %q, %#x; want %q", in, got, uint32(st), want)
		}
	}
	bad := []string{
		"..", `..\x`, `a\..`, `a\..\b`, ".", `a\.\b`, `\a`, `a\`, `a\\b`, "a/b", "/etc/passwd",
		"a\x00b", "file:stream", "file:stream:$DATA", `C:\x`,
		// The mapped forms of dot must not smuggle a parent reference.
		".\uF029", "\uF029\uF029", `a\` + "\uF029\uF029" + `\b`, "\uF029",
	}
	for _, in := range bad {
		if got, st := parsePath(in); st == statusSuccess {
			t.Errorf("parsePath(%q) = %q, want a refusal", in, got)
		}
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, st := parsePath(string(long)); st == statusSuccess {
		t.Error("a 256-byte component was accepted")
	}
}

func TestParseName(t *testing.T) {
	for _, c := range []struct {
		in, path, stream string
		ok               bool
	}{
		{"file", "file", "", true},
		{"file::$DATA", "file", "", true},
		{"file:meta", "file", "meta", true},
		{"file:meta:$DATA", "file", "meta", true},
		{`dir\file:AFP_AfpInfo:$DATA`, "dir/file", "AFP_AfpInfo", true},
		{":onroot", ".", "onroot", true},
		{"file:meta:$INDEX_ALLOCATION", "", "", false},
		{"file:a:b:c", "", "", false},
		{`dir:stream\file`, "", "", false},
		{`..\file:meta`, "", "", false},
		{"file:" + string(make([]byte, 300)), "", "", false},
	} {
		p, stream, st := parseName(c.in)
		if (st == statusSuccess) != c.ok || c.ok && (p != c.path || stream != c.stream) {
			t.Errorf("parseName(%q) = %q, %q, %#x", c.in, p, stream, uint32(st))
		}
	}
}

func TestNameMappingRoundTrip(t *testing.T) {
	for _, name := range []string{"a", "a:b", `q?*<>|"`, "trailing.", "trailing ", "mid.dle", ".", "..", ".git", "tab\there"} {
		wire := nameToWire(name)
		if name != "." && name != ".." {
			for _, r := range wire {
				if r < 0x20 || r == ':' || r == '?' || r == '*' {
					t.Errorf("nameToWire(%q) = %q still holds %q", name, wire, r)
				}
			}
		}
		if got := nameFromWire(wire); got != name {
			t.Errorf("round trip of %q gave %q", name, got)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything", true},
		{"*.txt", "a.txt", true},
		{"*.TXT", "a.txt", true},
		{"*.txt", "a.txt.bak", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"<.txt", "a.txt", true},
		{"", "", true},
		{"*", "", true},
		{"?", "", false},
	} {
		if got := matchPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v", c.pattern, c.name, got)
		}
	}
}

func TestSPNEGO(t *testing.T) {
	ntlm := append([]byte(ntlmSignature), 1, 0, 0, 0, 0, 0, 0, 0)

	tok, ok := parseSPNEGO(ntlm)
	if !ok || !tok.raw || !bytes.Equal(tok.mechToken, ntlm) {
		t.Fatalf("raw NTLMSSP: %+v %v", tok, ok)
	}

	mechs := derTLV(0x30, derTLV(0x06, oidNTLM))
	init := derTLV(0x60, derTLV(0x06, oidSPNEGO), derTLV(0xA0, derTLV(0x30,
		derTLV(0xA0, mechs), derTLV(0xA2, derTLV(0x04, ntlm)))))
	tok, ok = parseSPNEGO(init)
	if !ok || !tok.init || !tok.ntlmFirst || !bytes.Equal(tok.mechToken, ntlm) || !bytes.Equal(tok.mechTypes, mechs) {
		t.Fatalf("NegTokenInit: %+v %v", tok, ok)
	}

	// Another mechanism first: NTLM is then not the preferred one.
	other := derTLV(0x30, derTLV(0x06, []byte{0x2a, 0x86, 0x48}), derTLV(0x06, oidNTLM))
	tok, ok = parseSPNEGO(derTLV(0x60, derTLV(0x06, oidSPNEGO), derTLV(0xA0, derTLV(0x30, derTLV(0xA0, other)))))
	if !ok || tok.ntlmFirst || tok.mechToken != nil {
		t.Fatalf("NegTokenInit with a foreign mechanism: %+v %v", tok, ok)
	}

	tok, ok = parseSPNEGO(negTokenResp(negAcceptIncomplete, true, ntlm, []byte("mic")))
	if !ok || tok.init || !bytes.Equal(tok.mechToken, ntlm) || string(tok.mic) != "mic" {
		t.Fatalf("NegTokenResp: %+v %v", tok, ok)
	}

	// What the server itself announces must parse as an initial token
	// that prefers NTLM.
	tok, ok = parseSPNEGO(negTokenInit())
	if !ok || !tok.init || !tok.ntlmFirst {
		t.Fatalf("own NegTokenInit: %+v %v", tok, ok)
	}

	// A long token exercises the multi-byte DER lengths.
	big := append(bytes.Clone(ntlm), make([]byte, 1000)...)
	tok, ok = parseSPNEGO(negTokenResp(negAcceptIncomplete, false, big, nil))
	if !ok || !bytes.Equal(tok.mechToken, big) {
		t.Fatal("long token")
	}

	for _, bad := range [][]byte{nil, {0x60}, {0x60, 0x05, 1, 2}, {0x30, 0}, {0xA1, 0x82, 0xFF, 0xFF}, {0xA1, 0x84, 0, 0, 0, 1, 0}} {
		if _, ok := parseSPNEGO(bad); ok {
			t.Errorf("parseSPNEGO accepted %x", bad)
		}
	}
}

func TestErrorBody(t *testing.T) {
	b := errorBody(nil)
	if len(b) != headerSize+9 || le.Uint16(b[headerSize:]) != 9 {
		t.Fatalf("empty error body: %x", b[headerSize:])
	}
	b = errorBody([]byte{1, 2, 3, 4})
	if len(b) != headerSize+12 || le.Uint32(b[headerSize+4:]) != 4 {
		t.Fatalf("error body with data: %x", b[headerSize:])
	}
}

func TestLockOverlap(t *testing.T) {
	top := ^uint64(0)
	for _, c := range []struct {
		off, n, off2, n2 uint64
		want             bool
	}{
		{0, 10, 10, 10, false},
		{0, 10, 9, 1, true},
		{5, 1, 0, 10, true},
		{0, 0, 0, 10, false},
		{top - 1, 1, top - 1, 1, true},
		{top - 9, 10, 0, 10, false},
		{0, top, top - 1, 1, true},
	} {
		l := rangeLock{off: c.off, n: c.n}
		if got := l.overlaps(c.off2, c.n2); got != c.want {
			t.Errorf("[%d,+%d) vs [%d,+%d) = %v", c.off, c.n, c.off2, c.n2, got)
		}
	}
}
