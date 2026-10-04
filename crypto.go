package smbserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// SMB 3.0 signs with AES-CMAC under a key derived from the session key. It
// is here for the clients that are configured to speak SMB 3.0 and nothing
// else; see the dialects in negotiate.go.

// kdf is the SP800-108 counter-mode derivation of [MS-SMB2] 3.1.4.2, fixed to
// HMAC-SHA256 and a 128-bit output. label and context include their
// terminating NUL where the specification says so.
func kdf(key, label, context []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{0, 0, 0, 1})
	h.Write(label)
	h.Write([]byte{0})
	h.Write(context)
	h.Write([]byte{0, 0, 0, 128})
	return h.Sum(nil)[:16]
}

// aesCMAC implements RFC 4493, the signing algorithm of SMB 3.x.
func aesCMAC(key, msg []byte) (mac [16]byte) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return mac
	}
	var k1, k2 [16]byte
	blk.Encrypt(k1[:], k1[:])
	cmacDouble(&k1)
	k2 = k1
	cmacDouble(&k2)

	// All blocks but the last go through plain CBC with a zero IV, which
	// the standard library runs much faster than block-at-a-time calls.
	if n := (len(msg) - 1) / 16 * 16; n > 0 {
		cbc := cipher.NewCBCEncrypter(blk, mac[:])
		var scratch [4096]byte
		for rest := msg[:n]; len(rest) > 0; {
			m := min(len(rest), len(scratch))
			cbc.CryptBlocks(scratch[:m], rest[:m])
			copy(mac[:], scratch[m-16:m])
			rest = rest[m:]
		}
		msg = msg[n:]
	}
	var last [16]byte
	copy(last[:], msg)
	if len(msg) == 16 {
		subtle.XORBytes(last[:], last[:], k1[:])
	} else {
		last[len(msg)] = 0x80
		subtle.XORBytes(last[:], last[:], k2[:])
	}
	subtle.XORBytes(mac[:], mac[:], last[:])
	blk.Encrypt(mac[:], mac[:])
	return mac
}

// cmacDouble multiplies k by x in GF(2^128).
func cmacDouble(k *[16]byte) {
	carry := k[0] >> 7
	for i := 0; i < 15; i++ {
		k[i] = k[i]<<1 | k[i+1]>>7
	}
	k[15] <<= 1
	if carry != 0 {
		k[15] ^= 0x87
	}
}
