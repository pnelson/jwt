package jwt

import (
	"crypto/subtle"
	"encoding/base64"
)

var b64 = base64.RawURLEncoding

// compare returns true if the two byte slices are equal while mitigating from
// timing attacks by using an algorithm that doesn't expose timing information.
func compare(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

// decode returns the padding-free URL-safe base64 decoded byte array.
//
// See RFC 4648 Section 3.2.
func decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

// encode returns a base64 padding-free URL-safe encoded string.
//
// See RFC 4648 Section 3.2.
func encode(b []byte) string {
	return b64.EncodeToString(b)
}
