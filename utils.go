package notary

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
)

// compare returns true if the two byte slices are equal while mitigating from
// timing attacks by using an algorithm that doesn't expose timing information.
func compare(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}

	return subtle.ConstantTimeCompare(x, y) == 1
}

// decode returns the padding-free URL-safe base64 decoded byte array.
//
// See RFC 4648 Section 3.2.
func decode(b []byte) ([]byte, error) {
	pad := bytes.Repeat([]byte("="), (-len(b)%4+4)%4)
	padded := make([]byte, len(b)+len(pad))
	copy(padded, b)
	copy(padded[len(b):], pad)
	rv := make([]byte, base64.URLEncoding.DecodedLen(len(padded)))
	n, err := base64.URLEncoding.Decode(rv, padded)
	if err != nil {
		return nil, err
	}

	return rv[:n], nil
}

// encode returns a base64 padding-free URL-safe encoded byte array.
//
// See RFC 4648 Section 3.2.
func encode(b []byte) []byte {
	rv := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(rv, b)
	return bytes.TrimRight(rv, "=")
}
