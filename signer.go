package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Signer implementations.
var (
	HS256 = hmacSigner{name: "HS256", hash: sha256.New}
	HS384 = hmacSigner{name: "HS384", hash: sha512.New384}
	HS512 = hmacSigner{name: "HS512", hash: sha512.New}
)

// Signer errors.
var (
	ErrInvalidSignature = errors.New("notary: invalid signature")
)

// Signer is the interface that signs and verifies data.
type Signer interface {
	// String is the algorithm name.
	fmt.Stringer

	// Sign returns the signature of the data.
	Sign(b, key []byte) ([]byte, error)

	// Verify returns an error if the signature is invalid.
	Verify(b, signature, key []byte) error
}

// hmacSigner is a signer for the hash.Hash interface.
type hmacSigner struct {
	name string
	hash func() hash.Hash
}

// Sign returns the signature of the data.
func (s hmacSigner) Sign(b, key []byte) ([]byte, error) {
	return s.digest(b, key)
}

// Verify returns an error if the signature is invalid.
func (s hmacSigner) Verify(b, signature, key []byte) error {
	digest, err := s.digest(b, key)
	if err != nil {
		return err
	}
	if !compare(signature, digest) {
		return ErrInvalidSignature
	}
	return nil
}

// String implements the fmt.Stringer interface.
func (s hmacSigner) String() string {
	return s.name
}

func (s hmacSigner) digest(b, key []byte) ([]byte, error) {
	h := hmac.New(s.hash, key)
	_, err := h.Write(b)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
