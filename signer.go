package notary

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

var signers = make(map[string]Signer)

var ErrInvalidSignature = errors.New("notary: invalid signature")

// Signer is the interface that signs and verifies data.
type Signer interface {
	// Sign returns the signature of the data.
	Sign(b, key []byte) ([]byte, error)

	// Verify returns an error if the signature is invalid.
	Verify(b, signature, key []byte) error
}

// HMACSigner is a signer for the Hash interface.
type HMACSigner func() hash.Hash

// Register makes a signer available by the provided name.
// Panics if called twice with the same name or the signer is nil.
func Register(alg string, signer Signer) {
	if signer == nil {
		panic("notary: Register signer is nil")
	}

	if _, ok := signers[alg]; ok {
		panic("notary: Register called twice for signer " + alg)
	}

	signers[alg] = signer
}

// Sign returns the signature of the data.
func (s HMACSigner) Sign(b, key []byte) ([]byte, error) {
	return s.digest(b, key)
}

// Verify returns an error if the signature is invalid.
func (s HMACSigner) Verify(b, signature, key []byte) error {
	digest, err := s.digest(b, key)
	if err != nil {
		return err
	}

	if !compare(signature, digest) {
		return ErrInvalidSignature
	}

	return nil
}

func (s HMACSigner) digest(b, key []byte) ([]byte, error) {
	h := hmac.New(s, key)
	_, err := h.Write(b)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func init() {
	Register("HS256", HMACSigner(sha256.New))
	Register("HS384", HMACSigner(sha512.New384))
	Register("HS512", HMACSigner(sha512.New))
}
