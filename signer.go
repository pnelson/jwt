package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Signer implementations.
var (
	// HMAC
	HS256 = NewHMACSigner("HS256", crypto.SHA256)
	HS384 = NewHMACSigner("HS384", crypto.SHA384)
	HS512 = NewHMACSigner("HS512", crypto.SHA512)

	// RSA
	RS256 = NewRSASigner("RS256", crypto.SHA256)
	RS384 = NewRSASigner("RS384", crypto.SHA384)
	RS512 = NewRSASigner("RS512", crypto.SHA512)

	// ECDSA
	ES256 = NewECDSASigner("ES256", crypto.SHA256)
	ES384 = NewECDSASigner("ES384", crypto.SHA384)
	ES512 = NewECDSASigner("ES256", crypto.SHA512)
)

// Signer errors.
var (
	ErrHashUnavailable  = errors.New("jwt: hash unavailable")
	ErrInvalidSignature = errors.New("jwt: invalid signature")
)

// Signer is the interface that signs and verifies data.
type Signer interface {
	// String is the algorithm name.
	fmt.Stringer

	// Sign returns the signature of the data.
	Sign(b, key []byte) ([]byte, error)

	// Verify returns an error if the signature is invalid.
	Verify(b, sig, key []byte) error
}

// HMACSigner is a signer for HMAC over the crypto.Hash interface.
type HMACSigner struct {
	name string
	hash crypto.Hash
}

// NewHMACSigner returns a new HMACSigner.
func NewHMACSigner(name string, hash crypto.Hash) HMACSigner {
	return HMACSigner{name: name, hash: hash}
}

// Sign returns the signature of the data.
func (s HMACSigner) Sign(b, key []byte) ([]byte, error) {
	return s.digest(b, key)
}

// Verify returns an error if the signature is invalid.
func (s HMACSigner) Verify(b, sig, key []byte) error {
	digest, err := s.digest(b, key)
	if err != nil {
		return err
	}
	if !compare(sig, digest) {
		return ErrInvalidSignature
	}
	return nil
}

// String implements the fmt.Stringer interface.
func (s HMACSigner) String() string {
	return s.name
}

func (s HMACSigner) digest(b, key []byte) ([]byte, error) {
	if !s.hash.Available() {
		return nil, ErrHashUnavailable
	}
	h := hmac.New(s.hash.New, key)
	_, err := h.Write(b)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// RSASigner is a signer for RSA signatures.
type RSASigner struct {
	name string
	hash crypto.Hash
}

// NewRSASigner returns a new RSASigner.
func NewRSASigner(name string, hash crypto.Hash) RSASigner {
	return RSASigner{name: name, hash: hash}
}

// Sign returns the signature of the data.
// The key is expected to be a PEM-encoded RSA private key.
func (e RSASigner) Sign(b, key []byte) ([]byte, error) {
	priv, err := e.decodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	hash, err := hash(e.hash, b)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, e.hash, hash)
}

// decodePrivateKey decodes a PEM-encoded RSA private key.
func (e RSASigner) decodePrivateKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("jwt: invalid rsa private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// Verify returns an error if the signature is invalid.
// The key is expected to be a PEM-encoded RSA public key.
func (e RSASigner) Verify(b, sig, key []byte) error {
	pub, err := e.decodePublicKey(key)
	if err != nil {
		return err
	}
	hash, err := hash(e.hash, b)
	if err != nil {
		return err
	}
	err = rsa.VerifyPKCS1v15(pub, e.hash, hash, sig)
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// decodePublicKey decodes a PEM-encoded RSA public key.
func (e RSASigner) decodePublicKey(b []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("jwt: invalid rsa public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwt: invalid rsa public key")
	}
	return key, nil
}

// String implements the fmt.Stringer interface.
func (e RSASigner) String() string {
	return e.name
}

// ECDSASigner is a signer for ECDSA signatures.
type ECDSASigner struct {
	name      string
	hash      crypto.Hash
	keySize   int
	curveBits int
}

// NewECDSASigner returns a new ECDSASigner.
func NewECDSASigner(name string, hash crypto.Hash) ECDSASigner {
	return ECDSASigner{name: name, hash: hash}
}

// Sign returns the signature of the data.
// The key is expected to be a PEM-encoded ECDSA private key.
func (e ECDSASigner) Sign(b, key []byte) ([]byte, error) {
	priv, err := e.decodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	hash, err := hash(e.hash, b)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}
	n := e.getKeySize(priv.Curve)
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, 2*n)
	copy(sig[n-len(rb):], rb)
	copy(sig[n*2-len(sb):], sb)
	return sig, nil
}

// decodePrivateKey decodes a PEM-encoded ECDSA private key.
func (e ECDSASigner) decodePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("jwt: invalid ecdsa private key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// Verify returns an error if the signature is invalid.
// The key is expected to be a PEM-encoded ECDSA public key.
func (e ECDSASigner) Verify(b, sig, key []byte) error {
	pub, err := e.decodePublicKey(key)
	if err != nil {
		return err
	}
	keySize := e.getKeySize(pub.Curve)
	if len(sig) != 2*keySize {
		return ErrInvalidSignature
	}
	hash, err := hash(e.hash, b)
	if err != nil {
		return err
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	if !ecdsa.Verify(pub, hash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// decodePublicKey decodes a PEM-encoded ECDSA public key.
func (e ECDSASigner) decodePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("jwt: invalid ecdsa public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("jwt: invalid ecdsa public key")
	}
	return key, nil
}

// String implements the fmt.Stringer interface.
func (e ECDSASigner) String() string {
	return e.name
}

// getKeySize returns the size of the r/s key with padding.
func (e ECDSASigner) getKeySize(curve elliptic.Curve) int {
	n := curve.Params().BitSize / 8
	if n%8 > 0 {
		n++
	}
	return n
}
