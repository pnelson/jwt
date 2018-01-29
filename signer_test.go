package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	_ "crypto/sha256"
)

func TestHMACSigner(t *testing.T) {
	b := []byte("foo")
	key := []byte("secret")
	sig, err := HS256.Sign(b, key)
	if err != nil {
		t.Fatal(err)
	}
	err = HS256.Verify(b, sig, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	err = HS256.Verify(b, sig, key)
	if err != ErrInvalidSignature {
		t.Fatal("should be invalid")
	}
}

func TestRSASigner(t *testing.T) {
	b := []byte("foo")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := encodeRSA(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := RS256.Sign(b, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = RS256.Verify(b, sig, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	err = RS256.Verify(b, sig, publicKey)
	if err != ErrInvalidSignature {
		t.Fatal("should be invalid")
	}
}

func TestECDSASigner(t *testing.T) {
	b := []byte("foo")
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := encodeECDSA(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ES256.Sign(b, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = ES256.Verify(b, sig, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	err = ES256.Verify(b, sig, publicKey)
	if err != ErrInvalidSignature {
		t.Fatal("should be invalid")
	}
}

// encodeRSA encodes a RSA private key to PEM-formatted
// public and private keys.
func encodeRSA(priv *rsa.PrivateKey) ([]byte, []byte, error) {
	publicKey, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privateKey := encodeRSAPrivateKey(priv)
	return publicKey, privateKey, nil
}

// encodeECDSA encodes a ECDSA private key to PEM-formatted
// public and private keys.
func encodeECDSA(priv *ecdsa.PrivateKey) ([]byte, []byte, error) {
	publicKey, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := encodeECDSAPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// encodePublicKey encodes a RSA or ECDSA public key to PEM format.
func encodePublicKey(pub interface{}) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return pem.EncodeToMemory(block), nil
}

// encodeRSAPrivateKey encodes a RSA private key to PEM format.
func encodeRSAPrivateKey(priv *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(priv)
	return encodePrivateKey("RSA", der)
}

// encodeECDSAPrivateKey encodes a ECDSA private key to PEM format.
func encodeECDSAPrivateKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return encodePrivateKey("EC", der), nil
}

// encodePrivateKey encodes a private key to PEM format.
func encodePrivateKey(kind string, der []byte) []byte {
	block := &pem.Block{Type: kind + " PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(block)
}
