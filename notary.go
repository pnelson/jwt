// Package notary implements tamper resistant message signing
// and verification using JSON Web Tokens.
package notary

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// Token represents a JWT token.
type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

var sep = []byte(".")

var (
	ErrMalformed      = errors.New("notary: incorrect token string format")
	ErrHeaderTyp      = errors.New("notary: header does not contain valid typ")
	ErrHeaderAlg      = errors.New("notary: header does not contain valid alg")
	ErrSignerAlg      = errors.New("notary: alg not registered with signer")
	ErrClaimExpired   = errors.New("notary: current time must be before exp")
	ErrClaimNotBefore = errors.New("notary: current time must be after nbf")
)

// New creates a new Token configured with the provided Signer by name.
func New(alg string) *Token {
	return &Token{
		Claims: make(map[string]interface{}),
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": alg,
		},
	}
}

// Token returns the signed token by serializing the provided header and claims
// to JSON and calculating the signature with the configured Signer.
func (t *Token) Sign(key []byte) (string, error) {
	// Encode the header.
	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	// Encode the claims.
	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	// Build the signing string.
	base := new(bytes.Buffer)
	base.Write(encode(h))
	base.WriteByte('.')
	base.Write(encode(c))

	// Determine the algorithm to use.
	alg, ok := t.Header["alg"].(string)
	if !ok {
		return "", ErrHeaderAlg
	}

	// Find the registered Signer for the token alg header.
	signer, ok := signers[alg]
	if !ok {
		return "", ErrSignerAlg
	}

	// Calculate the signature.
	signature, err := signer.Sign(base.Bytes(), key)
	if err != nil {
		return "", err
	}

	// Complete the token.
	base.WriteByte('.')
	base.Write(encode(signature))

	return base.String(), nil
}

// Parse validates the provided message.
func Parse(message string, callback func(t *Token) ([]byte, error)) (*Token, error) {
	token := &Token{}

	// Split the message into header, claims, and signature parts.
	parts := bytes.Split([]byte(message), sep)
	if len(parts) != 3 {
		return nil, ErrMalformed
	}

	// Decode the header.
	h, err := decode(parts[0])
	if err != nil {
		return nil, err
	}

	// Parse the header.
	err = json.Unmarshal(h, &token.Header)
	if err != nil {
		return nil, err
	}

	// Validate the header.
	typ, ok := token.Header["typ"].(string)
	if !ok || typ != "JWT" {
		return nil, ErrHeaderTyp
	}

	// Determine the algorithm to use.
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return nil, ErrHeaderAlg
	}

	// Find the registered Signer for the token alg header.
	signer, ok := signers[alg]
	if !ok {
		return nil, ErrSignerAlg
	}

	// Callback to retrieve the key.
	key, err := callback(token)
	if err != nil {
		return nil, err
	}

	// Prepare to verify the signature.
	base := bytes.Join(parts[0:2], sep)
	signature, err := decode(parts[2])
	if err != nil {
		return nil, err
	}

	// Verify the signature.
	err = signer.Verify(base, signature, key)
	if err != nil {
		return nil, err
	}

	// Decode the claims.
	c, err := decode(parts[1])
	if err != nil {
		return nil, err
	}

	// Parse the claims.
	err = json.Unmarshal(c, &token.Claims)
	if err != nil {
		return nil, err
	}

	// Verify the claims.
	now := time.Now().Unix()
	if exp, ok := token.Claims["exp"].(float64); ok {
		if now > int64(exp) {
			return nil, ErrClaimExpired
		}
	}
	if nbf, ok := token.Claims["nbf"].(float64); ok {
		if now < int64(nbf) {
			return nil, ErrClaimNotBefore
		}
	}

	return token, nil
}

// ParseWithKey validates the provided message using the provided key.
// This is a shortcut for Parse in cases where the token doesn't need
// to be parsed to figure out the full key.
func ParseWithKey(message string, key []byte) (*Token, error) {
	return Parse(message, func(t *Token) ([]byte, error) {
		return key, nil
	})
}
