// Package notary implements tamper resistant message signing
// and verification using JSON Web Tokens.
package notary

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Token represents a JWT token.
type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

var sep = "."

// Token errors.
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

// Sign returns the signed token by serializing the provided header and claims
// to JSON and calculating the signature with the configured Signer.
func (t *Token) Sign(key []byte) (string, error) {
	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}
	token := encode(h) + sep + encode(c)
	alg, ok := t.Header["alg"].(string)
	if !ok {
		return "", ErrHeaderAlg
	}
	signer, ok := signers[alg]
	if !ok {
		return "", ErrSignerAlg
	}
	signature, err := signer.Sign([]byte(token), key)
	if err != nil {
		return "", err
	}
	token += sep + encode(signature)
	return token, nil
}

// Parse validates the provided message.
func Parse(jwt string, callback func(*Token) ([]byte, error)) (*Token, error) {
	t := &Token{}
	parts := strings.Split(jwt, sep)
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	h, err := decode(parts[0])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(h, &t.Header)
	if err != nil {
		return nil, err
	}
	typ, ok := t.Header["typ"].(string)
	if !ok || typ != "JWT" {
		return nil, ErrHeaderTyp
	}
	alg, ok := t.Header["alg"].(string)
	if !ok {
		return nil, ErrHeaderAlg
	}
	signer, ok := signers[alg]
	if !ok {
		return nil, ErrSignerAlg
	}
	key, err := callback(t)
	if err != nil {
		return nil, err
	}
	base := strings.Join(parts[:2], sep)
	signature, err := decode(parts[2])
	if err != nil {
		return nil, err
	}
	err = signer.Verify([]byte(base), signature, key)
	if err != nil {
		return nil, err
	}
	c, err := decode(parts[1])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(c, &t.Claims)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if exp, ok := t.Claims["exp"].(float64); ok {
		if now > int64(exp) {
			return nil, ErrClaimExpired
		}
	}
	if nbf, ok := t.Claims["nbf"].(float64); ok {
		if now < int64(nbf) {
			return nil, ErrClaimNotBefore
		}
	}
	return t, nil
}

// ParseWithKey validates the provided jwt using the provided key.
// This is a shortcut for Parse in cases where the token doesn't need
// to be parsed to figure out the full key.
func ParseWithKey(jwt string, key []byte) (*Token, error) {
	return Parse(jwt, func(*Token) ([]byte, error) {
		return key, nil
	})
}
