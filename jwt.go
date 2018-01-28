// Package jwt implements tamper resistant message signing
// and verification using JSON Web Tokens.
package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var sep = "."

// Token errors.
var (
	ErrMalformed      = errors.New("jwt: incorrect token string format")
	ErrHeaderTyp      = errors.New("jwt: header does not contain valid typ")
	ErrHeaderAlg      = errors.New("jwt: header does not contain valid alg")
	ErrClaimExpired   = errors.New("jwt: current time must be before exp")
	ErrClaimNotBefore = errors.New("jwt: current time must be after nbf")
)

// Token represents a JWT token.
type Token struct {
	Header map[string]interface{}
	Claims map[string]interface{}
}

// Sign returns the signed token by serializing the token
// header and claims to JSON and using s to calculate the signature.
func (t *Token) Sign(s Signer, key []byte) (string, error) {
	if t.Header == nil {
		t.Header = make(map[string]interface{})
	}
	t.Header["typ"] = "JWT"
	t.Header["alg"] = s.String()
	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	if t.Claims == nil {
		t.Claims = make(map[string]interface{})
	}
	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}
	jwt := encode(h) + sep + encode(c)
	sig, err := s.Sign([]byte(jwt), key)
	if err != nil {
		return "", err
	}
	jwt += sep + encode(sig)
	return jwt, nil
}

// Parse validates jwt with key.
// Signer s is explicitly passed as attackers could otherwise control the
// choice of algorithm with the alg header that has not yet been verified.
func Parse(s Signer, jwt string, key []byte) (*Token, error) {
	return ParseWithKeyFunc(s, jwt, func(t *Token) ([]byte, error) {
		return key, nil
	})
}

// ParseWithKeyFunc validates the provided jwt using the provided keyFn.
// This can be used in cases where the token header needs to be parsed
// to determine the full key.
func ParseWithKeyFunc(s Signer, jwt string, keyFn func(*Token) ([]byte, error)) (*Token, error) {
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
	if !ok || alg != s.String() {
		return nil, ErrHeaderAlg
	}
	key, err := keyFn(t)
	if err != nil {
		return nil, err
	}
	b := strings.Join(parts[:2], sep)
	sig, err := decode(parts[2])
	if err != nil {
		return nil, err
	}
	err = s.Verify([]byte(b), sig, key)
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
