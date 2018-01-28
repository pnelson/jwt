package jwt

import (
	"reflect"
	"testing"
	"time"
)

var (
	expired   = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	notBefore = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
)

func TestToken(t *testing.T) {
	var tests = []struct {
		// in
		claims map[string]interface{}
		signer Signer
		key    []byte
		// out
		jwt string
		err error
	}{
		{
			// simple
			map[string]interface{}{"foo": "bar"},
			HS256,
			[]byte("secret"),
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.dtxWM6MIcgoeMgH87tGvsNDY6cHWL6MGW4LeYvnm1JA",
			nil,
		},
		{
			// exp
			map[string]interface{}{"exp": expired},
			HS256,
			[]byte("secret"),
			"",
			ErrClaimExpired,
		},
		{
			// nbf
			map[string]interface{}{"nbf": notBefore},
			HS256,
			[]byte("secret"),
			"",
			ErrClaimNotBefore,
		},
	}
	for i, tt := range tests {
		token := New(tt.signer)
		token.Claims = tt.claims
		jwt, err := token.Sign(tt.key)
		if err != nil {
			t.Errorf("%d. Sign err\nhave %v\nwant %v", i, err, nil)
			continue
		}
		if tt.err == nil && jwt != tt.jwt {
			t.Errorf("%d. Sign jwt\nhave %v\nwant %v", i, jwt, tt.jwt)
			continue
		}
		parsed, err := Parse(tt.signer, jwt, tt.key)
		if err != tt.err {
			t.Errorf("%d. Parse err\nhave %v\nwant %v", i, err, tt.err)
			continue
		}
		if tt.err == nil && !reflect.DeepEqual(parsed.Claims, tt.claims) {
			t.Errorf("%d. Parse claims\nhave %v\nwant %v", i, parsed.Claims, tt.claims)
		}
	}
}

func TestSignNone(t *testing.T) {
	token := New(nil)
	_, err := token.Sign([]byte("secret"))
	if err != ErrSigner {
		t.Errorf("should return signer error")
	}
}
