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
			[]byte("private"),
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.pDG5DGe90Z3718jJSfSRDVVbr__V3MLCx92x8r51t3E",
			nil,
		},
		{
			// exp
			map[string]interface{}{"exp": expired},
			HS256,
			[]byte("private"),
			"",
			ErrClaimExpired,
		},
		{
			// nbf
			map[string]interface{}{"nbf": notBefore},
			HS256,
			[]byte("private"),
			"",
			ErrClaimNotBefore,
		},
	}
	for i, tt := range tests {
		token := &Token{Claims: tt.claims}
		jwt, err := token.Sign(tt.signer, tt.key)
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
