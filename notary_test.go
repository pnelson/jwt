package notary

import (
	"reflect"
	"testing"
	"time"
)

var (
	expired   = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	notBefore = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
)

func TestNew(t *testing.T) {
	token := New("HS256")
	if token == nil {
		t.Fatal("expected a *Token")
	}

	if typ, ok := token.Header["typ"]; ok {
		if typ.(string) != "JWT" {
			t.Error("token header typ should be 'JWT'")
		}
	} else {
		t.Error("token header should have 'typ' field")
	}

	if alg, ok := token.Header["alg"]; ok {
		if alg.(string) != "HS256" {
			t.Error("token header alg should be 'HS256'")
		}
	} else {
		t.Error("token header should have 'alg' field")
	}
}

func TestToken(t *testing.T) {
	var tests = []struct {
		// in
		claims map[string]interface{}
		signer string
		key    []byte

		// out
		message string
		err     error
	}{
		{
			// simple
			map[string]interface{}{"foo": "bar"},
			"HS256",
			[]byte("private"),
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.pDG5DGe90Z3718jJSfSRDVVbr__V3MLCx92x8r51t3E",
			nil,
		},
		{
			// exp
			map[string]interface{}{"exp": expired},
			"HS256",
			[]byte("private"),
			"",
			ErrClaimExpired,
		},
		{
			// nbf
			map[string]interface{}{"nbf": notBefore},
			"HS256",
			[]byte("private"),
			"",
			ErrClaimNotBefore,
		},
	}

	for i, tt := range tests {
		token := New(tt.signer)
		token.Claims = tt.claims

		message, err := token.Sign(tt.key)
		if err != nil {
			t.Errorf("%d. Sign err\nhave %v\nwant %v", i, err, nil)
			continue
		}

		if tt.err == nil && message != tt.message {
			t.Errorf("%d. Sign message\nhave %v\nwant %v", i, message, tt.message)
			continue
		}

		parsed, err := ParseWithKey(message, tt.key)
		if err != tt.err {
			t.Errorf("%d. Parse err\nhave %v\nwant %v", i, err, tt.err)
			continue
		}

		if tt.err == nil && !reflect.DeepEqual(parsed.Claims, tt.claims) {
			t.Errorf("%d. Parse claims\nhave %v\nwant %v", i, parsed.Claims, tt.claims)
		}
	}
}
