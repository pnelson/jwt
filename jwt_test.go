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

func TestSignRSA(t *testing.T) {
	var (
		publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----
`)
		privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----
`)
	)
	token := New(RS256)
	token.Claims["foo"] = "bar"
	have, err := token.Sign(privateKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.G4NF4svnzzB18700LltE4hAwedbgW-rkdkzCOsN-etT3ZZfmre1mix_u4Q_LkhdjE6h880vzjSLo1b-JSk0v03fxXCrWSRhh7h_I0h43fW8AtnFs_v78CF1toGbqTLsW1EdPCMpxxnVRzcUtSXCRS_GtM08TAGhXOknY1FqcO4Y"
	if have != want {
		t.Fatalf("have %s\nwant %s", have, want)
	}
	parsed, err := Parse(RS256, have, publicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(parsed.Claims, token.Claims) {
		t.Fatalf("have %v\nwant %v", parsed.Claims, token.Claims)
	}
}

func TestSignNone(t *testing.T) {
	token := New(nil)
	_, err := token.Sign([]byte("secret"))
	if err != ErrSigner {
		t.Errorf("should return signer error")
	}
}
