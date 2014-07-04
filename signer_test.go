package notary

import (
	"crypto/sha256"
	"testing"
)

func TestHMACSigner(t *testing.T) {
	var tests = []struct {
		// in
		in  []byte
		key []byte

		// out
		out []byte
	}{
		{
			[]byte("foo"),
			[]byte("private"),
			[]byte{
				135, 92, 179, 193, 139, 166, 183, 85, 151, 36,
				230, 7, 59, 208, 129, 100, 233, 13, 234, 7,
				109, 160, 36, 50, 237, 78, 214, 42, 156, 68,
				148, 219,
			},
		},
		{
			[]byte("bar"),
			[]byte("private"),
			[]byte{
				101, 200, 91, 13, 253, 20, 248, 101, 149, 63,
				222, 99, 56, 203, 231, 189, 220, 86, 41, 134,
				224, 230, 67, 224, 93, 147, 24, 255, 44, 162,
				206, 153,
			},
		},
		{
			[]byte("baz"),
			[]byte("private"),
			[]byte{
				205, 187, 221, 76, 226, 246, 189, 251, 240, 16,
				42, 224, 90, 12, 244, 162, 185, 122, 87, 72,
				56, 2, 51, 35, 135, 157, 116, 115, 164, 5,
				157, 156,
			},
		},
	}

	signer := HMACSigner(sha256.New)
	for i, tt := range tests {
		out, err := signer.Sign(tt.in, tt.key)
		if err != nil {
			t.Errorf("%d. Sign err\nhave %v\nwant %v", i, err, nil)
			continue
		}

		err = signer.Verify(tt.in, tt.out, tt.key)
		if err != nil {
			t.Errorf("%d. Verify\nhave %v %v\nwant %v", i, err, out, nil)
		}
	}
}
