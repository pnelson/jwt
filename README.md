# jwt

Package jwt implements tamper resistant message signing and verification
using JSON Web Tokens.

Besides validating the signature, jwt will also check for the existence
of `exp` and `nbf` claims, and validate as necessary.

The header and claims maps are of type `map[string]interface{}`.
That said, be mindful of the way `encoding/json` unmarshals into interface{}
values. Notably, all JSON numbers are stored as `float64`.


## Usage

### Sign

```go
t := jwt.New(jwt.HS256)
t.Claims["exp"] = time.Now().Add(24 * time.Hour).Unix()
token, err := t.Sign([]byte("secret"))
```

### Verify with Known Key

```go
t, err := jwt.Parse(jwt.HS256, token, []byte("secret"))
```

### Verify with Key Func Callback

```go
t, err := jwt.ParseWithKeyFunc(jwt.HS256, token, func(t *jwt.Token) ([]byte, error) {
  // optionally find the key using header, say t.Header["kid"]
  return []byte("secret"), nil
})
```
