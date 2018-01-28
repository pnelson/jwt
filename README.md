# jwt

Package jwt implements tamper resistant message signing and verification
using JSON Web Tokens.

Besides validating the signature, jwt will also check for the existence
of `exp` and `nbf` claims, and validate as necessary.

The header and claims maps are of type `map[string]interface{}`, unfortunately.
That said, be mindful of the way `encoding/json` unmarshals into interface{}
values. Notably, all JSON numbers are stored as `float64`.


## Usage

### Sign

```go
t := new(jwt.Token)
t.Claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
token, err := t.Sign(jwt.HS256, []byte("secret"))
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
