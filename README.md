# notary

Package notary implements tamper resistant message signing and verification
using JSON Web Tokens.

Besides validating the signature, notary will also check for the existence
of exp and nbf claims, and validate as necessary.

The header and claims maps are of type map[string]interface{}, unfortunately.
That said, be mindful of the way encoding/json unmarshals into interface{}
values. Notably, all JSON numbers are stored as float64.


## Usage

### Sign

```go
token := notary.New("HS256")
token.Claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
message, err := token.Sign([]byte("secret"))
```

### Verify with Known Key

```go
parsed, err := notary.ParseWithKey(message, []byte("secret"))
```

### Verify with Callback

```go
parsed, err := notary.Parse(message, func(t *notary.Token) ([]byte, error) {
  // optionally find the key using header/claims of parsed token t
  return []byte("secret"), nil
})
```
