## Tito: TOTP Generation and Validation (Go)

### Features
- Generate and validate TOTP codes per RFC 6238
- Base32 secrets with no padding; robust normalization (spaces, dashes, case, padding)
- Algorithms: SHA1 (default), SHA256, SHA512
- Helpers to generate secrets from a seed and randomly

### Install

- Library:
```
go get github.com/bi0dread/tito
```
- CLI (from this repo):
```
go install github.com/bi0dread/tito/cmd/tito@latest
```

### Usage

```go
import (
    "fmt"
    tito "github.com/bi0dread/tito"
)

func example() {
    // Create a configured Tito instance (6 digits, 30s period)
    t := tito.New(tito.Options{Digits: 6, Period: 30})

    // Generate a random secret (20 bytes → 32 chars Base32, no padding)
    secret, _ := tito.GenerateRandomSecret(20)

    // TOTP codes
    code, _ := t.GenerateTOTP(secret)
    fmt.Println(code)

    // Validate within ±1 step (±30s)
    res, _ := t.ValidateTOTP(secret, code, 1)
    fmt.Println(res.OK, res.Skew)

    // SHA256/SHA512 (configure on Tito)
    t256 := tito.New(tito.Options{Digits: 8, Period: 30, Algorithm: tito.HashSHA256})
    code256, _ := t256.GenerateTOTP(secret)

    t512 := tito.New(tito.Options{Digits: 8, Period: 30, Algorithm: tito.HashSHA512})
    code512, _ := t512.GenerateTOTP(secret)
    fmt.Println(code256, code512)

    // Secrets from seed (method)
    seeded := t.GenerateSecretFromSeed("seed value")
    uri, _ := t.BuildTOTPURI("Alice", "Acme", seeded)
    _ = uri // can be encoded to QR using QRPNGFromURI
}
```

### CLI
After installing the CLI:
```
# Generate a TOTP
TITO_SECRET=$(tito secret) # if you add a helper; else provide one

tito -mode totp -secret "$TITO_SECRET" -digits 6 -period 30

# Build a provisioning URI and PNG QR (writes PNG bytes to stdout)
tito -mode uri -secret "$TITO_SECRET" -label "Alice" -issuer "Acme"
tito -mode qr  -secret "$TITO_SECRET" -label "Alice" -issuer "Acme" > totp.png
```

### Notes
- `digits` supported range: 6–8
- Default timestep is 30s; inputs are normalized (case-insensitive, spaces/dashes/padding ignored)

### Testing

```
go test ./...
```


