# msc-bbs-plus-plus

A Go implementation of BBS++ signature schemes for privacy-preserving cryptographic protocols.

## Features

- **Key Generation**: Generate signing and verification keys for BBS++.
- **Signing**: Create signatures over message vectors.
- **Verification**: Verify BBS++ signatures.
- **Experimental Utilities**: Benchmark key generation and signing performance.

## Installation

```sh
go get github.com/aniagut/msc-bbs-plus-plus
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/aniagut/msc-bbs-plus-plus/keygen"
    "github.com/aniagut/msc-bbs-plus-plus/sign"
    "github.com/aniagut/msc-bbs-plus-plus/verify"
)

func main() {
    // Key generation
    l := 5
    result, err := keygen.KeyGen(l)
    if err != nil {
        panic(err)
    }

    // Signing
    messages := []string{"message1", "message2", "message3", "message4", "message5"}
    signature, err := sign.Sign(result.PublicParameters, result.SigningKey, messages)
    if err != nil {
        panic(err)
    }

    // Verification
    isValid, err := verify.Verify(result.PublicParameters, result.VerificationKey, messages, signature)
    if err != nil {
        panic(err)
    }
    fmt.Println("Signature valid?", isValid)
}
```

## Project Structure

- `keygen/` – Key generation logic
- `sign/` – Signature creation
- `verify/` – Signature verification
- `utils/` – Cryptographic utilities
- `experiments/` – Benchmarking and experiments

## Running Tests

```sh
go test ./...
```

## License

MIT License

---