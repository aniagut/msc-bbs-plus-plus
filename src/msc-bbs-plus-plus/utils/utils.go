package utils

import (
	"crypto/rand"
	"errors"
	"math/big"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// RandomG1Element generates a random element in the elliptic curve group G1.
func RandomG1Element() (e.G1, error) {
    var h e.G1
    randomBytes := make([]byte, 48)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return e.G1{}, errors.New("failed to generate random input for hashing to G1")
    }

    // Hash the random bytes to the curve using a domain separation tag
    h.Hash(randomBytes, []byte("domain-separation-tag"))
    return h, nil
}

// GenerateLRandomG1Elements generates l random elements in G1.
func GenerateLRandomG1Elements(l int) ([]e.G1, error) {
	elements := make([]e.G1, l)
	for i := 0; i < l; i++ {
		element, err := RandomG1Element()
		if err != nil {
			return nil, err
		}
		elements[i] = element
	}
	return elements, nil
}

// RandomScalar generates a random scalar in Z_p* (the field of scalars modulo the curve order).
func RandomScalar() (e.Scalar, error) {
    order := OrderAsBigInt()
    bigIntScalar, err := rand.Int(rand.Reader, order)
    if err != nil {
        return e.Scalar{}, errors.New("failed to generate random scalar")
    }

    if bigIntScalar.Sign() == 0 { // Ensure it's nonzero
        return RandomScalar()
    }

    // Convert to a scalar
    var scalar e.Scalar
    scalar.SetBytes(bigIntScalar.Bytes())
    return scalar, nil
}

// OrderAsBigInt returns the order of the elliptic curve as a big.Int.
func OrderAsBigInt() *big.Int {
    return new(big.Int).SetBytes(e.Order())
}

// Serialize string to bytes
func SerializeString(s string) []byte {
	return []byte(s)
}

// ComputeCommitment computes the commitment C for a given message M.
func ComputeCommitment(M []string, h1 []e.G1, g1 *e.G1) (*e.G1, error) {
	// Ensure the message vector length matches the length of h1
    if len(M) != len(h1) {
        return nil, errors.New("message vector length does not match h1 length")
    }

	// Initialize the commitment C with g1
	C := new(e.G1)
	*C = *g1

	for i, message := range M {
		// Convert message to a scalar
		mScalar := new(e.Scalar)
		mScalar.SetBytes(SerializeString(message))

		// Compute h1[i]^m[i]
        h1Exp := new(e.G1)
        h1Exp.ScalarMult(mScalar, &h1[i])

        // Multiply the result into the commitment
        C.Add(C, h1Exp)
	}

	return C, nil
}