package keygen

import (
    "testing"

    "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// TestKeyGenLength tests that KeyGen generates the correct number of h1 generators.
func TestKeyGenLength(t *testing.T) {
    // Define the length of the message vector
    messageLength := 5

    // Call KeyGen
    result, err := KeyGen(messageLength)

    // Assert no error occurred
    assert.NoError(t, err, "KeyGen should not return an error")

    // Assert the correct number of h1 generators is generated
    assert.Equal(t, messageLength, len(result.PublicParameters.H1), "KeyGen should generate the correct number of h1 generators")
}

// TestKeyGenRandomness tests that KeyGen generates random and independent keys.
func TestKeyGenRandomness(t *testing.T) {
    // Call KeyGen twice with the same message length
    messageLength := 5
    result1, err1 := KeyGen(messageLength)
    result2, err2 := KeyGen(messageLength)

    // Assert no errors occurred
    assert.NoError(t, err1, "First KeyGen call should not return an error")
    assert.NoError(t, err2, "Second KeyGen call should not return an error")

    // Assert that the signing keys are different
    assert.NotEqual(t, result1.SigningKey.X, result2.SigningKey.X, "Signing keys should be random and independent")

    // Assert that the verification keys are different
    assert.NotEqual(t, result1.VerificationKey.X2, result2.VerificationKey.X2, "Verification keys should be random and independent")

    // Assert that the h1 generators are different
    assert.NotEqual(t, result1.PublicParameters.H1, result2.PublicParameters.H1, "h1 generators should be random and independent")
}

// TestKeyGenVerificationKey tests that the verification key is computed correctly.
func TestKeyGenVerificationKey(t *testing.T) {
    // Define the length of the message vector
    messageLength := 5

    // Call KeyGen
    result, err := KeyGen(messageLength)

    // Assert no error occurred
    assert.NoError(t, err, "KeyGen should not return an error")

    // Compute the expected verification key: X2 = g2^x
    expectedX2 := new(bls12381.G2)
    expectedX2.ScalarMult(result.SigningKey.X, result.PublicParameters.G2)

    // Assert the verification key matches the expected value
    assert.Equal(t, expectedX2, result.VerificationKey.X2, "Verification key should be computed as g2^x")
}

// TestKeyGenH1Generators tests that the h1 generators are valid elements in G1.
func TestKeyGenH1Generators(t *testing.T) {
    // Define the length of the message vector
    messageLength := 5

    // Call KeyGen
    result, err := KeyGen(messageLength)

    // Assert no error occurred
    assert.NoError(t, err, "KeyGen should not return an error")

    // Assert each h1 generator is a valid element in G1
    for i, h1 := range result.PublicParameters.H1 {
        assert.False(t, h1.IsIdentity(), "h1[%d] should not be the identity element", i)
    }
}