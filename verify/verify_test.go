package verify

import (
    "testing"

    "github.com/aniagut/msc-bbs-plus-plus/models"
    "github.com/aniagut/msc-bbs-plus-plus/utils"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// TestVerifyValidSignature tests that a valid signature is correctly verified.
func TestVerifyValidSignature(t *testing.T) {
    // Mock public parameters
    publicParams := models.PublicParameters{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H1: GenerateMockH1(3), // Generate 3 mock h1 generators
    }

    // Mock signing key
    signingKey := models.SigningKey{
        X: GenerateMockScalar(12345),
    }

    // Mock verification key
    verificationKey := models.VerificationKey{
        X2: new(e.G2),
    }
    verificationKey.X2.ScalarMult(signingKey.X, publicParams.G2)

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Generate a valid signature
    signature, err := GenerateValidSignature(publicParams, signingKey, messages)
    assert.NoError(t, err, "Signature generation should not return an error")

    // Call the Verify function
    isValid, err := Verify(publicParams, verificationKey, messages, signature)

    // Assert no error occurred
    assert.NoError(t, err, "Verify should not return an error")

    // Assert the signature is valid
    assert.True(t, isValid, "Verify should return true for a valid signature")
}

// TestVerifyInvalidSignature tests that an invalid signature is correctly rejected.
func TestVerifyInvalidSignature(t *testing.T) {
    // Mock public parameters
    publicParams := models.PublicParameters{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H1: GenerateMockH1(3), // Generate 3 mock h1 generators
    }

    // Mock verification key
    verificationKey := models.VerificationKey{
        X2: e.G2Generator(),
    }

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Mock an invalid signature
    signature := models.Signature{
        A: e.G1Generator(),
        E: GenerateMockScalar(99999),
    }

    // Call the Verify function
    isValid, err := Verify(publicParams, verificationKey, messages, signature)

    // Assert no error occurred
    assert.NoError(t, err, "Verify should not return an error")

    // Assert the signature is invalid
    assert.False(t, isValid, "Verify should return false for an invalid signature")
}

// GenerateValidSignature generates a valid signature for testing.
func GenerateValidSignature(publicParams models.PublicParameters, signingKey models.SigningKey, messages []string) (models.Signature, error) {
    // Compute commitment c
    c, err := utils.ComputeCommitment(messages, publicParams.H1, publicParams.G1)
    if err != nil {
        return models.Signature{}, err
    }

    // Generate random scalar e
    eScalar, err := utils.RandomScalar()
    if err != nil {
        return models.Signature{}, err
    }

    // Compute a = c^{1 / (x + e)}
    xPlusE := new(e.Scalar)
    xPlusE.Add(signingKey.X, &eScalar)
    xPlusE.Inv(xPlusE)

    a := new(e.G1)
    a.ScalarMult(xPlusE, c)

    // Return the signature
    return models.Signature{
        A: a,
        E: &eScalar,
    }, nil
}

// GenerateMockH1 generates a slice of mock G1 elements for testing purposes.
func GenerateMockH1(length int) []e.G1 {
    h1 := make([]e.G1, length)
    for i := 0; i < length; i++ {
        h1[i] = *e.G1Generator()
    }
    return h1
}

// GenerateMockScalar generates a mock scalar for testing purposes.
func GenerateMockScalar(value uint64) *e.Scalar {
    scalar := new(e.Scalar)
    scalar.SetUint64(value)
    return scalar
}