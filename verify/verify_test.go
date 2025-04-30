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
        H1: generateMockH1(3), // Generate 3 mock h1 generators
    }

    // Mock signing key
    signingKey := models.SigningKey{
        X: generateMockScalar(12345),
    }

    // Mock verification key
    verificationKey := models.VerificationKey{
        X2: new(e.G2),
    }
    verificationKey.X2.ScalarMult(signingKey.X, publicParams.G2)

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Generate a valid signature
    signature, err := generateValidSignature(publicParams, signingKey, messages)
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
        H1: generateMockH1(3), // Generate 3 mock h1 generators
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
        E: generateMockScalar(99999),
    }

    // Call the Verify function
    isValid, err := Verify(publicParams, verificationKey, messages, signature)

    // Assert no error occurred
    assert.NoError(t, err, "Verify should not return an error")

    // Assert the signature is invalid
    assert.False(t, isValid, "Verify should return false for an invalid signature")
}

// Helper function to generate a valid signature
func generateValidSignature(publicParams models.PublicParameters, signingKey models.SigningKey, messages []string) (models.Signature, error) {
    // Compute commitment C
    C, err := utils.ComputeCommitment(messages, publicParams.H1, publicParams.G1)
    if err != nil {
        return models.Signature{}, err
    }

    // Generate random scalar e
    eScalar, err := utils.RandomScalar()
    if err != nil {
        return models.Signature{}, err
    }

    // Compute A = C^{1 / (x + e)}
    x_plus_e := new(e.Scalar)
    x_plus_e.Add(signingKey.X, &eScalar)
    x_plus_e.Inv(x_plus_e)

    A := new(e.G1)
    A.ScalarMult(x_plus_e, C)

    // Return the signature
    return models.Signature{
        A: A,
        E: &eScalar,
    }, nil
}

// Helper function to generate mock h1 generators
func generateMockH1(length int) []e.G1 {
    h1 := make([]e.G1, length)
    for i := 0; i < length; i++ {
        h1[i] = *e.G1Generator()
    }
    return h1
}

// Helper function to generate a mock scalar
func generateMockScalar(value uint64) *e.Scalar {
    scalar := new(e.Scalar)
    scalar.SetUint64(value)
    return scalar
}