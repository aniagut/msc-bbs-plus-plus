package sign

import (
    "testing"

    "github.com/aniagut/msc-bbs-plus-plus/models"
	"github.com/aniagut/msc-bbs-plus-plus/utils"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// TestSignBasic tests that the Sign function generates a valid signature.
func TestSignBasic(t *testing.T) {
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

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Call the Sign function
    signature, err := Sign(publicParams, signingKey, messages)

    // Assert no error occurred
    assert.NoError(t, err, "Sign should not return an error")

    // Assert the signature components are not nil
    assert.NotNil(t, signature.A, "Signature component A should not be nil")
    assert.NotNil(t, signature.E, "Signature component E should not be nil")
}

// TestSignRandomness tests that the Sign function generates different signatures for the same input.
func TestSignRandomness(t *testing.T) {
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

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Call the Sign function twice
    signature1, err1 := Sign(publicParams, signingKey, messages)
    signature2, err2 := Sign(publicParams, signingKey, messages)

    // Assert no errors occurred
    assert.NoError(t, err1, "First Sign call should not return an error")
    assert.NoError(t, err2, "Second Sign call should not return an error")

    // Assert the signatures are different
    assert.NotEqual(t, signature1.A, signature2.A, "Signature component A should be random and independent")
    assert.NotEqual(t, signature1.E, signature2.E, "Signature component E should be random and independent")
}

// TestSignCorrectness tests that the signature satisfies the expected mathematical properties.
func TestSignCorrectness(t *testing.T) {
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

    // Mock message vector
    messages := []string{"message1", "message2", "message3"}

    // Call the Sign function
    signature, err := Sign(publicParams, signingKey, messages)

    // Assert no error occurred
    assert.NoError(t, err, "Sign should not return an error")

    // Recompute x + e
    x_plus_e := new(e.Scalar)
    x_plus_e.Add(signingKey.X, signature.E)
	x_plus_e.Inv(x_plus_e)

    // Compute the expected A = C^{1 / (x + e)}
    C, err := utils.ComputeCommitment(messages, publicParams.H1, publicParams.G1)
    assert.NoError(t, err, "ComputeCommitment should not return an error")

    expectedA := new(e.G1)
    expectedA.ScalarMult(x_plus_e, C)

    // Assert the signature component A matches the expected value
    assert.Equal(t, expectedA, signature.A, "Signature component A should satisfy the expected mathematical property")
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