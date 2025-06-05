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
    publicParams := models.PublicParameters{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H1: GenerateMockH1(3),
    }
    signingKey := models.SigningKey{
        X: GenerateMockScalar(12345),
    }
    messages := []string{"message1", "message2", "message3"}
    signature, err := Sign(publicParams, signingKey, messages)
    assert.NoError(t, err, "Sign should not return an error")
    assert.NotNil(t, signature.A, "Signature component A should not be nil")
    assert.NotNil(t, signature.E, "Signature component E should not be nil")
}

// TestSignRandomness tests that the Sign function generates different signatures for the same input.
func TestSignRandomness(t *testing.T) {
    publicParams := models.PublicParameters{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H1: GenerateMockH1(3),
    }
    signingKey := models.SigningKey{
        X: GenerateMockScalar(12345),
    }
    messages := []string{"message1", "message2", "message3"}
    signature1, err1 := Sign(publicParams, signingKey, messages)
    signature2, err2 := Sign(publicParams, signingKey, messages)
    assert.NoError(t, err1, "First Sign call should not return an error")
    assert.NoError(t, err2, "Second Sign call should not return an error")
    assert.NotEqual(t, signature1.A, signature2.A, "Signature component A should be random and independent")
    assert.NotEqual(t, signature1.E, signature2.E, "Signature component E should be random and independent")
}

// TestSignCorrectness tests that the signature satisfies the expected mathematical properties.
func TestSignCorrectness(t *testing.T) {
    publicParams := models.PublicParameters{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H1: GenerateMockH1(3),
    }
    signingKey := models.SigningKey{
        X: GenerateMockScalar(12345),
    }
    messages := []string{"message1", "message2", "message3"}
    signature, err := Sign(publicParams, signingKey, messages)
    assert.NoError(t, err, "Sign should not return an error")
    xPlusE := new(e.Scalar)
    xPlusE.Add(signingKey.X, signature.E)
    xPlusE.Inv(xPlusE)
    C, err := utils.ComputeCommitment(messages, publicParams.H1, publicParams.G1)
    assert.NoError(t, err, "ComputeCommitment should not return an error")
    expectedA := new(e.G1)
    expectedA.ScalarMult(xPlusE, C)
    assert.Equal(t, expectedA, signature.A, "Signature component A should satisfy the expected mathematical property")
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