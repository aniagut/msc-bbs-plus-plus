package utils

import (
    "testing"

    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
	"math/big"
)

// TestComputeCommitment tests the ComputeCommitment function.
func TestComputeCommitment(t *testing.T) {
    // Mock inputs
    messages := []string{"message1", "message2", "message3"}
    h1, err := GenerateLRandomG1Elements(len(messages))
    assert.NoError(t, err, "GenerateLRandomG1Elements should not return an error")

    g1 := e.G1Generator()

    // Call ComputeCommitment
    commitment, err := ComputeCommitment(messages, h1, g1)
    assert.NoError(t, err, "ComputeCommitment should not return an error")

    // Assert the commitment is not nil
    assert.NotNil(t, commitment, "Commitment should not be nil")

    // Assert the commitment is not the identity element
    assert.False(t, commitment.IsIdentity(), "Commitment should not be the identity element")
}

// TestRandomScalar tests the RandomScalar function.
func TestRandomScalar(t *testing.T) {
    // Call RandomScalar
    scalar, err := RandomScalar()
    assert.NoError(t, err, "RandomScalar should not return an error")

    // Assert the scalar is not zero
    assert.False(t, scalar.IsZero() == 1, "RandomScalar should not generate a zero scalar")

    // Assert the scalar is less than the curve order
    order := OrderAsBigInt()
	scalarBytes, err := scalar.MarshalBinary()
	assert.NoError(t, err, "Scalar.MarshalBinary should not return an error")

    scalarBigInt := new(big.Int).SetBytes(scalarBytes)
    assert.True(t, scalarBigInt.Cmp(order) < 0, "RandomScalar should be less than the curve order")
}

// TestGenerateLRandomG1Elements tests the GenerateLRandomG1Elements function.
func TestGenerateLRandomG1Elements(t *testing.T) {
    // Define the number of elements to generate
    numElements := 5

    // Call GenerateLRandomG1Elements
    elements, err := GenerateLRandomG1Elements(numElements)
    assert.NoError(t, err, "GenerateLRandomG1Elements should not return an error")

    // Assert the correct number of elements is generated
    assert.Equal(t, numElements, len(elements), "GenerateLRandomG1Elements should generate the correct number of elements")

    // Assert each element is not the identity element
    for i, element := range elements {
        assert.False(t, element.IsIdentity(), "Element %d should not be the identity element", i)
    }
}

// TestSerializeString tests the SerializeString function.
func TestSerializeString(t *testing.T) {
    // Mock input string
    input := "Hello, world!"

    // Call SerializeString
    serialized := SerializeString(input)

    // Assert the serialized output matches the input
    assert.Equal(t, []byte(input), serialized, "SerializeString should return the correct byte slice")
}

// TestOrderAsBigInt tests the OrderAsBigInt function.
func TestOrderAsBigInt(t *testing.T) {
    // Call OrderAsBigInt
    order := OrderAsBigInt()

    // Assert the order is not nil
    assert.NotNil(t, order, "OrderAsBigInt should not return nil")

    // Assert the order is greater than zero
    assert.True(t, order.Sign() > 0, "OrderAsBigInt should return a positive value")
}