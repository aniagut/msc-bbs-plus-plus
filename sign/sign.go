package sign

import (
	"errors"
	"github.com/aniagut/msc-bbs-plus-plus/models"
	"github.com/aniagut/msc-bbs-plus-plus/utils"
	e "github.com/cloudflare/circl/ecc/bls12381"
)


// Sign generates a BBS++ signature for a given message.
//
// Parameters:
//   - publicParams: The public key of the system.
//   - signingKey: The key used for signing the message.
//   - M: The message to be signed.
//
// Returns:
//   - Signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicParams models.PublicParameters, signingKey models.SigningKey, M []string) (models.Signature, error) {
	// Step 1: Compute commitment C ← g1 * ∏_i h₁[i]^m[i]
	C, err := utils.ComputeCommitment(M, publicParams.H1, publicParams.G1)
    if err != nil {
        return models.Signature{}, err
    }

	// Step 2: Set random elem ← Z_p* and ensure x + e ≠ 0
	elem := new(e.Scalar)
	for {
		randomScalar, err := utils.RandomScalar()
		if err != nil {
			return models.Signature{}, errors.New("failed to generate random scalar e")
		}

		// Check if x + e ≠ 0
		elem.Add(signingKey.X, &randomScalar)
		if elem.IsZero() == 0 {
			break
		}
	}

	// Step 3: Compute signature component A <- C^{1 / (x + e)} ∈ G_1
	A := computeA(signingKey.X, elem, C)

	// Step 4: Return the signature σ = (A, e)
	return models.Signature{
		A: A,
		E: elem,
	}, nil
}

// ComputeA computes the signature component A = C^{1 / (x + e)} ∈ G_1
func computeA(x *e.Scalar, elem *e.Scalar, C *e.G1) *e.G1 {
	x_plus_e := new(e.Scalar)
	x_plus_e.Add(x, elem)

	// Compute the inverse of (x + e)
	x_plus_e.Inv(x_plus_e)

	// Compute A = C^{1 / (x + e)}
	A := new(e.G1)
	A.ScalarMult(x_plus_e, C)
	return A
}