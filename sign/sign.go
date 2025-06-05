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
//   - m: The message to be signed.
//
// Returns:
//   - signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicParams models.PublicParameters, signingKey models.SigningKey, m []string) (models.Signature, error) {
    // Step 1: Compute commitment c ← g1 * ∏_i h₁[i]^m[i]
    c, err := utils.ComputeCommitment(m, publicParams.H1, publicParams.G1)
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

    // Step 3: Compute signature component A <- c^{1 / (x + e)} ∈ G_1
    A := ComputeA(signingKey.X, elem, c)

    // Step 4: Return the signature σ = (A, e)
    return models.Signature{
        A: A,
        E: elem,
    }, nil
}

// ComputeA computes the signature component A = c^{1 / (x + e)} ∈ G_1
func ComputeA(x *e.Scalar, elem *e.Scalar, c *e.G1) *e.G1 {
    xPlusE := new(e.Scalar)
    xPlusE.Add(x, elem)

    // Compute the inverse of (x + e)
    xPlusE.Inv(xPlusE)

    // Compute A = c^{1 / (x + e)}
    A := new(e.G1)
    A.ScalarMult(xPlusE, c)
    return A
}