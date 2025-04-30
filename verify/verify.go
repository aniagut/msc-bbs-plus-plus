package verify

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs-plus-plus/models"
	"github.com/aniagut/msc-bbs-plus-plus/utils"
)


// Verify checks the validity of a BBS++ signature.
//
// Parameters:
//   - publicParams: The public parameters of the system.
//   - verificationKey: The verification key of the system.
//   - M: The message to be verified.
//   - signature: The signature to be verified.
//
// Returns:
//   - boolean: True if the signature is valid, false otherwise.
//   - error: An error if the verification process fails.
func Verify(publicParams models.PublicParameters, verificationKey models.VerificationKey, M []string, signature models.Signature) (bool, error) {
	// Step 1: Compute commitment C ← g1 * ∏_i h₁[i]^m[i]
	C, err := utils.ComputeCommitment(M, publicParams.H1, publicParams.G1)
	if err != nil {
		return false, err
	}

	// Step 2: Check pairing e(A, g₂^e · vk) ?= e(C, g₂)
	// If equal, return true
	g_2_e := new(e.G2)
	g_2_e.ScalarMult(signature.E, publicParams.G2)
	g_2_e.Add(g_2_e, verificationKey.X2)

	e1 := new(e.Gt)
	e1 = e.Pair(signature.A, g_2_e)
	e2 := new(e.Gt)
	e2 = e.Pair(C, publicParams.G2)
	if e1.IsEqual(e2) == false {
		return false, nil
	}
	return true, nil
}