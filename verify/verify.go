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
//   - m: The message to be verified.
//   - signature: The signature to be verified.
//
// Returns:
//   - boolean: True if the signature is valid, false otherwise.
//   - error: An error if the verification process fails.
func Verify(publicParams models.PublicParameters, verificationKey models.VerificationKey, m []string, signature models.Signature) (bool, error) {
    // Step 1: Compute commitment c ← g1 * ∏_i h₁[i]^m[i]
    c, err := utils.ComputeCommitment(m, publicParams.H1, publicParams.G1)
    if err != nil {
        return false, err
    }

    // Step 2: Check pairing e(a, g2^e · vk) ?= e(c, g2)
    // If equal, return true
    g2e := new(e.G2)
    g2e.ScalarMult(signature.E, publicParams.G2)
    g2e.Add(g2e, verificationKey.X2)

    e1 := new(e.Gt)
    e1 = e.Pair(signature.A, g2e)
    e2 := new(e.Gt)
    e2 = e.Pair(c, publicParams.G2)
    if !e1.IsEqual(e2) {
        return false, nil
    }
    return true, nil
}