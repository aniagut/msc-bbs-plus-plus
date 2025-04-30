package keygen

import (
	"github.com/aniagut/msc-bbs-plus-plus/models"
	"github.com/aniagut/msc-bbs-plus-plus/utils"
	e "github.com/cloudflare/circl/ecc/bls12381"
)
	

// KeyGen generates the key material for the BBS++ signature scheme.
// 
// Parameters:
//   - l - length of the messages vector
//
// Returns:
//   - KeyGenResult: A struct containing the keys for signing and verifying messages.
//   - error: An error if key generation fails.
func KeyGen(l int) (models.KeyGenResult, error) {
	
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()

	// 2. Select random h_1[1..l] ← independent generators of G1
	h1, err:= utils.GenerateLRandomG1Elements(l)
	if err != nil {
		return models.KeyGenResult{}, err
	}

	// 3. Select random x ∈ Zp*
	x, err := utils.RandomScalar()
	if err != nil {
		return models.KeyGenResult{}, err
	}

	// 4. Compute verification key vk = X₂ ← g₂^x
	X2 := new(e.G2)
	X2.ScalarMult(&x, g2)

	// Return the result
	return models.KeyGenResult{
		SigningKey: models.SigningKey{
			X: &x,
		},
		VerificationKey: models.VerificationKey{
			X2: X2,
		},
		PublicParameters: models.PublicParameters{
			G1: g1,
			G2: g2,
			H1: h1,
		},
	}, nil
}