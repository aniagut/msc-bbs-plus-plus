package models

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
)

type KeyGenResult struct {
	SigningKey       SigningKey
	VerificationKey  VerificationKey
	PublicParameters PublicParameters
}

type SigningKey struct {
	X *e.Scalar
}

type VerificationKey struct {
	X2 *e.G2
}

type PublicParameters struct {
	G1 *e.G1
	G2 *e.G2
	H1 []e.G1
}

type Signature struct {
	A *e.G1
	E *e.Scalar
}
	