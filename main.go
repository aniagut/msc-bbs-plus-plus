package main

import (
	"fmt"
	"github.com/aniagut/msc-bbs-plus-plus/keygen"
	"github.com/aniagut/msc-bbs-plus-plus/sign"
	"github.com/aniagut/msc-bbs-plus-plus/verify"
	// "github.com/aniagut/msc-bbs-plus-plus/experiments"
)


func main() {
	// Measure the time taken for KeyGen function
	// experiments.MeasureVerifyTimeByMessageVectorLength()
	
	// Example usage of KeyGen
	l := 5 // Length of the messages vector
	result, err := keygen.KeyGen(l)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	fmt.Println("Signing Key:", result.SigningKey.X)
	fmt.Println("Verification Key:", result.VerificationKey.X2)
	fmt.Println("Generated keys successfully.")

	// Example usage of Sign
	M := []string{"message1", "message2", "message3", "message4", "message5"}
	signature, err := sign.Sign(result.PublicParameters, result.SigningKey, M)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Println("Signature A:", signature.A)
	fmt.Println("Signature e:", signature.E)
	fmt.Println("Signature generated successfully.")

	// Example usage of Verify
	M1 := []string{"message1", "message99", "message3", "message4", "message5"}
	isValid, err := verify.Verify(result.PublicParameters, result.VerificationKey, M1, signature)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		return
	}
	fmt.Println("Is the signature valid?", isValid)
}

