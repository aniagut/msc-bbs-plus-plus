package experiments

import (
	"fmt"
	"time"
	"os"
	"github.com/aniagut/msc-bbs-plus-plus/keygen"
	"github.com/aniagut/msc-bbs-plus-plus/sign"
)

// MeasureSignTimeByMessageLength measures the time taken for the Sign function for different message lengths
// and saves the results to a file.
func MeasureSignTimeByMessageLength() {
	// Open the results file for writing
	file, err := os.Create("experiments/results/sign_time_results_msg_length.txt")
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()
	// Write the header to the file
	_, err = file.WriteString("MessageLength,AverageSignTime\n")
	if err != nil {
		fmt.Printf("Error writing to results file: %v\n", err)
		return
	}
	// Generate keys for the system and set l = 1 (one message)
	keyGenResult, err := keygen.KeyGen(1)
	if err != nil {
		fmt.Printf("Error generating keys: %v\n", err)
		return
	}

	// Extract the signing key and public parameters
	signingKey, publicParams := keyGenResult.SigningKey, keyGenResult.PublicParameters

	// Define the length of the message string to test
	messageLengths := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}
	// Iterate over each message length
	for _, length := range messageLengths {
		// Create a random message of the specified length
		message := make([]byte, length)
		for i := range message {
			message[i] = 'a' + byte(i%26) // Fill with letters a-z
		}
		messageString := string(message)
		var totalTime time.Duration
		// Run Sign 10 times and measure the total time
		for i := 0; i < 10; i++ {
			start := time.Now()
			// Call Sign
			message := []string{messageString}
			_, err := sign.Sign(publicParams, signingKey, message)
			if err != nil {
				fmt.Printf("Error during Sign for length=%d: %v\n", length, err)
				return
			}
			// Measure the elapsed time
			elapsed := time.Since(start)
			totalTime += elapsed
		}
		// Calculate the average time
		averageTime := totalTime / 10

		// Print the results
		fmt.Printf("Average Sign time for message length=%d: %v\n", length, averageTime)

		// Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", length, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
	}
}

// MeasureSignTimeByMessageVectorLength measures the time taken for the Sign function for different message vector lengths
// and saves the results to a file.
func MeasureSignTimeByMessageVectorLength() {
	// Open the results file for writing
	file, err := os.Create("experiments/results/sign_time_results_msg_vector_length.txt")
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()
	// Write the header to the file
	_, err = file.WriteString("MessageVectorLength,AverageSignTime\n")
	if err != nil {
		fmt.Printf("Error writing to results file: %v\n", err)
		return
	}

	// Define the sizes of the messages vector to test
	messageVectorLengths := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}

	// Iterate over each message vector length
	for _, length := range messageVectorLengths {
		// Generate keys for the system
		keyGenResult, err := keygen.KeyGen(length)
		if err != nil {
			fmt.Printf("Error generating keys: %v\n", err)
			return
		}

		// Extract the signing key and public parameters
		signingKey, publicParams := keyGenResult.SigningKey, keyGenResult.PublicParameters

		var totalTime time.Duration
		// Create a random message vector of the length `length`
		messageVector := make([]string, length)
		for i := 0; i < length; i++ {
			messageVector[i] = fmt.Sprintf("message%d", i+1)
		}
		// Run Sign 10 times and measure the total time
		for i := 0; i < 10; i++ {
			start := time.Now()
			// Call Sign
			_, err := sign.Sign(publicParams, signingKey, messageVector)
			if err != nil {
				fmt.Printf("Error during Sign for message vector length=%d: %v\n", length, err)
				return
			}
			// Measure the elapsed time
			elapsed := time.Since(start)
			totalTime += elapsed
		}
		// Calculate the average time
		averageTime := totalTime / 10

		// Print the results
		fmt.Printf("Average Sign time for message vector length=%d: %v\n", length, averageTime)

		// Write the results to the file
		_, err = file.WriteString(fmt.Sprintf("%d,%v\n", length, averageTime))
		if err != nil {
			fmt.Printf("Error writing to results file: %v\n", err)
			return
		}
	}
}


