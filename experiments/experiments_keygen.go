package experiments

import (
    "fmt"
    "time"
    "os"
    "github.com/aniagut/msc-bbs-plus-plus/keygen"
)

// MeasureKeyGenTime measures the time taken for the KeyGen function
// for different parameter l - length of the messages vector

func MeasureKeyGenTime() {
    // Open the results file for writing
    file, err := os.Create("experiments/results/keygen_time_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()

    // Write the header to the file
    _, err = file.WriteString("MessageVectorLength,AverageKeyGenTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }

    // Define the sizes of the messages vector to test
    lSizes := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000}
    // Iterate over each size
    for _, l := range lSizes {
        var totalTime time.Duration
        // Run KeyGen 10 times and measure the total time
        for i := 0; i < 10; i++ {
            start := time.Now()
            // Call KeyGen
            _, err := keygen.KeyGen(l)
            if err != nil {
                fmt.Printf("Error during KeyGen for l=%d: %v\n", l, err)
                return
            }
            // Measure the elapsed time
            elapsed := time.Since(start)
            totalTime += elapsed
        }
        // Calculate the average time
        averageTime := totalTime / 10
        // Print the results
        fmt.Printf("Average KeyGen time for l=%d: %v\n", l, averageTime)

        // Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", l, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
    }
}