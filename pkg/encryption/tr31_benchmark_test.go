package encryption

import (
	"encoding/hex"
	"testing"
)

// BenchmarkUnwrap_D_32_WithSetup benchmarks the Unwrap function with setup cost excluded
func BenchmarkUnwrap_D_32_WithSetup(b *testing.B) {

	kbpkopts := KBPKOptions{
		Version:   "D",
		KeyLength: 32,
	}

	header, err := NewHeader("D", "D0", "A", "D", "00", "E")
	if err != nil {
		b.Fatalf("failed to create header: %v", err)
	}

	// Create a slice of different KBPKs for testing
	kbpks := make([][]byte, b.N)
	keyBlocks := make([]*KeyBlock, b.N)
	rawKeyBlocks := make([]string, b.N)
	expectedKeys := make([][]byte, b.N)

	for i := 0; i < b.N; i++ {
		// Generate a different KBPK for each iteration
		key, _ := GenerateKBPK(kbpkopts)
		kbpks[i] = key
		// Create a key block for each KBPK
		kblock, err := NewKeyBlock(kbpks[i], header)
		if err != nil {
			b.Fatalf("failed to create key block: %v", err)
		}
		keyBlocks[i] = kblock

		expectedKeys[i] = urandom(b, 16)
		rawKeyBlocks[i], err = kblock.Wrap(expectedKeys[i], nil)
		if err != nil {
			b.Fatalf("failed to wrap key block: %v", err)
		}
	}

	// Reset timer after setup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyOut, err := keyBlocks[i].Unwrap(rawKeyBlocks[i])
		if err != nil {
			b.Fatalf("failed to unwrap key %s: %v", hex.EncodeToString(kbpks[i]), err)
		}
		// check that the value of keyout matches the expectedKeys
		if string(keyOut) != string(expectedKeys[i]) {
			b.Fatalf("invalid key length: got %s, want %s", keyOut, expectedKeys[i])
		}
	}
}

// BenchmarkUnwrap_D_32_Parallel benchmarks the Unwrap function with parallel execution
func BenchmarkUnwrap_D_32_Parallel(b *testing.B) {
	kbpkopts := KBPKOptions{
		Version:   "D",
		KeyLength: 32,
	}

	header, err := NewHeader("D", "D0", "A", "D", "00", "E")
	if err != nil {
		b.Fatalf("failed to create header: %v", err)
	}

	// Create initial test data - we'll use a fixed size that's large enough
	const testDataSize = 500 // Adjust this number based on your needs
	kbpks := make([][]byte, testDataSize)
	keyBlocks := make([]*KeyBlock, testDataSize)
	rawKeyBlocks := make([]string, testDataSize)
	expectedKeys := make([][]byte, testDataSize)

	// Setup phase - generate test data
	for i := 0; i < testDataSize; i++ {
		// Generate a different KBPK for each iteration
		key, _ := GenerateKBPK(kbpkopts)
		kbpks[i] = key

		// Create a key block for each KBPK
		kblock, err := NewKeyBlock(kbpks[i], header)
		if err != nil {
			b.Fatalf("failed to create key block: %v", err)
		}
		keyBlocks[i] = kblock

		expectedKeys[i] = urandom(b, 16)
		rawKeyBlocks[i], err = kblock.Wrap(expectedKeys[i], nil)
		if err != nil {
			b.Fatalf("failed to wrap key block: %v", err)
		}
	}

	// Set the number of iterations for the benchmark
	b.SetBytes(int64(32)) // Set bytes/op metric
	b.ResetTimer()

	// Run the benchmark in parallel
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine gets its own counter
		localCounter := 0
		for pb.Next() {
			// Use the local counter modulo the test data size
			i := localCounter % testDataSize
			localCounter++

			keyOut, err := keyBlocks[i].Unwrap(rawKeyBlocks[i])
			if err != nil {
				b.Fatalf("failed to unwrap key %s: %v", hex.EncodeToString(kbpks[i]), err)
			}

			// Check that the value of keyout matches the expectedKeys
			if string(keyOut) != string(expectedKeys[i]) {
				b.Fatalf("key mismatch at index %d: got %x, want %x",
					i, keyOut, expectedKeys[i])
			}
		}
	})
}
