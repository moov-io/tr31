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

		expectedKeys[i] = urandom(16)
		rawKeyBlocks[i], err = kblock.Wrap(expectedKeys[i], nil)
		if err != nil {
			b.Fatalf("failed to wrap key block: %v", err)
		}
	}

	// Reset timer after setup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyOut, err := keyBlocks[i].Unwrap(hex.EncodeToString(kbpks[i]))
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
/* func BenchmarkUnwrap_D_32_Parallel(b *testing.B) {
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
	expectedKeys := make([][]byte, b.N)
	kblocks := make([]*KeyBlock, b.N)

	for i := 0; i < b.N; i++ {
		// Generate a different KBPK for each iteration
		key, _ := GenerateKBPK(kbpkopts)
		kbpks[i] = key
		// Create a key block for each KBPK
		kblock, err := NewKeyBlock(kbpks[i], header)
		if err != nil {
			b.Fatalf("failed to create key block: %v", err)
		}
		kblocks[i] = kblock
		// Unwrap the key to get the expected key
		keyOut, err := kblocks[i].Unwrap(hex.EncodeToString(kbpks[i]))
		if err != nil {
			b.Fatalf("failed to unwrap key block: %v", err)
		}
		expectedKeys[i] = keyOut
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			keyOut, err := kblocks[counter].Unwrap(hex.EncodeToString(kbpks[counter]))
			if err != nil {
				b.Fatalf("failed to unwrap key %s: %v", hex.EncodeToString(kbpks[counter]), err)
			}
			// check that the value of keyout matches the expectedKeys
			if string(keyOut) != string(expectedKeys[counter]) {
				b.Fatalf("invalid key length: got %s, want %s", keyOut, expectedKeys[counter])
			}
		}
	})
} */
