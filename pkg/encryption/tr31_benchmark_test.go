package encryption

import (
	"encoding/hex"
	"testing"
)

// BenchmarkUnwrap_D_32 benchmarks the Unwrap function with different KBPKs
// func BenchmarkUnwrap_D_32(b *testing.B) {
// 	// Original test values
// 	kb := "D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"
// 	expectedKey, _ := hex.DecodeString("B9517FF24FD4C71833478D424C29751D")

// 	// Validate initial setup works
// 	initialKBPK, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
// 	initialKblock, err := NewKeyBlock(initialKBPK, nil)
// 	if err != nil {
// 		b.Fatalf("failed to create initial key block: %v", err)
// 	}
// 	initialKeyOut, err := initialKblock.Unwrap(kb)
// 	if err != nil {
// 		b.Fatalf("failed initial unwrap: %v", err)
// 	}
// 	if len(initialKeyOut) != len(expectedKey) {
// 		b.Fatalf("initial setup failed: invalid key length: got %d, want %d", len(initialKeyOut), len(expectedKey))
// 	}

// 	// Run the benchmark
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		// Generate a different KBPK for each iteration by modifying the last byte
// 		kbpk, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
// 		kbpk[len(kbpk)-1] = byte(i % 256)

// 		kblock, err := NewKeyBlock(kbpk, nil)
// 		if err != nil {
// 			b.Fatalf("failed to create key block: %v", err)
// 		}

// 		keyOut, err := kblock.Unwrap(kb)
// 		if err != nil {
// 			b.Fatalf("failed to unwrap: %v", err)
// 		}

// 		if len(keyOut) != len(expectedKey) {
// 			b.Fatalf("invalid key length: got %d, want %d", len(keyOut), len(expectedKey))
// 		}
// 	}
// }

// BenchmarkUnwrap_D_32_Parallel benchmarks the Unwrap function with parallel execution
// func BenchmarkUnwrap_D_32_Parallel(b *testing.B) {
// 	kb := "D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"
// 	expectedKey, _ := hex.DecodeString("B9517FF24FD4C71833478D424C29751D")

// 	// Validate initial setup
// 	initialKBPK, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
// 	initialKblock, err := NewKeyBlock(initialKBPK, nil)
// 	if err != nil {
// 		b.Fatalf("failed to create initial key block: %v", err)
// 	}
// 	initialKeyOut, err := initialKblock.Unwrap(kb)
// 	if err != nil {
// 		b.Fatalf("failed initial unwrap: %v", err)
// 	}
// 	if len(initialKeyOut) != len(expectedKey) {
// 		b.Fatalf("initial setup failed: invalid key length: got %d, want %d", len(initialKeyOut), len(expectedKey))
// 	}

// 	b.ResetTimer()
// 	b.RunParallel(func(pb *testing.PB) {
// 		counter := 0
// 		for pb.Next() {
// 			// Generate a different KBPK for each iteration
// 			kbpk, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
// 			kbpk[len(kbpk)-1] = byte(counter % 256)
// 			counter++

// 			kblock, err := NewKeyBlock(kbpk, nil)
// 			if err != nil {
// 				b.Fatalf("failed to create key block: %v", err)
// 			}

// 			keyOut, err := kblock.Unwrap(kb)
// 			if err != nil {
// 				b.Fatalf("failed to unwrap: %v", err)
// 			}

// 			if len(keyOut) != len(expectedKey) {
// 				b.Fatalf("invalid key length: got %d, want %d", len(keyOut), len(expectedKey))
// 			}
// 		}
// 	})
// }

// BenchmarkUnwrap_D_32_WithSetup benchmarks the Unwrap function with setup cost excluded
func BenchmarkUnwrap_D_32_WithSetup(b *testing.B) {
	kb := "D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"
	expectedKey, _ := hex.DecodeString("B9517FF24FD4C71833478D424C29751D")

	// Validate initial setup
	initialKBPK, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	initialKblock, err := NewKeyBlock(initialKBPK, nil)
	if err != nil {
		b.Fatalf("failed to create initial key block: %v", err)
	}
	initialKeyOut, err := initialKblock.Unwrap(kb)
	if err != nil {
		b.Fatalf("failed initial unwrap: %v", err)
	}
	if len(initialKeyOut) != len(expectedKey) {
		b.Fatalf("initial setup failed: invalid key length: got %d, want %d", len(initialKeyOut), len(expectedKey))
	}

	// Create a slice of different KBPKs for testing
	kbpks := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		key, _ := GenerateKBPK(KBPKOptions{
			Version:   "D",
			KeyLength: 32,
		})
		kbpks[i] = key
	}
	// Create a default header: version d, key length 32
	header, err := NewHeader("D", "D0", "A", "D", "00", "E")
	if err != nil {
		b.Fatalf("failed to create header: %v", err)
	}

	// Create a slide of NewKeyBlocks from kbpks
	kblocks := make([]*KeyBlock, b.N)
	for i := 0; i < b.N; i++ {
		kblock, err := NewKeyBlock(kbpks[i], header)
		if err != nil {
			b.Fatalf("failed to create key block: %v", err)
		}
		kblocks[i] = kblock
	}

	// Reset timer after setup
	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		keyOut, err := kblocks[i].Unwrap(hex.EncodeToString(kbpks[i]))
		if err != nil {
			b.Fatalf("failed to unwrap key %s: %v", hex.EncodeToString(kbpks[i]), err)
		}

		if len(keyOut) != len(expectedKey) {
			b.Fatalf("invalid key length: got %d, want %d", len(keyOut), len(expectedKey))
		}
	}
}
