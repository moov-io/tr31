package tr31

import (
	"crypto/rand"
	"testing"
)

// func urandom(tb testing.TB, length int) []byte {
// 	tb.Helper()

//		pad := make([]byte, length)
//		_, err := rand.Read(pad)
//		if err != nil {
//			tb.Fatal(err)
//		}
//		return pad
//	}
func urandom(tb testing.TB, length int) []byte {
	tb.Helper()

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		tb.Fatalf("failed to generate random bytes: %v", err)
	}
	return buf
}
