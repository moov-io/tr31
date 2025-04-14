package tr31

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generate_cbc_mac_with_well_known(t *testing.T) {
	tests := []struct {
		padding int
		length  int
		result  string
	}{
		{1, 8, "68D9038F23360DF3"},
		{2, 8, "32DC341271ACCD00"},
		{3, 8, "CDACA53E2DAA5412"},
		{1, 0, "68D9038F23360DF3"},
		{2, 0, "32DC341271ACCD00"},
		{3, 0, "CDACA53E2DAA5412"},
		{1, 4, "68D9038F"},
		{2, 4, "32DC3412"},
		{3, 4, "CDACA53E"},
	}
	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			keyData, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
			data := []byte("hello world")
			encData, err := GenerateCBCMAC(keyData, data, tt.padding, tt.length, DES)
			assert.Nil(t, err)
			assert.Equal(t, strings.ToLower(tt.result), hex.EncodeToString(encData))
		})
	}
}
func TestGenerateCBCMAC(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		data      []byte
		padding   int
		length    int
		algorithm Algorithm
		wantErr   bool
	}{
		{"AES CBC-MAC, Padding 1, 16-byte Data", []byte("1234567890123456"), []byte("abcdefghijklmnop"), 1, 16, AES, false},
		{"AES CBC-MAC, Padding 1, 32-byte Data", []byte("1234567890123456"), []byte("abcdefghijklmnopqrstuvwx"), 1, 16, AES, false},
		{"AES CBC-MAC, Padding 2, 13-byte Data", []byte("1234567890123456"), []byte("abcdefghijklm"), 2, 16, AES, false},
		{"AES CBC-MAC, Padding 3, 14-byte Data", []byte("1234567890123456"), []byte("abcdefghijklmn"), 3, 16, AES, false},
		{"AES CBC-MAC, Padding 2, Empty Data", []byte("1234567890123456"), []byte{}, 2, 16, AES, true},
		{"AES CBC-MAC, Invalid Padding Method", []byte("1234567890123456"), []byte("abc"), 4, 16, AES, true},
		{"AES CBC-MAC, Invalid Padding Method", []byte("1234567890123456"), []byte("abc"), 0, 16, AES, true},
		{"AES CBC-MAC, Zero Length Defaults to Block Size", []byte("1234567890123456"), []byte("abcdefghijklmnop"), 1, 0, AES, false},
		{"AES CBC-MAC, Data Not a Multiple of Block Size (Fails)", []byte("1234567890123456"), []byte("abcde"), 1, 16, AES, false},
		{"AES CBC-MAC, Longer Length (Truncated)", []byte("1234567890123456"), []byte("abcdefghijklmnop"), 1, 8, AES, false},
		{"AES CBC-MAC, Longer Key", []byte("12345678901234567890123456789012"), []byte("abcdefghijklmnop"), 1, 16, AES, false},

		//DES Tests
		{"DES CBC-MAC, Padding 1, 8-byte Data", []byte("12345678"), []byte("abcdefgh"), 1, 8, DES, false},
		{"DES CBC-MAC, Padding 1, 16-byte Data", []byte("12345678"), []byte("abcdefghijklmnop"), 1, 8, DES, false},
		{"DES CBC-MAC, Padding 2, 7-byte Data", []byte("12345678"), []byte("abcdefg"), 2, 8, DES, false},
		{"DES CBC-MAC, Padding 3, 6-byte Data", []byte("12345678"), []byte("abcdef"), 3, 8, DES, false},
		{"DES CBC-MAC, Invalid Padding Method", []byte("12345678"), []byte("abc"), 4, 8, DES, true},
		{"DES CBC-MAC, Invalid Padding Method", []byte("12345678"), []byte("abc"), 0, 8, DES, true},
		{"DES CBC-MAC, Zero Length Defaults to Block Size", []byte("12345678"), []byte("abcdefgh"), 1, 0, DES, false},
		{"DES CBC-MAC, Longer Length (Truncated)", []byte("12345678"), []byte("abcdefgh"), 1, 4, DES, false},
		{"DES CBC-MAC, Data Not a Multiple of Block Size (Fails)", []byte("12345678"), []byte("abcde"), 1, 8, DES, false},
		{"DES CBC-MAC, Empty Data with Padding", []byte("12345678"), []byte{}, 2, 8, DES, true},
		{"DES CBC-MAC, Longer Key", []byte("123456789012345678"), []byte("abcdefgh"), 1, 8, DES, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCBCMAC(tt.key, tt.data, tt.padding, tt.length, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCBCMAC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.length != 0 && len(got) != tt.length {
				t.Errorf("GenerateCBCMAC() got length = %d, want %d", len(got), tt.length)
			}
		})
	}
}

// Test function for generateRetailMAC
func TestGenerateRetailMAC(t *testing.T) {
	tests := []struct {
		name    string
		key1    []byte
		key2    []byte
		data    []byte
		padding int
		length  int
		wantErr bool
	}{
		// Valid Test Cases
		{"Valid MAC, No Padding, 8-byte Data", []byte("key1key1"), []byte("key2key2"), []byte("abcdefgh"), 1, 8, false},
		{"Valid MAC, Padding 1, 7-byte Data", []byte("key1key1"), []byte("key2key2"), []byte("abcdefg"), 2, 8, false},
		{"Valid MAC, Padding 2, 6-byte Data", []byte("key1key1"), []byte("key2key2"), []byte("abcdef"), 3, 8, false},
		{"Valid MAC, No Padding, 16-byte Data", []byte("key1key1"), []byte("key2key2"), []byte("abcdefghijklmnop"), 1, 8, false},

		// Edge Cases
		{"MAC with Zero Length (Defaults to 8)", []byte("key1key1"), []byte("key2key2"), []byte("abcdefgh"), 1, 0, false},
		{"MAC with Longer Length (Truncated)", []byte("key1key1"), []byte("key2key2"), []byte("abcdefgh"), 1, 4, false},
		{"MAC with Large Input Data", []byte("key1key1"), []byte("key2key2"), []byte("abcdefghijklmnopqrstuv"), 2, 8, false},
		{"MAC with Different Key Sizes", []byte("key1key1key1key1"), []byte("key2key2"), []byte("abcdefgh"), 2, 8, false},
		{"MAC with Same Key1 and Key2", []byte("key1key1"), []byte("key1key1"), []byte("abcdefgh"), 2, 8, false},

		// Invalid Test Cases
		{"Invalid Padding Method", []byte("key1key1"), []byte("key2key2"), []byte("abc"), 4, 8, true},
		{"Invalid Padding Method", []byte("key1key1"), []byte("key2key2"), []byte("abc"), 0, 8, true},
		{"MAC with Short Key1", []byte("key1"), []byte("key2key2"), []byte("abcdefgh"), 2, 8, true},
		{"MAC with Short Key2", []byte("key1key1"), []byte("key2"), []byte("abcdefgh"), 2, 8, true},
		{"MAC with Both Short Keys", []byte("key1"), []byte("key2"), []byte("abcdefgh"), 2, 8, true},
		{"MAC with Empty Data and No Padding", []byte("key1key1"), []byte("key2key2"), []byte{}, 1, 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateRetailMAC(tt.key1, tt.key2, tt.data, tt.padding, tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateRetailMAC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.length != 0 && len(got) != tt.length {
				t.Errorf("generateRetailMAC() got length = %d, want %d", len(got), tt.length)
			}
		})
	}
}

// Test function for padISO1
func TestPadISO1(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  []byte
	}{
		// Valid Test Cases
		{"Exact Block Size (8 bytes)", []byte("12345678"), 8, []byte("12345678")},
		{"Shorter Than Block (5 bytes, padded to 8)", []byte("12345"), 8, []byte("12345\x00\x00\x00")},
		{"Longer Than Block (10 bytes, padded to 16)", []byte("abcdefghij"), 8, []byte("abcdefghij\x00\x00\x00\x00\x00\x00")},
		{"Multiple Blocks (16 bytes, no padding)", []byte("1234567812345678"), 8, []byte("1234567812345678")},
		{"Zero Length Input (should pad to block size)", []byte{}, 8, []byte("\x00\x00\x00\x00\x00\x00\x00\x00")},

		// Edge Cases
		{"Block Size 1 (pads to 1-byte block)", []byte("X"), 1, []byte("X")},
		{"Block Size 3 (pads to 6-byte block)", []byte("AB"), 3, []byte("AB\x00")},
		{"Block Size 16 (pads from 10 to 16)", []byte("abcdefghij"), 16, []byte("abcdefghij\x00\x00\x00\x00\x00\x00")},

		// Invalid Cases
		{"Negative Block Size (defaults to 8, pads to 8)", []byte("ABC"), -5, []byte("ABC\x00\x00\x00\x00\x00")},
		{"Zero Block Size (defaults to 8, pads to 8)", []byte("ABCD"), 0, []byte("ABCD\x00\x00\x00\x00")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padISO1(tt.data, tt.blockSize)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("padISO1() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// Test function for padISO2
func TestPadISO2(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  []byte
	}{
		//  Valid Test Cases
		{"Exact Block Size (8 bytes, adds 0x80 and pads to 16)", []byte("12345678"), 8, []byte("12345678\x80\x00\x00\x00\x00\x00\x00\x00")},
		{"Shorter Than Block (5 bytes, adds 0x80 and pads to 8)", []byte("12345"), 8, []byte("12345\x80\x00\x00")},
		{"Longer Than Block (10 bytes, adds 0x80 and pads to 16)", []byte("abcdefghij"), 8, []byte("abcdefghij\x80\x00\x00\x00\x00\x00")},
		{"Multiple Blocks (16 bytes, adds 0x80 and pads to 24)", []byte("1234567812345678"), 8, []byte("1234567812345678\x80\x00\x00\x00\x00\x00\x00\x00")},
		{"Zero Length Input (adds 0x80 and pads to 8)", []byte{}, 8, []byte("\x80\x00\x00\x00\x00\x00\x00\x00")},

		//  Edge Cases
		{"Block Size 1 (adds 0x80, no padding needed)", []byte("X"), 1, []byte("X\x80")},
		{"Block Size 3 (adds 0x80 and pads to 6)", []byte("AB"), 6, []byte("AB\x80\x00\x00\x00")},
		{"Block Size 16 (pads from 10 to 16)", []byte("abcdefghij"), 16, []byte("abcdefghij\x80\x00\x00\x00\x00\x00")},

		//  Invalid Cases
		{"Negative Block Size (defaults to 8, pads accordingly)", []byte("ABC"), -5, []byte("ABC\x80\x00\x00\x00\x00")},
		{"Zero Block Size (defaults to 8, pads accordingly)", []byte("ABCD"), 0, []byte("ABCD\x80\x00\x00\x00")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padISO2(tt.data, tt.blockSize)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("padISO2() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
func makeLengthPrefix(dataLen int, blockSize int) []byte {
	lengthBytes := make([]byte, blockSize)
	if blockSize < 4 {
		value := uint64(dataLen * 8)
		for i := 0; i < blockSize; i++ {
			lengthBytes[i] = byte(value >> (8 * (blockSize - 1 - i))) // Extract highest bytes first
		}
	} else if blockSize < 8 {
		if len(lengthBytes) < 4 {
			return nil
		}
		binary.BigEndian.PutUint32(lengthBytes, uint32(dataLen*8))
	} else {
		if len(lengthBytes) < 8 {
			return nil
		}
		binary.BigEndian.PutUint64(lengthBytes, uint64(dataLen*8))
	}
	return lengthBytes
}

// Test function for padISO3
func TestPadISO3(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		expected  []byte
	}{
		//  Valid Test Cases
		{"Exact Block Size (8 bytes, adds length prefix)", []byte("12345678"), 8, append(makeLengthPrefix(8, 8), []byte("12345678")...)},
		{"Shorter Than Block (5 bytes, pads and adds length prefix)", []byte("12345"), 8, append(makeLengthPrefix(5, 8), []byte("12345\x00\x00\x00")...)},
		{"Longer Than Block (10 bytes, pads to 16 and adds length prefix)", []byte("abcdefghij"), 8, append(makeLengthPrefix(10, 8), []byte("abcdefghij\x00\x00\x00\x00\x00\x00")...)},
		{"Multiple Blocks (16 bytes, adds length prefix)", []byte("1234567812345678"), 8, append(makeLengthPrefix(16, 8), []byte("1234567812345678")...)},
		{"Zero Length Input (adds length prefix and pads to 8)", []byte{}, 8, append(makeLengthPrefix(0, 8), []byte("\x00\x00\x00\x00\x00\x00\x00\x00")...)},

		//  Edge Cases
		{"Block Size 4 (adds 4-byte length prefix and pads to 8)", []byte("AB"), 4, append(makeLengthPrefix(2, 4), []byte("AB\x00\x00")...)},
		{"Block Size 16 (pads from 10 to 16 and adds length prefix)", []byte("abcdefghij"), 16, append(makeLengthPrefix(10, 16), []byte("abcdefghij\x00\x00\x00\x00\x00\x00")...)},
		{"Small Block Size 3 (uses 4-byte length prefix and pads to 6)", []byte("ABC"), 3, append(makeLengthPrefix(3, 3), []byte("ABC")...)},

		//  Invalid Cases
		{"Negative Block Size (defaults to 8, pads accordingly)", []byte("ABC"), -5, append(makeLengthPrefix(3, 8), []byte("ABC\x00\x00\x00\x00\x00")...)},
		{"Zero Block Size (defaults to 8, pads accordingly)", []byte("ABCD"), 0, append(makeLengthPrefix(4, 8), []byte("ABCD\x00\x00\x00\x00")...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padISO3(tt.data, tt.blockSize)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("padISO3() = %v, expected %v", got, tt.expected)
			}
		})
	}
}
