package encryption

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestHeaderLoad(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0000xxxxxxxx"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 16, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 0)
	assert.Equal(t, "B0016P0TE00N0000", h.String())
}
func TestHeaderBlocksDict(t *testing.T) {
	h := NewHeader("B", "P0", "T", "E", "", "")
	h.Blocks._blocks["KS"] = "ABCD"

	if len(h.Blocks._blocks) != 1 {
		t.Errorf("Expected 1 block, got %d", len(h.Blocks._blocks))
	}
	if h.Blocks._blocks["KS"] != "ABCD" {
		t.Errorf("Expected block 'KS' to be 'ABCD', got '%s'", h.Blocks._blocks["KS"])
	}
	if _, exists := h.Blocks._blocks["KS"]; !exists {
		t.Error("Expected 'KS' to exist in blocks")
	}
	if repr := fmt.Sprintf("%v", h.Blocks._blocks); repr != "map[KS:ABCD]" {
		t.Errorf("Expected repr 'map[KS:ABCD]', got '%s'", repr)
	}

	delete(h.Blocks._blocks, "KS")
	if len(h.Blocks._blocks) != 0 {
		t.Errorf("Expected 0 blocks after deletion, got %d", len(h.Blocks._blocks))
	}
	if _, exists := h.Blocks._blocks["KS"]; exists {
		t.Error("Expected 'KS' to be deleted from blocks")
	}
	if repr := fmt.Sprintf("%v", h.Blocks._blocks); repr != "map[]" {
		t.Errorf("Expected repr 'map[]', got '%s'", repr)
	}
}

// TestHeaderLoadOptionalDes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalDes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292800000", h.Blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0100KS1800604B120F9292800000", h.String())
}

// TestHeaderLoadOptionalAes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalAes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292800000", h.Blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1800604B120F9292800000PB080000", h.String())
}

// TestHeaderLoadOptionalWithBadCountDes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalWithBadCountDes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0000KS1800604B120F9292800000"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 16, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 0)
	assert.Equal(t, "B0016P0TE00N0000", h.String())
}

// TestHeaderLoadOptionalWithBadCountAES tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalWithBadCountAES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0000KS1800604B120F9292800000"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 16, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 0)
	assert.Equal(t, "D0016P0TE00N0000", h.String())

}

// TestHeaderLoadOptionalPaddedDES tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalPaddedDES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS1200604B120F9292PB0600"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.Blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0200KS1200604B120F9292PB0600", h.String())
}
func TestHeaderLoadOptionalPaddedAES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS1200604B120F9292PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 40, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.Blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1200604B120F9292PB0E0000000000", h.String())
}
func Test_header_load_optional_256_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS0002010A" + strings.Repeat("P", 256) + "PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 288, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, strings.Repeat("P", 256), h.Blocks._blocks["KS"])
	assert.Equal(t, "B0288P0TE00N0200KS0002010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_256_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS0002010A" + strings.Repeat("P", 256) + "PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 288, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, strings.Repeat("P", 256), h.Blocks._blocks["KS"])
	assert.Equal(t, "D0288P0TE00N0200KS0002010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_extended_length_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS00011600604B120F9292PB0A000000"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 48, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.Blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0200KS1200604B120F9292PB0600", h.String())
}
func Test_header_load_optional_extended_length_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS00011600604B120F9292PB0A000000"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 48, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.Blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1200604B120F9292PB0E0000000000", h.String())
}
func Test_header_load_optional_multiple_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 56, length)
	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 3)
	assert.Equal(t, "00604B120F9292800000", h.Blocks._blocks["KS"])
	assert.Equal(t, "", h.Blocks._blocks["T1"])
	assert.Equal(t, "00", h.Blocks._blocks["T2"])
	assert.Equal(t, "B0056P0TE00N0400KS1800604B120F9292800000T104T20600PB0600", h.String())
}
func Test_header_load_optional_multiple_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 56, length)
	assert.Equal(t, "D", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 3)
	assert.Equal(t, "00604B120F9292800000", h.Blocks._blocks["KS"])
	assert.Equal(t, "", h.Blocks._blocks["T1"])
	assert.Equal(t, "00", h.Blocks._blocks["T2"])
	assert.Equal(t, "D0064P0TE00N0400KS1800604B120F9292800000T104T20600PB0E0000000000", h.String())
}
func Test_header_load_optional_reset(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 56, length)

	tr31StrRe := "B0000P0TE00N0000"
	lengthRe, _ := h.Load(tr31StrRe)
	assert.Equal(t, 16, lengthRe)

	assert.Equal(t, "B", h.VersionID)
	assert.Equal(t, "P0", h.KeyUsage)
	assert.Equal(t, "T", h.Algorithm)
	assert.Equal(t, "E", h.ModeOfUse)
	assert.Equal(t, "N", h.Exportability)
	assert.Equal(t, "00", h.Reserved)
	assert.Len(t, h.Blocks._blocks, 0)
	assert.Equal(t, "B0016P0TE00N0000", h.String())
}

type HeaderErrorItem struct {
	header      string
	exceptError string
}

var InitialHeaderErrorSequence = []HeaderErrorItem{
	{
		header:      "B0000P0TE00N0100",
		exceptError: "Block ID () is malformed.",
	},
	{
		header:      "B0000P0TE00N0100K",
		exceptError: "Block ID (K) is malformed.",
	},
	{header: "B0000P0TE00N0100KS", exceptError: "Block KS length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS1", exceptError: "Block KS length (1) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS1Y", exceptError: "Block KS length (1Y) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS02", exceptError: "Block KS length does not include block ID and length."},
	{header: "B0000P0TE00N0100KS071", exceptError: "Block KS data is malformed. Received 1/3. Block data: '1'"},
	{header: "B0000P0TE00N0100KS00", exceptError: "Block KS length of length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS001", exceptError: "Block KS length of length (1) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS001S", exceptError: "Block KS length of length (1S) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS0000", exceptError: "Block KS length of length must not be 0."},
	{header: "B0000P0TE00N0100KS0001", exceptError: "Block KS length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS00010", exceptError: "Block KS length (0) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS00010H", exceptError: "Block KS length (0H) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0100KS000101", exceptError: "Block KS length does not include block ID and length."},
	{header: "B0000P0TE00N0100KS0001FF", exceptError: "Block KS data is malformed. Received 0/247. Block data: ''"},
	{header: "B0000P0TE00N0200KS07000T", exceptError: "Block ID (T) is malformed."},
	{header: "B0000P0TE00N0200KS0600TT", exceptError: "Block TT length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS050TT1", exceptError: "Block TT length (1) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT1X", exceptError: "Block TT length (1X) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT03", exceptError: "Block TT length does not include block ID and length."},
	{header: "B0000P0TE00N0200KS04TT05", exceptError: "Block TT data is malformed. Received 0/1. Block data: ''"},
	{header: "B0000P0TE00N0200KS04TT00", exceptError: "Block TT length of length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT001", exceptError: "Block TT length of length (1) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT001S", exceptError: "Block TT length of length (1S) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT0000", exceptError: "Block TT length of length must not be 0."},
	{header: "B0000P0TE00N0200KS04TT0001", exceptError: "Block TT length () is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT00010", exceptError: "Block TT length (0) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT00010H", exceptError: "Block TT length (0H) is malformed. Expecting 2 hexchars."},
	{header: "B0000P0TE00N0200KS04TT000101", exceptError: "Block TT length does not include block ID and length."},
	{header: "B0000P0TE00N0200KS04TT00011F", exceptError: "Block TT data is malformed. Received 0/23. Block data: ''"},
	{header: "B0000P0TE00N0100**04", exceptError: "Block ID (**) is invalid. Expecting 2 alphanumeric characters."},
	{header: "B0000P0TE00N0200KS0600??04", exceptError: "Block ID (??) is invalid. Expecting 2 alphanumeric characters."},
	{header: "B0000P0TE00N0100KS05\x03", exceptError: "Block KS data is invalid. Expecting ASCII printable characters. Data: '\x03'"},
	{header: "B0000P0TE00N0200KS04TT05\xFF", exceptError: "Block TT data is invalid. Expecting ASCII printable characters. Data: '\xFF'"},
}

func Test_header_block_load_exceptions(t *testing.T) {
	//for _, item := range InitialHeaderErrorSequence {
	//	h := NewHeader("", "", "", "", "", "")
	//	_, err := h.Load(item.header)
	//	assert.IsType(t, &HeaderError{}, err)
	//	if headerErr, ok := err.(*HeaderError); ok {
	//		assert.Contains(t, item.exceptError, headerErr.message)
	//	}
	//}
	assert.Equal(t, 1, 2)
}
func Test_header_block_dump_exception_block_too_large(t *testing.T) {
	//h := NewHeader("", "", "", "", "", "")
	//tr31Str := "B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	//_, err := h.Load(item.header)
	assert.Equal(t, 1, 2)
}
func Test_header_block_dump_exception_too_many_blocks(t *testing.T) {
	assert.Equal(t, 1, 2)
}

type TestCaseHeaderParam struct {
	versionID     string
	keyUsage      string
	algorithm     string
	modeOfUse     string
	versionNum    string
	exportability string
	expectedError string
}

func validateHeader(versionID, keyUsage, algorithm, modeOfUse, versionNum, exportability string) string {
	_ = NewHeader(versionID, keyUsage, algorithm, modeOfUse, versionNum, exportability)
	return ""
}

//func Test_header_attributes_exceptions(t *testing.T) {
//	testCases := []TestCaseHeaderParam{
//		{"_", "P0", "T", "E", "00", "N", "Version ID (_) is not supported."},
//		{"B0", "P0", "T", "E", "00", "N", "Version ID (B0) is not supported."},
//		{"", "P0", "T", "E", "00", "N", "Version ID () is not supported."},
//		{"B", "P_", "T", "E", "00", "N", "Key usage (P_) is invalid."},
//		{"B", "P", "T", "E", "00", "N", "Key usage (P) is invalid."},
//		{"B", "P00", "T", "E", "00", "N", "Key usage (P00) is invalid."},
//		{"B", "P0", "", "E", "00", "N", "Algorithm () is invalid."},
//		{"B", "P0", "_", "E", "00", "N", "Algorithm (_) is invalid."},
//		{"B", "P0", "T0", "E", "00", "N", "Algorithm (T0) is invalid."},
//		{"B", "P0", "T", "_", "00", "N", "Mode of use (_) is invalid."},
//		{"B", "P0", "T", "", "00", "N", "Mode of use () is invalid."},
//		{"B", "P0", "T", "EE", "00", "N", "Mode of use (EE) is invalid."},
//		{"B", "P0", "T", "E", "0", "N", "Version number (0) is invalid."},
//		{"B", "P0", "T", "E", "000", "N", "Version number (000) is invalid."},
//		{"B", "P0", "T", "E", "0_", "N", "Version number (0_) is invalid."},
//		{"B", "P0", "T", "E", "00", "", "Exportability () is invalid."},
//		{"B", "P0", "T", "E", "00", "NN", "Exportability (NN) is invalid."},
//		{"B", "P0", "T", "E", "00", "_", "Exportability (_) is invalid."},
//	}
//
//	for _, tc := range testCases {
//		t.Run(tc.versionID, func(t *testing.T) {
//			// Validate header using the test case inputs
//			actualError := validateHeader(tc.versionID, tc.keyUsage, tc.algorithm, tc.modeOfUse, tc.versionNum, tc.exportability)
//			assert.Equal(t, tc.expectedError, actualError)
//		})
//	}
//}

func sanityCheck(kbpk, key []byte, header *Header) error {
	kb, _ := NewKeyBlock(kbpk, header)
	rawKb, _ := kb.Wrap(key, nil)

	// Test if unwrap after wrap returns the original key
	decKey, _ := kb.Unwrap(rawKb)
	if string(key) != string(decKey) {
		return fmt.Errorf("unwrap failed: key mismatch after wrap")
	}

	// Create another KeyBlock instance to test with only kbpk
	kb2, _ := NewKeyBlock(kbpk, NewHeader("", "", "", "", "", ""))
	decKey2, _ := kb2.Unwrap(rawKb)
	if string(key) != string(decKey2) {
		return fmt.Errorf("unwrap failed: key mismatch after wrap (second instance)")
	}

	return nil
}

func Test_kb_sanity(t *testing.T) {
	tests := []struct {
		versionID string
		kbpk      []byte
	}{
		{"A", append(bytes.Repeat([]byte("A"), 8), append(bytes.Repeat([]byte("B"), 8), bytes.Repeat([]byte("C"), 8)...)...)},
		{"A", append(bytes.Repeat([]byte("A"), 8), bytes.Repeat([]byte("B"), 8)...)},
		{"A", bytes.Repeat([]byte("A"), 8)},
		{"B", append(bytes.Repeat([]byte("A"), 8), append(bytes.Repeat([]byte("B"), 8), bytes.Repeat([]byte("C"), 8)...)...)},
		{"B", append(bytes.Repeat([]byte("A"), 8), bytes.Repeat([]byte("B"), 8)...)},
		{"C", append(bytes.Repeat([]byte("A"), 8), append(bytes.Repeat([]byte("B"), 8), bytes.Repeat([]byte("C"), 8)...)...)},
		{"C", append(bytes.Repeat([]byte("A"), 8), bytes.Repeat([]byte("B"), 8)...)},
		{"C", bytes.Repeat([]byte("A"), 8)},
		{"D", append(bytes.Repeat([]byte("A"), 16), append(bytes.Repeat([]byte("B"), 8), bytes.Repeat([]byte("C"), 8)...)...)},
		{"D", append(bytes.Repeat([]byte("A"), 16), bytes.Repeat([]byte("B"), 8)...)},
		{"D", bytes.Repeat([]byte("A"), 16)},
	}

	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.versionID, func(t *testing.T) {
			h := NewHeader(tt.versionID, "P0", "T", "E", "00", "N")
			//keyLens := []int{0, 1, 8, 16, 24, 32, 99, 999}
			keyLens := []int{24}
			for _, keyLen := range keyLens {
				err := sanityCheck(tt.kbpk, urandom(keyLen), h)
				assert.Equal(t, nil, err)
			}
		})
	}
}
func Test_kb_known_values(t *testing.T) {
	testCases := []struct {
		kbpk string
		key  string
		kb   string
	}{
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "B0096M3TC00E0000B6CD513680EF255FC0DC590726FD0129A7CF6602E7F271631AB4EE7350642F11181AF4CC12F12FD9"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "C0088M3TC00E0000A53CF172FE6562E7FDD5E6482E8925DA46F7FFE4D1BAD49EB33A9EDBB96A8A8D39F13A31"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "A0088M3TC00E0000BE8AE894906D0B8F6FF555573A3907DC37FF13B12CE1CB8A97A97C8414AE1A8FF9183122"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "B0096M3TC00E0000D578DACC2286C7D10F20DEA88799CA8A2F44E0CC21226A2158D5DC8FD5C78E621327DA956C678808"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "C0088M3TC00E00009BC6306FC31891BF87B3148463627B1D68C603D9FAB9074E4A0D2E78D40B29905A826F5C"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "B0096M3TC00E0000C7C6FE86A5DE769C20DCA238C52341378B484D544A9764D43963C3B2824AE56C2D07A565DD3AB342"},
		{"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "C0088M3TC00E000091FA4978279FD9C218BDCBE9CC62F11A182F828406B67AC61B5573748FCF348FD59FA93A"},
		{"89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "A0072P0TE00E0000F5161ED902807AF26F1D62263644BD24192FDB3193C730301CEE8701"},
		{"DD7515F2BFC17F85CE48F3CA25CB21F6", "3F419E1CB7079442AA37474C2EFBF8B8", "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E"},
		{"B8ED59E0A279A295E9F5ED7944FD06B9", "EDB380DD340BC2620247D445F5B8D678", "C0096B0TX12S0100KS1800604B120F9292800000BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D60989015D02155C"},
		{"1D22BF32387C600AD97F9B97A51311AC", "E8BC63E5479455E26577F715D587FE68", "B0104B0TX12S0100KS1800604B120F9292800000BB68BE8680A400D9191AD4ECE45B6E6C0D21C4738A52190E248719E24B433627"},
		{"89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "A0088P0TE00E00007DD4DD9566DC0E2F956DCAC0FDE9153159539373E9D82D3CD4AFD305A7EF1BA67FE03712"},
		{"89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "B0120P0TE12E0100KS1800604B120F9292800000E6E28F097CB0350B2EB2DF520947F779FA34D9759CEE7E0DEEACF8353DB778D47FA4EC20DA3A9754"},
		{"B8ED59E0A279A295E9F5ED7944FD06B9", "F039121BEC83D26B169BDCD5B22AAF8F", "A0112P0TE12E0200KS1400604B120F929280PB047A1BB737854CD7AF58A8A1E4506A942277EDA76EBA6BA228AF62ADDA3AD8799E8B2C8CD7"},
	}

	for _, tt := range testCases {
		t.Run(tt.kbpk, func(t *testing.T) {
			kbpkBytes, err := hex.DecodeString(tt.kbpk)
			if err != nil {
				fmt.Println("Error decoding kbpk:", err)
				return
			}

			keyBytes, err := hex.DecodeString(tt.key)
			if err != nil {
				fmt.Println("Error decoding key:", err)
				return
			}
			block, _ := NewKeyBlock(kbpkBytes, nil)
			resultKB, _ := block.Unwrap(tt.kb)
			assert.Equal(t, keyBytes, resultKB)
		})
	}
}
func Test_kb_init_with_raw_header(t *testing.T) {
	data := []byte("E")
	repeatedData := bytes.Repeat(data, 16)
	block, _ := NewKeyBlock(repeatedData, "B0000P0TE00N0000xxxxxxxx")
	assert.Equal(t, "B", block.header.VersionID)
	assert.Equal(t, "P0", block.header.KeyUsage)
	assert.Equal(t, "T", block.header.Algorithm)
	assert.Equal(t, "E", block.header.ModeOfUse)
	assert.Equal(t, "N", block.header.Exportability)
	assert.Equal(t, "00", block.header.Reserved)
	assert.Equal(t, 0, len(block.header.Blocks._blocks))
}

func Test_kb_init_with_raw_header_blocks(t *testing.T) {
	data := []byte("E")
	repeatedData := bytes.Repeat(data, 16)
	block, _ := NewKeyBlock(repeatedData, "B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx")
	assert.Equal(t, "B", block.header.VersionID)
	assert.Equal(t, "P0", block.header.KeyUsage)
	assert.Equal(t, "T", block.header.Algorithm)
	assert.Equal(t, "E", block.header.ModeOfUse)
	assert.Equal(t, "N", block.header.Exportability)
	assert.Equal(t, "00", block.header.Reserved)
	assert.Equal(t, 1, len(block.header.Blocks._blocks))
	assert.Equal(t, "00604B120F9292800000", block.header.Blocks._blocks["KS"])
}

//# fmt: off
//@pytest.mark.parametrize(
//["kbpk_len", "kb", "error"],
//[
//(16, "B0040P0TE00N0000", "Key block header length (40) doesn't match input data length (16)."),
//(16, "BX040P0TE00N0000", "Key block header length (X040) is malformed. Expecting 4 digits."),
//
//(16, "A0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version A."),
//(16, "B0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version B."),
//(16, "C0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version C."),
//(16, "D0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 16 for key block version D."),
//
//(16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '9AA5BBAX'"),
//(16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '468910379AA5BBAX'"),
//(16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '9AA5BBAX'"),
//(16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6B89B8F5C30BDD3A946205FDF791C3548EX", "Key block MAC must be valid hexchars. MAC: '9B8F5C30BDD3A946205FDF791C3548EX'"),
//
//(16, "A0024M3TC00E0100TT04BBA6", "Key block MAC is malformed. Received 4 bytes MAC. Expecting 8 bytes for key block version A. MAC: 'BBA6'"),
//(16, "B0024M3TC00E00009AA5BBA6", "Key block MAC is malformed. Received 8 bytes MAC. Expecting 16 bytes for key block version B. MAC: '9AA5BBA6'"),
//(16, "C0024M3TC00E0100TT04BBA6", "Key block MAC is malformed. Received 4 bytes MAC. Expecting 8 bytes for key block version C. MAC: 'BBA6'"),
//(16, "D0032P0AE00E0000205FDF791C3548EC", "Key block MAC is malformed. Received 16 bytes MAC. Expecting 32 bytes for key block version D. MAC: '205FDF791C3548EC'"),
//
//(16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"),
//(16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X468910379AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X'"),
//(16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"),
//(16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6BX9B8F5C30BDD3A946205FDF791C3548EC", "Encrypted key must be valid hexchars. Key data: 'DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6BX'"),
//
//(16, "A0024M3TC00E00009AA5BBA6", "Encrypted key is malformed. Key data: ''"),
//(16, "B0032M3TC00E0000FFFFFFFF9AA5BBA6", "Encrypted key is malformed. Key data: ''"),
//(16, "C0024M3TC00E00009AA5BBA6", "Encrypted key is malformed. Key data: ''"),
//(16, "D0048P0AE00E00009B8F5C30BDD3A946205FDF791C3548EC", "Encrypted key is malformed. Key data: ''"),
//
//(16, "A0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC doesn't match generated MAC."),
//(16, "B0064M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFFFFFFFF9AA5BBA6", "Key block MAC doesn't match generated MAC."),
//(16, "C0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC doesn't match generated MAC."),
//(16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6B89B8F5C30BDD3A946205FDF791C3548E4", "Key block MAC doesn't match generated MAC."),
//
//(7,  "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be Single, Double or Triple DES for key block version A."),
//(8,  "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (8) must be Double or Triple DES for key block version B."),
//(7,  "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be Single, Double or Triple DES for key block version C."),
//(19, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6B89B8F5C30BDD3A946205FDF791C3548E4", "KBPK length (19) must be AES-128, AES-192 or AES-256 for key block version D."),
//
//# These keys have length set to 3 bits And key lengths that do not add up to a byte are not supported.
//# KBPK must be b"E"*16.
//(16, "A0056M3TC00E0000C6F4C83842160CBA48D98A1218862857124FAF46", "Decrypted key is invalid."),
//(16, "B0064M3TC00E0000F74E0A3502C5CEE07342D5DE9E72135E4A81944F80691F0F", "Decrypted key is invalid."),
//(16, "C0056M3TC00E0000F71573EB7441BB50A5C4511893AFB37B5B95A4AD", "Decrypted key is invalid."),
//(16, "D0080M3TC00E000007E81A7F29A870D4A0CD5AB27E9FEC4A8863E879B11EA3A0ADA406AD26D35B2F", "Decrypted key is invalid."),
//
//# DES key length is set to 128 bits while the key is 64 bits. KBPK must be b"E"*16.
//# AES key length is set to 256 bits while the key is 128 bits. KBPK must be b"E"*16.
//(16, "A0056M3TC00E0000EF14FD71CFCDCE0630AD5C1CDE0041DCF95CF1D0", "Decrypted key is malformed."),
//(16, "B0064M3TC00E00000398DC96A5DDB0EF61E26F8935173BD478DF9484050A672A", "Decrypted key is malformed."),
//(16, "C0056M3TC00E000001235EC22408B6CE866746FF992B8707FD7A26D2", "Decrypted key is malformed."),
//(16, "D0112P0AE00E00000DC02E4C2B63120403CC732FB1B17E6D44138E7C341AE7368DEAD6FB4673F25ECFD803F1101F701A7FE8BD3516D3D1BF", "Decrypted key is malformed."),
//],
//)
