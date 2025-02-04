package encryption

import (
	"bytes"
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
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 0)
	assert.Equal(t, "B0016P0TE00N0000", h.String())
}
func TestHeaderBlocksDict(t *testing.T) {
	h := NewHeader("B", "P0", "T", "E", "", "")
	h.blocks._blocks["KS"] = "ABCD"

	if len(h.blocks._blocks) != 1 {
		t.Errorf("Expected 1 block, got %d", len(h.blocks._blocks))
	}
	if h.blocks._blocks["KS"] != "ABCD" {
		t.Errorf("Expected block 'KS' to be 'ABCD', got '%s'", h.blocks._blocks["KS"])
	}
	if _, exists := h.blocks._blocks["KS"]; !exists {
		t.Error("Expected 'KS' to exist in blocks")
	}
	if repr := fmt.Sprintf("%v", h.blocks._blocks); repr != "map[KS:ABCD]" {
		t.Errorf("Expected repr 'map[KS:ABCD]', got '%s'", repr)
	}

	delete(h.blocks._blocks, "KS")
	if len(h.blocks._blocks) != 0 {
		t.Errorf("Expected 0 blocks after deletion, got %d", len(h.blocks._blocks))
	}
	if _, exists := h.blocks._blocks["KS"]; exists {
		t.Error("Expected 'KS' to be deleted from blocks")
	}
	if repr := fmt.Sprintf("%v", h.blocks._blocks); repr != "map[]" {
		t.Errorf("Expected repr 'map[]', got '%s'", repr)
	}
}

// TestHeaderLoadOptionalDes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalDes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292800000", h.blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0100KS1800604B120F9292800000", h.String())
}

// TestHeaderLoadOptionalAes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalAes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292800000", h.blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1800604B120F9292800000PB080000", h.String())
}

// TestHeaderLoadOptionalWithBadCountDes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalWithBadCountDes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0000KS1800604B120F9292800000"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 16, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 0)
	assert.Equal(t, "B0016P0TE00N0000", h.String())
}

// TestHeaderLoadOptionalWithBadCountAES tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalWithBadCountAES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0000KS1800604B120F9292800000"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 16, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 0)
	assert.Equal(t, "D0016P0TE00N0000", h.String())

}

// TestHeaderLoadOptionalPaddedDES tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalPaddedDES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS1200604B120F9292PB0600"
	length, _ := h.Load(tr31Str)
	assert.Equal(t, 40, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0200KS1200604B120F9292PB0600", h.String())
}
func TestHeaderLoadOptionalPaddedAES(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS1200604B120F9292PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 40, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1200604B120F9292PB0E0000000000", h.String())
}
func Test_header_load_optional_256_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS0002010A" + strings.Repeat("P", 256) + "PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 288, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, strings.Repeat("P", 256), h.blocks._blocks["KS"])
	assert.Equal(t, "B0288P0TE00N0200KS0002010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_256_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS0002010A" + strings.Repeat("P", 256) + "PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 288, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, strings.Repeat("P", 256), h.blocks._blocks["KS"])
	assert.Equal(t, "D0288P0TE00N0200KS0002010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_extended_length_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0200KS00011600604B120F9292PB0A000000"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 48, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.blocks._blocks["KS"])
	assert.Equal(t, "B0040P0TE00N0200KS1200604B120F9292PB0600", h.String())
}
func Test_header_load_optional_extended_length_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0200KS00011600604B120F9292PB0A000000"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 48, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 1)
	assert.Equal(t, "00604B120F9292", h.blocks._blocks["KS"])
	assert.Equal(t, "D0048P0TE00N0200KS1200604B120F9292PB0E0000000000", h.String())
}
func Test_header_load_optional_multiple_des(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 56, length)
	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 3)
	assert.Equal(t, "00604B120F9292800000", h.blocks._blocks["KS"])
	assert.Equal(t, "", h.blocks._blocks["T1"])
	assert.Equal(t, "00", h.blocks._blocks["T2"])
	assert.Equal(t, "B0056P0TE00N0400KS1800604B120F9292800000T104T20600PB0600", h.String())
}
func Test_header_load_optional_multiple_aes(t *testing.T) {
	h := NewHeader("", "", "", "", "", "")
	tr31Str := "D0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	length, _ := h.Load(tr31Str)

	assert.Equal(t, 56, length)
	assert.Equal(t, "D", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 3)
	assert.Equal(t, "00604B120F9292800000", h.blocks._blocks["KS"])
	assert.Equal(t, "", h.blocks._blocks["T1"])
	assert.Equal(t, "00", h.blocks._blocks["T2"])
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

	assert.Equal(t, "B", h.versionID)
	assert.Equal(t, "P0", h.keyUsage)
	assert.Equal(t, "T", h.algorithm)
	assert.Equal(t, "E", h.modeOfUse)
	assert.Equal(t, "N", h.exportability)
	assert.Equal(t, "00", h.reserved)
	assert.Len(t, h.blocks._blocks, 0)
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

func Test_header_attributes_exceptions(t *testing.T) {
	testCases := []TestCaseHeaderParam{
		{"_", "P0", "T", "E", "00", "N", "Version ID (_) is not supported."},
		{"B0", "P0", "T", "E", "00", "N", "Version ID (B0) is not supported."},
		{"", "P0", "T", "E", "00", "N", "Version ID () is not supported."},
		{"B", "P_", "T", "E", "00", "N", "Key usage (P_) is invalid."},
		{"B", "P", "T", "E", "00", "N", "Key usage (P) is invalid."},
		{"B", "P00", "T", "E", "00", "N", "Key usage (P00) is invalid."},
		{"B", "P0", "", "E", "00", "N", "Algorithm () is invalid."},
		{"B", "P0", "_", "E", "00", "N", "Algorithm (_) is invalid."},
		{"B", "P0", "T0", "E", "00", "N", "Algorithm (T0) is invalid."},
		{"B", "P0", "T", "_", "00", "N", "Mode of use (_) is invalid."},
		{"B", "P0", "T", "", "00", "N", "Mode of use () is invalid."},
		{"B", "P0", "T", "EE", "00", "N", "Mode of use (EE) is invalid."},
		{"B", "P0", "T", "E", "0", "N", "Version number (0) is invalid."},
		{"B", "P0", "T", "E", "000", "N", "Version number (000) is invalid."},
		{"B", "P0", "T", "E", "0_", "N", "Version number (0_) is invalid."},
		{"B", "P0", "T", "E", "00", "", "Exportability () is invalid."},
		{"B", "P0", "T", "E", "00", "NN", "Exportability (NN) is invalid."},
		{"B", "P0", "T", "E", "00", "_", "Exportability (_) is invalid."},
	}

	for _, tc := range testCases {
		t.Run(tc.versionID, func(t *testing.T) {
			// Validate header using the test case inputs
			actualError := validateHeader(tc.versionID, tc.keyUsage, tc.algorithm, tc.modeOfUse, tc.versionNum, tc.exportability)
			assert.Equal(t, tc.expectedError, actualError)
		})
	}
}

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
		//{"A", append(bytes.Repeat([]byte("A"), 8), append(bytes.Repeat([]byte("B"), 8), bytes.Repeat([]byte("C"), 8)...)...)},
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
