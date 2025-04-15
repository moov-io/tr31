package tr31

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderLoad(t *testing.T) {
	h := DefaultHeader()
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

// TestHeaderLoadOptionalDes tests the Load method and the String method of the Header.
func TestHeaderLoadOptionalDes(t *testing.T) {
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
	tr31Str := "B0000P0TE00N0200KS0004010A" + strings.Repeat("P", 256) + "PB0600"
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
	assert.Equal(t, "B0288P0TE00N0200KS0004010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_256_aes(t *testing.T) {
	h := DefaultHeader()
	tr31Str := "D0000P0TE00N0200KS0004010A" + strings.Repeat("P", 256) + "PB0600"
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
	assert.Equal(t, "D0288P0TE00N0200KS0004010A"+strings.Repeat("P", 256)+"PB0600", h.String())
}
func Test_header_load_optional_extended_length_des(t *testing.T) {
	h := DefaultHeader()
	tr31Str := "B0000P0TE00N0200KS00021600604B120F9292PB0A000000"
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
	h := DefaultHeader()
	tr31Str := "D0000P0TE00N0200KS00021600604B120F9292PB0A000000"
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
	h := DefaultHeader()
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
}
func Test_header_load_optional_multiple_aes(t *testing.T) {
	h := DefaultHeader()
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
}
func Test_header_load_optional_reset(t *testing.T) {
	h := DefaultHeader()
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

type BlockrErrorItem struct {
	header      string
	exceptError string
}

func Test_header_block_load_exceptions(t *testing.T) {
	var testCases = []BlockrErrorItem{
		{"B0000P0TE00N0100", "Block ID () is malformed."},
		{"B0000P0TE00N0100K", "Block ID (K) is malformed."},
		{"B0000P0TE00N0100KS", "Block KS length () is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS1", "Block KS length (1) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS02", "Block KS length (02) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS071", "Block KS length (071) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS00", "Block KS length (00) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS001", "Block KS length (001) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS001S", "Block KS length of length (1S) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS0000", "Block KS length of length must not be 0."},
		{"B0000P0TE00N0100KS0001", "Block KS length () is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS00010", "Block KS length does not include block ID and length."},
		{"B0000P0TE00N0100KS00010H", "Block KS length does not include block ID and length."},
		{"B0000P0TE00N0100KS000101", "Block KS length does not include block ID and length."},
		{"B0000P0TE00N0100KS0001FF", "Block KS data is malformed. Received 1/8. Block data: 'F'"},
		{"B0000P0TE00N0200KS07000T", "Block ID (T) is malformed."},
		{"B0000P0TE00N0200KS0600TT", "Block TT length () is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS050TT1", "Block TT length (1) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT1X", "Block TT length (1X) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT03", "Block TT length (03) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT05", "Block TT length (05) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT00", "Block TT length (00) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT001", "Block TT length (001) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT001S", "Block TT length of length (1S) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT0000", "Block TT length of length must not be 0."},
		{"B0000P0TE00N0200KS04TT0001", "Block TT length () is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT00010", "Block TT length does not include block ID and length."},
		{"B0000P0TE00N0200KS04TT00010H", "Block TT length does not include block ID and length."},
		{"B0000P0TE00N0200KS04TT000101", "Block TT length does not include block ID and length."},
		{"B0000P0TE00N0200KS04TT00011F", "Block TT length does not include block ID and length."},
		{"B0000P0TE00N0100**04", "Block ID (**) is invalid. Expecting 2 alphanumeric characters."},
		{"B0000P0TE00N0200KS0600??04", "Block ID (??) is invalid. Expecting 2 alphanumeric characters."},
	}
	for _, tc := range testCases {
		t.Run(tc.header, func(t *testing.T) {
			h := DefaultHeader()
			_, err := h.Load(tc.header)
			assert.IsType(t, &HeaderError{}, err)
			if headerErr, ok := err.(*HeaderError); ok {
				assert.Contains(t, tc.exceptError, headerErr.Message)
			}
		})
	}
}
func Test_header_block_dump_exception_block_too_large(t *testing.T) {
	//h := NewHeader("", "", "", "", "", "")
	//tr31Str := "B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"
	//_, err := h.Load(item.header)
	assert.Equal(t, 1, 1)
}
func Test_header_block_dump_exception_too_many_blocks(t *testing.T) {
	assert.Equal(t, 1, 1)
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

func Test_header_attributes_exceptions(t *testing.T) {
	testCases := []TestCaseHeaderParam{
		//{"_", "P0", "T", "E", "00", "N", "Version ID (_) is not supported."},
		//{"B0", "P0", "T", "E", "00", "N", "Version ID (B0) is not supported."},
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
			_, actualError := NewHeader(tc.versionID, tc.keyUsage, tc.algorithm, tc.modeOfUse, tc.versionNum, tc.exportability)
			assert.IsType(t, &HeaderError{}, actualError)
			if headerErr, ok := actualError.(*HeaderError); ok {
				assert.Equal(t, tc.expectedError, headerErr.Message)
			}
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
	newHeader := DefaultHeader()
	kb2, _ := NewKeyBlock(kbpk, newHeader)
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
			h, _ := NewHeader(tt.versionID, "P0", "T", "E", "00", "N")
			//keyLens := []int{0, 1, 8, 16, 24, 32, 99, 999}
			keyLens := []int{24}
			for _, keyLen := range keyLens {
				err := sanityCheck(tt.kbpk, urandom(t, keyLen), h)
				assert.Equal(t, nil, err)
			}
		})
	}
}
func Test_kb_know_values_with_python(t *testing.T) {
	kbpkBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	if kbpkBytes == nil || err != nil {
		return
	}
	keyBytes, err := hex.DecodeString("CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD")
	if err != nil {
		return
	}
	kb := "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E"
	block, _ := NewKeyBlock(kbpkBytes, nil)
	resultKB, _ := block.Unwrap(kb)
	assert.Equal(t, true, CompareByte(keyBytes, resultKB))
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
				return
			}

			keyBytes, err := hex.DecodeString(tt.key)
			if err != nil {
				return
			}
			block, _ := NewKeyBlock(kbpkBytes, nil)
			resultKB, _ := block.Unwrap(tt.kb)
			assert.Equal(t, true, CompareByte(keyBytes, resultKB))
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
func intPtr(i int) *int {
	return &i
}

func Test_kb_masking_key_length(t *testing.T) {
	testCases := []struct {
		version_id     string
		algorithm      string
		key_len        int
		masked_key_len *int
		kb_len         int
	}{
		{"A", "D", 24, intPtr(24), 88},
		{"A", "D", 16, intPtr(24), 88},
		{"A", "D", 8, intPtr(24), 88},
		{"A", "D", 24, nil, 88},
		{"A", "D", 16, nil, 88},
		{"A", "D", 8, nil, 88},
		{"A", "D", 16, intPtr(16), 72},
		{"A", "D", 16, intPtr(8), 72},
		{"A", "D", 16, intPtr(0), 72},
		{"A", "D", 16, intPtr(-8), 72},
		{"A", "D", 8, intPtr(8), 56},
		{"A", "D", 8, intPtr(0), 56},

		{"B", "T", 24, intPtr(24), 96},
		{"B", "T", 16, intPtr(24), 96},
		{"B", "T", 8, intPtr(24), 96},
		{"B", "T", 24, nil, 96},
		{"B", "T", 16, nil, 96},
		{"B", "T", 8, nil, 96},
		{"B", "T", 16, intPtr(16), 80},
		{"B", "T", 16, intPtr(8), 80},
		{"B", "T", 16, intPtr(0), 80},
		{"B", "T", 16, intPtr(-8), 80},
		{"B", "T", 8, intPtr(8), 64},
		{"B", "T", 8, intPtr(0), 64},

		{"C", "T", 24, intPtr(24), 88},
		{"C", "T", 16, intPtr(24), 88},
		{"C", "T", 8, intPtr(24), 88},
		{"C", "T", 24, nil, 88},
		{"C", "T", 16, nil, 88},
		{"C", "T", 8, nil, 88},
		{"C", "T", 16, intPtr(16), 72},
		{"C", "T", 16, intPtr(8), 72},
		{"C", "T", 16, intPtr(0), 72},
		{"C", "T", 16, intPtr(-8), 72},
		{"C", "T", 8, intPtr(8), 56},
		{"C", "T", 8, intPtr(0), 56},

		{"D", "A", 32, intPtr(32), 144},
		{"D", "A", 24, intPtr(32), 144},
		{"D", "A", 16, intPtr(32), 144},
		{"D", "A", 32, nil, 144},
		{"D", "A", 24, nil, 144},
		{"D", "A", 16, nil, 144},
		{"D", "A", 24, intPtr(24), 112},
		{"D", "A", 24, intPtr(16), 112},
		{"D", "A", 24, intPtr(8), 112},
		{"D", "A", 24, intPtr(0), 112},
		{"D", "A", 24, intPtr(-1), 112},
		{"D", "A", 16, intPtr(16), 112},
		{"D", "A", 16, intPtr(8), 112},
		{"D", "A", 16, intPtr(0), 112},
		{"D", "A", 16, intPtr(-1), 112},

		{"D", "T", 24, intPtr(24), 112},
		{"D", "T", 16, intPtr(24), 112},
		{"D", "T", 8, intPtr(24), 112},
		{"D", "T", 24, nil, 112},
		{"D", "T", 16, nil, 112},
		{"D", "T", 8, nil, 112},
		{"D", "T", 16, intPtr(16), 112},
		{"D", "T", 16, intPtr(8), 112},
		{"D", "T", 16, intPtr(0), 112},
		{"D", "T", 16, intPtr(-8), 112},
		{"D", "T", 8, intPtr(8), 80},
		{"D", "T", 8, intPtr(0), 80},
	}
	for _, tt := range testCases {
		t.Run(tt.version_id, func(t *testing.T) {
			kbpkBytes := bytes.Repeat([]byte("E"), 24)
			keyBytes := bytes.Repeat([]byte("F"), tt.key_len)
			block, _ := NewKeyBlock(kbpkBytes, nil)
			block.header.SetVersionID(tt.version_id)
			block.header.SetAlgorithm(tt.algorithm)
			kb_s, _ := block.Wrap(keyBytes, tt.masked_key_len)
			assert.Equal(t, tt.kb_len, len(kb_s))
		})
	}
}

func Test_invalid_enctript_key_wrap(t *testing.T) {
	testCases := []struct {
		versionID     string
		kbpkLen       int
		keyLen        int
		expectedError string
	}{
		{"A", 7, 24, "KBPK length (7) must be Single, Double or Triple DES for key block version A."},
		{"B", 7, 24, "KBPK length (7) must be Double or Triple DES for key block version B."},
		{"C", 7, 24, "KBPK length (7) must be Single, Double or Triple DES for key block version C."},
		{"D", 17, 24, "KBPK length (17) must be AES-128, AES-192 or AES-256 for key block version D."},
	}

	for _, tt := range testCases {
		t.Run(tt.versionID, func(t *testing.T) {
			kbpkBytes := bytes.Repeat([]byte("E"), tt.kbpkLen)
			keyBytes := bytes.Repeat([]byte("F"), tt.kbpkLen)
			block, _ := NewKeyBlock(kbpkBytes, nil)
			block.header.SetVersionID(tt.versionID)
			_, actualError := block.Wrap(keyBytes, nil)
			assert.IsType(t, &KeyBlockError{}, actualError)
			if headerErr, ok := actualError.(*KeyBlockError); ok {
				assert.Equal(t, tt.expectedError, headerErr.Message)
			}
		})
	}
}
func Test_invalid_enctript_key_uwrap(t *testing.T) {
	test_cases := []struct {
		kbpk_len int
		kb       string
		error    string
	}{
		{16, "B0040P0TE00N0000", "Key block header length (40) doesn't match input data length (16)."},
		{16, "BX040P0TE00N0000", "Key block header length (X040) is malformed. Expecting 4 digits."},
		{16, "A0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version A."},
		{16, "B0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version B."},
		{16, "C0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8 for key block version C."},
		{16, "D0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 16 for key block version D."},
		{16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars."},
		{16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X468910379AA5BBA6", "Encrypted key must be valid hexchars."},
		{16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars."},
		{16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6BX9B8F5C30BDD3A946205FDF791C3548EC", "Encrypted key must be valid hexchars."},
		{16, "A0024M3TC00E00009AA5BBA6", "Key block MAC must be valid hexchars. MAC: '9AA5BBA6'"},
		{16, "B0032M3TC00E0000FFFFFFFF9AA5BBA6", "Key block MAC must be valid hexchars. MAC: 'FFFFFFFF9AA5BBA6'"},
		{16, "C0024M3TC00E00009AA5BBA6", "Key block MAC must be valid hexchars. MAC: '9AA5BBA6'"},
		{16, "D0048P0AE00E00009B8F5C30BDD3A946205FDF791C3548EC", "Key block MAC must be valid hexchars. MAC: '9B8F5C30BDD3A946205FDF791C3548EC'"},

		{16, "A0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC is not matched."},
		{16, "B0064M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFFFFFFFF9AA5BBA6", "Key block MAC is not matched."},
		{16, "C0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC is not matched."},
		{16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6B89B8F5C30BDD3A946205FDF791C3548E4", "Key block MAC is not matched."},

		{7, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be Single, Double or Triple DES for key block version A."},
		{8, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (8) must be Double or Triple DES for key block version B."},
		{7, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be Single, Double or Triple DES for key block version C."},
		{19, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6B89B8F5C30BDD3A946205FDF791C3548E4", "KBPK length (19) must be AES-128, AES-192 or AES-256 for key block version D."},

		{16, "A0056M3TC00E0000C6F4C83842160CBA48D98A1218862857124FAF46", "Decrypted key is invalid."},
		{16, "B0064M3TC00E0000F74E0A3502C5CEE07342D5DE9E72135E4A81944F80691F0F", "Decrypted key is invalid."},
		{16, "C0056M3TC00E0000F71573EB7441BB50A5C4511893AFB37B5B95A4AD", "Decrypted key is invalid."},
		{16, "D0080M3TC00E000007E81A7F29A870D4A0CD5AB27E9FEC4A8863E879B11EA3A0ADA406AD26D35B2F", "Decrypted key is invalid."},

		{16, "A0056M3TC00E0000EF14FD71CFCDCE0630AD5C1CDE0041DCF95CF1D0", "Decrypted key is malformed."},
		{16, "B0064M3TC00E00000398DC96A5DDB0EF61E26F8935173BD478DF9484050A672A", "Decrypted key is malformed."},
		{16, "C0056M3TC00E000001235EC22408B6CE866746FF992B8707FD7A26D2", "Decrypted key is malformed."},
		{16, "D0112P0AE00E00000DC02E4C2B63120403CC732FB1B17E6D44138E7C341AE7368DEAD6FB4673F25ECFD803F1101F701A7FE8BD3516D3D1BF", "Decrypted key is malformed."},
	}
	for _, tt := range test_cases {
		t.Run(tt.kb, func(t *testing.T) {
			kbpkBytes := bytes.Repeat([]byte("E"), tt.kbpk_len)
			block, _ := NewKeyBlock(kbpkBytes, nil)
			_, actualError := block.Unwrap(tt.kb)
			assert.IsType(t, &KeyBlockError{}, actualError)
			if headerErr, ok := actualError.(*KeyBlockError); ok {
				assert.Equal(t, tt.error, headerErr.Message)
			}
		})
	}
}
func Test_wrap_unwrap_functions(t *testing.T) {
	kbpk := []byte{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB}
	key := []byte{0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD}
	kblock, _ := NewKeyBlock(kbpk, nil)
	wrapData, _ := kblock.Wrap(key, nil)
	keyOut, _ := kblock.Unwrap(wrapData)
	assert.Equal(t, key, keyOut)
}
func Test_wrap_unwrap_header_functions(t *testing.T) {
	kbpk := []byte{0xEF, 0xEF, 0xEF, 0xEF, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF}
	key := []byte{0x55, 0x55, 0x55, 0x55, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0x55, 0x55, 0x55, 0x55, 0x55}
	kblock, _ := NewKeyBlock(kbpk, nil)
	wrapData, _ := kblock.Wrap(key, nil)
	keyOut, _ := kblock.Unwrap(wrapData)

	assert.Equal(t, key, keyOut)
}
func Test_Unwrap_Apple_Proximity(t *testing.T) {
	// Key Block Protection Key
	kbpk, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	// Key Block
	kb := "D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3"
	// Expected Key
	key, _ := hex.DecodeString("B9517FF24FD4C71833478D424C29751D")
	kblock, _ := NewKeyBlock(kbpk, nil)
	keyOut, err := kblock.Unwrap(kb)
	assert.Nil(t, err)
	assert.Equal(t, key, keyOut)
}
func Test_Unexpected_Input_Wrap(t *testing.T) {
	kbpk := []byte{}
	key := []byte{0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD}
	kblock, _ := NewKeyBlock(kbpk, nil)
	_, err := kblock.Wrap(key, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "KB is not supported", err.Error())
}

func Test_Unexpected_Input_UnWrap(t *testing.T) {
	kbpk := []byte{}
	kblock, _ := NewKeyBlock(kbpk, nil)
	_, err := kblock.Unwrap("D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3")
	assert.NotNil(t, err)
	assert.Equal(t, "KB is not supported", err.Error())
}

func Test_Unrwap_Optional_and_Cert_From_Spec(t *testing.T) {
	kbpk, _ := hex.DecodeString("FA36E44278DB3AB5F298F9F7DA8F1F88")
	tr31block := "D3776S0RS00N0400CT0004050000MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7ZKP1001D77F007724TS1320200818221218ZPB0D000000000A7C9F8FA80A4BA3555CA071503CE1A6133649BB18A5A9130492172CA4E7360C060379738A28503230BDB04EED4E9B209643867613F5090A0E0392C21EB74747795B397315AB5D1F49A33693533E73AC0BEDA172FF530BE986F5EC1C25F481F05A69DF8B33624E621AF35FFAEC06C2005F37872923EEBFF38182FB290BFBA2A9FF88AD36278625868FA38A0DC9A53E0202C4D1DEF3B9DACFD249DA85DE3CCF92A8E6C0F8CDF8DE5FD17331BE5D580F210CE4EA1B01F1A0BFD6EFF410A71661234AD363D4B60885F00358729900FF95D7C87D3DE6FB4C83B24C8C7BB5A2E3763E9CBA50A0E3A8C1AF908699952BCB6B038FEA9D13FDE08801DC0573E55B842219DBF6D5DA5F028C73793AA718D01DE93D85AE06E7E08DC94ADB4EAA51B6DDAEA3750D0B77467D2982AC96F3EB28889715CBB81C71E97A60E58D44977C1D8220A422E98E17ACEBF72A8A18D4E7FC1695F442860E6063E8BB6BFF2184F77E635C2F5A02DADE4897A3B1374145C3AD6DF06C0D556F5DE9454CF40C4FC8922DFE245F868E668F1DA5BE0079F9D1D1861CA4B5E6C782F296098C07CB43784D64D8B8557410E5BAFF59333A791FF030EB0661C0590A665B50A3A727217100C4550B2AD9C96C658D6731C09B55DFAE665952E2913A4E090F45DCEB45D6683C3FC15E3A4CA49C7F2E684B3580DB47A53E5BDB228FAD250C584548D5DEDBB45004B5E0E75C37ACE8167CC6D9574A74876718D2F42996622B8EC0B895FF7A6739E4CF64B7F03FABDFBC0A565CB3455736D2B4E2B64D6EC175A569F78DB7ACB331B00804279677F4BFD0C35CBF0A38D646AA9051961123E16075A06B6331A9A30601AF3FD6A89AD9924AE1D9EC2FE0FF3B3A1B3E3E13D09B08B80D91F9EDF51B2E6D8DABD0FEB6C5C1085A11FA6A98CE8CC09E36C8A24D981A74E140EF30912E8CDBBE2A0CBD52B40C72D1958F4BB2F49BCBABBD80116FEF21BC91D219EEAEDA4DC11692C624B0836C3137A3BEE4549DEAB750A9DD5ACA7E3F822084783CDFEEB765EBEB9E3CFF053E8B8D5A1F1854B8AFF6325F10B81C7627D0DA895B1D19FEEF0AE3F3E138E87C4ADDF0BA53CA40ED0D1452044600FF4838D710F6D03474C317AC306DD7DA169B6C918E999E3A50DA1A34DDFCA3899F4469B9E969C0BD144F04B2621AB9E9E18455D526844155309565DA9D1726CD3A7ACC5FEDEF30DED078547CED31CEF84A31A810FA966F303CB950ACC324AE54BFAB9A04FAD93C38CD6239D7FAD2C59A9B71171F5676DA8ED3A3FFB5287DF141C1F5CE972CA26857AD3039B82B625960A7859F19EF0E94F8C4680A33189870942139DDFA64D5095FA46EB49085DB99EFC9C6A3F3A290DB9592F8B76B017113F7D1FEFE52E70FE26574467257CFEEA6D3F2BBD1BAEDDDCE3468827568A78536DE78E7AC872247BDB120A55DDE16A3D0CFBB7D097AD7AD0FA2671390D8D532A3915F5B3163FF1EE23553D83A1109980859C420F754BC74ECD1449B9A60EA252D3F035D715BCBD491485261C51238926E290BD7F0617E90BD6AB8B46443B05C28D61F8BB897417926623AF91B499C661629795165EF56460850F1D4F9CE199C2B9E21F1884A4D14644DAE5FB963B880EC2FFF70021772D524289D068A24F0283C42F0B4779996D2CF60EE6E45C364E2547DB92361B3DBCEDBAA96B9F10A1AAA1AB23CDE1B75F3299D4544787A07F6A9F7127"
	kblock, _ := NewKeyBlock(kbpk, nil)

	privkey, err := kblock.Unwrap(tr31block)

	if assert.NoError(t, err) {
		assert.Equal(t, uint8(0x30), privkey[0])
		assert.Equal(t, "D", kblock.header.VersionID)
		assert.Equal(t, 3, len(kblock.header.GetBlocks()))
	}
}
