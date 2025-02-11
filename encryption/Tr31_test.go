package encryption

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/moov-io/psec/pkg"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	h := DefaultHeader()
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
	assert.Equal(t, "D0064P0TE00N0400KS1800604B120F9292800000T104T20600PB0E0000000000", h.String())
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
		{"B0000P0TE00N0100KS00010", "Block KS length (0) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS00010H", "Block KS length (0H) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0100KS000101", "Block KS length does not include block ID and length."},
		{"B0000P0TE00N0100KS0001FF", "Block KS data is malformed. Received 0/247. Block data: ''"},
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
		{"B0000P0TE00N0200KS04TT00010", "Block TT length (0) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT00010H", "Block TT length (0H) is malformed. Expecting 2 hexchars."},
		{"B0000P0TE00N0200KS04TT000101", "Block TT length does not include block ID and length."},
		{"B0000P0TE00N0200KS04TT00011F", "Block TT data is malformed. Received 0/23. Block data: ''"},
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
				err := sanityCheck(tt.kbpk, urandom(keyLen), h)
				assert.Equal(t, nil, err)
			}
		})
	}
}
func Test_kb_know_values_with_python(t *testing.T) {
	kbpkBytes, err := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC")
	if kbpkBytes == nil || err != nil {
		fmt.Println("Error decoding kbpk:", err)
		return
	}
	keyBytes, err := hex.DecodeString("CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD")
	if err != nil {
		fmt.Println("Error decoding key:", err)
		return
	}
	kb := "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E"
	block, _ := NewKeyBlock(kbpkBytes, nil)
	resultKB, _ := block.Unwrap(kb)
	assert.Equal(t, true, pkg.CompareByte(keyBytes, resultKB))
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
			assert.Equal(t, true, pkg.CompareByte(keyBytes, resultKB))
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
		{16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"},
		{16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X468910379AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X'"},
		{16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"},
		{16, "D0112P0AE00E0000DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6BX9B8F5C30BDD3A946205FDF791C3548EC", "Encrypted key must be valid hexchars. Key data: 'DDF7B73888F22B757600010215895621B94A4E8DA57DD3E01BB66FF046A4E6BX'"},
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
