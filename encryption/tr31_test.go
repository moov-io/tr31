package encryption

import (
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
	for _, item := range InitialHeaderErrorSequence {
		h := NewHeader("", "", "", "", "", "")
		_, err := h.Load(item.header)
		assert.IsType(t, &HeaderError{}, err)
		if headerErr, ok := err.(*HeaderError); ok {
			assert.Contains(t, item.exceptError, headerErr.message)
		}
	}
}
