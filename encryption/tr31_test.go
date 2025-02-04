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
