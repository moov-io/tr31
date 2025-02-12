package encryption

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_pad_iso_1(t *testing.T) {
	tests := []struct {
		data      string
		block_len int
		result    string
	}{
		{"1234", 8, "1234000000000000"},
		{"1234567890123456", 8, "1234567890123456"},
		{"1234", 0, "1234000000000000"},
		{"1234567890123456", 0, "1234567890123456"},
		{"1234", 4, "12340000"},
		{"12345678", 4, "12345678"},
		{"", 4, "00000000"},
	}

	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			macData, _ := hex.DecodeString(tt.data)
			result, _ := padISO1(macData, tt.block_len)
			assert.Equal(t, tt.result, hex.EncodeToString(result))
		})
	}
}
func Test_pad_iso_2(t *testing.T) {
	tests := []struct {
		data      string
		block_len int
		result    string
	}{
		{"1234", 8, "1234800000000000"},
		{"12345678901234", 8, "1234567890123480"},
		{"1234567890123456", 8, "12345678901234568000000000000000"},
		{"1234", 0, "1234800000000000"},
		{"12345678901234", 0, "1234567890123480"},
		{"1234567890123456", 0, "12345678901234568000000000000000"},
		{"1234", 4, "12348000"},
		{"123456", 4, "12345680"},
		{"12345678", 4, "1234567880000000"},
		{"", 4, "80000000"},
	}
	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			macData, _ := hex.DecodeString(tt.data)
			result, _ := padISO2(macData, tt.block_len)
			assert.Equal(t, tt.result, hex.EncodeToString(result))
		})
	}
}
func Test_pad_iso_3(t *testing.T) {
	tests := []struct {
		data      string
		block_len int
		result    string
	}{
		{"1234", 8, "00000000000000101234000000000000"},
		{"1234567890123456", 8, "00000000000000401234567890123456"},
		{"1234", 0, "00000000000000101234000000000000"},
		{"1234567890123456", 0, "00000000000000401234567890123456"},
		{"1234", 4, "0000001012340000"},
		{"12345678", 4, "0000002012345678"},
		{"", 4, "0000000000000000"},
	}
	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.data, func(t *testing.T) {
			macData, _ := hex.DecodeString(tt.data)
			result, _ := padISO3(macData, tt.block_len)
			assert.Equal(t, tt.result, hex.EncodeToString(result))
		})
	}
}
func Test_generate_cbc_mac_exception(t *testing.T) {
	key, _ := hex.DecodeString("AAAAAAAAAAAAAAAA")
	data, _ := hex.DecodeString("hello world")
	_, err := GenerateCBCMAC(key, data, 4, 0, DES)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Specify valid padding method: 1, 2 or 3.")
}
func Test_generate_cbc_mac(t *testing.T) {
	tests := []struct {
		padding int
		length  int
		result  string
	}{
		{1, 8, "e1cc69341d2cfc4c"},
		{2, 8, "90f11bd8938b260c"},
		{3, 8, "bfe523e5e49fbf69"},
		{1, 0, "e1cc69341d2cfc4c"},
		{2, 0, "90f11bd8938b260c"},
		{3, 0, "bfe523e5e49fbf69"},
		{1, 4, "e1cc6934"},
		{2, 4, "90f11bd8"},
		{3, 4, "bfe523e5"},
	}
	// Loop through each test case
	for _, tt := range tests {
		t.Run(tt.result, func(t *testing.T) {
			keyData, _ := hex.DecodeString("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB")
			data, _ := hex.DecodeString("hello world")
			encData, err := GenerateCBCMAC(keyData, data, tt.padding, tt.length, DES)
			assert.Nil(t, err)
			assert.Equal(t, tt.result, hex.EncodeToString(encData))
		})
	}
}
