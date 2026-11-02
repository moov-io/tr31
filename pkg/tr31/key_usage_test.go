package tr31

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyUsageConstants(t *testing.T) {
	// The two codes most often confused: a BDK is B0, the key a terminal
	// receives is B1, and I0 is an IV, not an IPEK.
	assert.Equal(t, "B0", KEY_USAGE_BDK)
	assert.Equal(t, "B1", KEY_USAGE_INITIAL_DUKPT_KEY)
	assert.Equal(t, "I0", KEY_USAGE_INITIALIZATION_VECTOR)
	assert.Equal(t, "D0", KEY_USAGE_DATA_ENCRYPTION)
	assert.Equal(t, "P0", KEY_USAGE_PIN_ENCRYPTION)
	assert.Equal(t, "K1", KEY_USAGE_KEY_BLOCK_PROTECTION)
	assert.Equal(t, "X", MODE_OF_USE_DERIVE)
	assert.Equal(t, "N", MODE_OF_USE_NO_RESTRICTIONS)

	// Every constant is accepted by NewHeader.
	for usage := range allowedModesOfUse {
		_, err := NewHeader(TR31_VERSION_D, usage, ENC_ALGORITHM_AES, allowedModesOfUse[usage][0], "00", "N")
		require.NoError(t, err, usage)
	}
}

func TestValidateKeyUsageModeOfUse(t *testing.T) {
	tests := []struct {
		usage, mode string
		valid       bool
	}{
		// Derivation keys (B0, B1, E0-E6) only derive: X, and not N.
		{KEY_USAGE_INITIAL_DUKPT_KEY, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_BDK, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_INITIAL_DUKPT_KEY, MODE_OF_USE_ENCRYPT, false},
		{KEY_USAGE_INITIAL_DUKPT_KEY, MODE_OF_USE_NO_RESTRICTIONS, false},
		{KEY_USAGE_BDK, MODE_OF_USE_NO_RESTRICTIONS, false},
		{KEY_USAGE_BDK, MODE_OF_USE_ENCRYPT_DECRYPT, false},
		// A base key variant key only creates variants.
		{KEY_USAGE_BASE_KEY_VARIANT, MODE_OF_USE_CREATE_VARIANTS, true},
		{KEY_USAGE_BASE_KEY_VARIANT, MODE_OF_USE_DERIVE, false},
		// Encryption, wrapping and PIN keys: B, D, E.
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_ENCRYPT, true},
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_DECRYPT, true},
		{KEY_USAGE_PIN_ENCRYPTION, MODE_OF_USE_ENCRYPT_DECRYPT, true},
		{KEY_USAGE_TR34_ASYMMETRIC, MODE_OF_USE_ENCRYPT, true},
		{KEY_USAGE_TR34_ASYMMETRIC, MODE_OF_USE_DERIVE, false},
		{KEY_USAGE_KEY_BLOCK_PROTECTION, MODE_OF_USE_NO_RESTRICTIONS, false},
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_DERIVE, false},
		{KEY_USAGE_PIN_ENCRYPTION, MODE_OF_USE_GENERATE_VERIFY, false},
		// K3 also derives.
		{KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT, MODE_OF_USE_ENCRYPT_DECRYPT, true},
		// MAC, card verification and PIN verification keys: C, G, V.
		{KEY_USAGE_MAC_CMAC, MODE_OF_USE_GENERATE_VERIFY, true},
		{KEY_USAGE_PIN_VERIFICATION_VISA_PVV, MODE_OF_USE_VERIFY, true},
		{KEY_USAGE_CARD_VERIFICATION, MODE_OF_USE_GENERATE, true},
		{KEY_USAGE_MAC_ISO9797_1_ALG6, MODE_OF_USE_GENERATE_VERIFY, true},
		{KEY_USAGE_MAC_HMAC, MODE_OF_USE_ENCRYPT, false},
		// Signature keys: S, V; S2 also T, B, D, E.
		{KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE, MODE_OF_USE_SIGN, true},
		{KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE, MODE_OF_USE_SIGN_DECRYPT, false},
		{KEY_USAGE_ASYMMETRIC_NON_X924, MODE_OF_USE_SIGN_DECRYPT, true},
		// An IV is not a key: N only.
		{KEY_USAGE_INITIALIZATION_VECTOR, MODE_OF_USE_NO_RESTRICTIONS, true},
		{KEY_USAGE_INITIALIZATION_VECTOR, MODE_OF_USE_ENCRYPT, false},
		// Usages Table 6 does not define are not checked.
		{KEY_USAGE_KEY_DERIVATION, MODE_OF_USE_NO_RESTRICTIONS, true},
		{"10", MODE_OF_USE_ENCRYPT, true},
		{"Z9", MODE_OF_USE_ENCRYPT, true},
	}
	for _, tt := range tests {
		t.Run(tt.usage+"/"+tt.mode, func(t *testing.T) {
			err := ValidateKeyUsageModeOfUse(tt.usage, tt.mode)
			if tt.valid {
				require.NoError(t, err)
				return
			}
			var herr *HeaderError
			require.True(t, errors.As(err, &herr), "want *HeaderError, got %v", err)
			assert.Contains(t, herr.Message, tt.usage)
		})
	}
}

func TestHeader_ValidateKeyUsageModeOfUse(t *testing.T) {
	// NewHeader still accepts a mismatched header; validation is opt-in.
	h, err := NewHeader(TR31_VERSION_D, KEY_USAGE_INITIAL_DUKPT_KEY, ENC_ALGORITHM_AES, MODE_OF_USE_ENCRYPT, "00", "N")
	require.NoError(t, err)
	assert.Error(t, h.ValidateKeyUsageModeOfUse())

	h, err = NewHeader(TR31_VERSION_D, KEY_USAGE_INITIAL_DUKPT_KEY, ENC_ALGORITHM_AES, MODE_OF_USE_DERIVE, "00", "N")
	require.NoError(t, err)
	assert.NoError(t, h.ValidateKeyUsageModeOfUse())

	// It also works on a header loaded from an existing key block.
	loaded := &Header{}
	_, err = loaded.Load("D0016B1AX00N0000")
	require.NoError(t, err)
	assert.NoError(t, loaded.ValidateKeyUsageModeOfUse())
}

// TestAllowedModesOfUseMatchesTR31Table6 pins the check to ASC X9 TR 31-2018,
// Annex A, Table 6, written out row by row independently of how the code
// groups usages, so an edit to the grouped table that drifts from the
// standard fails here.
func TestAllowedModesOfUseMatchesTR31Table6(t *testing.T) {
	table6 := map[string]string{
		"B0": "X", "B1": "X", "B2": "Y",
		"C0": "CGV",
		"D0": "BDE", "D1": "BDE", "D2": "BDE",
		"E0": "X", "E1": "X", "E2": "X", "E3": "X", "E4": "X", "E5": "X", "E6": "X",
		"I0": "N",
		"K0": "BDE", "K1": "BDE", "K2": "BDE", "K3": "BDEX",
		"M0": "CGV", "M1": "CGV", "M2": "CGV", "M3": "CGV", "M4": "CGV",
		"M5": "CGV", "M6": "CGV", "M7": "CGV", "M8": "CGV",
		"P0": "BDE",
		"S0": "SV", "S1": "SV", "S2": "SVTBDE",
		"V0": "CGV", "V1": "CGV", "V2": "CGV", "V3": "CGV", "V4": "CGV",
	}
	require.Len(t, allowedModesOfUse, len(table6))
	for usage, modes := range table6 {
		got, ok := allowedModesOfUse[usage]
		require.True(t, ok, "Table 6 usage %s has no rule", usage)
		assert.ElementsMatch(t, strings.Split(modes, ""), got, "modes for %s", usage)
	}
}
