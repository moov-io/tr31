package tr31

import (
	"errors"
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
		// Derivation keys derive.
		{KEY_USAGE_INITIAL_DUKPT_KEY, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_BDK, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_BDK, MODE_OF_USE_NO_RESTRICTIONS, true},
		{KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS, MODE_OF_USE_DERIVE, true},
		{KEY_USAGE_INITIAL_DUKPT_KEY, MODE_OF_USE_ENCRYPT, false},
		{KEY_USAGE_BDK, MODE_OF_USE_ENCRYPT_DECRYPT, false},
		// Encryption keys encrypt and/or decrypt.
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_ENCRYPT, true},
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_DECRYPT, true},
		{KEY_USAGE_PIN_ENCRYPTION, MODE_OF_USE_ENCRYPT_DECRYPT, true},
		{KEY_USAGE_KEY_BLOCK_PROTECTION, MODE_OF_USE_NO_RESTRICTIONS, true},
		{KEY_USAGE_DATA_ENCRYPTION, MODE_OF_USE_DERIVE, false},
		{KEY_USAGE_PIN_ENCRYPTION, MODE_OF_USE_GENERATE_VERIFY, false},
		// MAC and verification keys generate and/or verify.
		{KEY_USAGE_MAC_CMAC, MODE_OF_USE_GENERATE_VERIFY, true},
		{KEY_USAGE_PIN_VERIFICATION_VISA_PVV, MODE_OF_USE_VERIFY, true},
		{KEY_USAGE_CARD_VERIFICATION, MODE_OF_USE_GENERATE, true},
		{KEY_USAGE_MAC_HMAC, MODE_OF_USE_ENCRYPT, false},
		// Asymmetric keys have no "no restrictions" mode.
		{KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE, MODE_OF_USE_SIGN, true},
		{KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE, MODE_OF_USE_NO_RESTRICTIONS, false},
		{KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT, MODE_OF_USE_DERIVE, true},
		// Usages with no rule are not checked.
		{KEY_USAGE_INITIALIZATION_VECTOR, MODE_OF_USE_ENCRYPT, true},
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
