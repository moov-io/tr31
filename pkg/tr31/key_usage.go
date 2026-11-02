package tr31

import (
	"fmt"
	"strings"
)

// TR-31 key usage codes (header bytes 5-6), as assigned by ANSI X9.143.
//
// The key usage says what kind of key is in the block, and so what it may be
// used for. Passing these constants to NewHeader, rather than raw strings,
// makes the choice readable and harder to get wrong. Two easy mistakes:
//
//   - "B0" is a Base Derivation Key (BDK), the DUKPT master key. The key a
//     terminal receives, the IPEK, is an Initial DUKPT Key, "B1".
//   - "I0" is an Initialization Vector, not an IPEK.
//
// Only codes whose meaning is the same in every public reference we checked
// are defined here: the IBM CCA TR-31 documentation, AWS Payment Cryptography's
// key attributes, and the kabc TR-31 key block tool. X9.143 assigns more codes
// (and vendors add proprietary ones); NewHeader still accepts any
// two-character alphanumeric value, so a missing constant does not stop you
// from using a code.
const (
	// KEY_USAGE_BDK is a Base Derivation Key: the DUKPT master key that
	// initial keys are derived from (ANSI X9.24). It normally stays in the HSM.
	KEY_USAGE_BDK string = "B0"
	// KEY_USAGE_INITIAL_DUKPT_KEY is an Initial DUKPT Key (IK, or IPEK for
	// TDES DUKPT): the per-device key a terminal derives its transaction keys
	// from.
	KEY_USAGE_INITIAL_DUKPT_KEY string = "B1"
	// KEY_USAGE_KEY_DERIVATION is a key derivation key for derivations other
	// than ANSI X9.24 DUKPT.
	KEY_USAGE_KEY_DERIVATION string = "B3"
	// KEY_USAGE_CARD_VERIFICATION is a card verification key (CVK), for
	// CVV/CVC/CSC values.
	KEY_USAGE_CARD_VERIFICATION string = "C0"
	// KEY_USAGE_DATA_ENCRYPTION is a symmetric key for data encryption.
	KEY_USAGE_DATA_ENCRYPTION string = "D0"
	// KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION is an asymmetric key for data
	// encryption.
	KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION string = "D1"
	// KEY_USAGE_SENSITIVE_DATA_ENCRYPTION is a symmetric key for encrypting
	// sensitive data.
	KEY_USAGE_SENSITIVE_DATA_ENCRYPTION string = "D3"
	// KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS is an EMV/chip issuer master key for
	// application cryptograms.
	KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS string = "E0"
	// KEY_USAGE_EMV_MKEY_CONFIDENTIALITY is an EMV/chip issuer master key for
	// secure messaging confidentiality.
	KEY_USAGE_EMV_MKEY_CONFIDENTIALITY string = "E1"
	// KEY_USAGE_EMV_MKEY_INTEGRITY is an EMV/chip issuer master key for secure
	// messaging integrity.
	KEY_USAGE_EMV_MKEY_INTEGRITY string = "E2"
	// KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE is an EMV/chip issuer master key for
	// data authentication codes.
	KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE string = "E3"
	// KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS is an EMV/chip issuer master key for
	// dynamic numbers.
	KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS string = "E4"
	// KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION is an EMV/chip issuer master key
	// for card personalization.
	KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION string = "E5"
	// KEY_USAGE_EMV_MKEY_OTHER is an EMV/chip issuer master key for other uses.
	KEY_USAGE_EMV_MKEY_OTHER string = "E6"
	// KEY_USAGE_INITIALIZATION_VECTOR is an Initialization Vector (IV). It is
	// not an IPEK.
	KEY_USAGE_INITIALIZATION_VECTOR string = "I0"
	// KEY_USAGE_KEY_ENCRYPTION is a key encryption (key wrapping) key.
	KEY_USAGE_KEY_ENCRYPTION string = "K0"
	// KEY_USAGE_KEY_BLOCK_PROTECTION is a TR-31 key block protection key
	// (KBPK).
	KEY_USAGE_KEY_BLOCK_PROTECTION string = "K1"
	// KEY_USAGE_TR34_ASYMMETRIC is an asymmetric key for TR-34 key transport.
	KEY_USAGE_TR34_ASYMMETRIC string = "K2"
	// KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT is an asymmetric key for key
	// agreement (for example ECDH).
	KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT string = "K3"
	// KEY_USAGE_ISO20038_KEY_BLOCK_PROTECTION is an ISO 20038 key block
	// protection key.
	KEY_USAGE_ISO20038_KEY_BLOCK_PROTECTION string = "K4"
	// KEY_USAGE_MAC_ISO16609 is a MAC key for ISO 16609 MAC algorithm 1 (TDES).
	KEY_USAGE_MAC_ISO16609 string = "M0"
	// KEY_USAGE_MAC_ISO9797_1_ALG1 is a MAC key for ISO 9797-1 MAC algorithm 1.
	KEY_USAGE_MAC_ISO9797_1_ALG1 string = "M1"
	// KEY_USAGE_MAC_ISO9797_1_ALG3 is a MAC key for ISO 9797-1 MAC algorithm 3.
	KEY_USAGE_MAC_ISO9797_1_ALG3 string = "M3"
	// KEY_USAGE_MAC_CMAC is a MAC key for ISO 9797-1 MAC algorithm 5 (CMAC).
	KEY_USAGE_MAC_CMAC string = "M6"
	// KEY_USAGE_MAC_HMAC is an HMAC key.
	KEY_USAGE_MAC_HMAC string = "M7"
	// KEY_USAGE_PIN_ENCRYPTION is a PIN encryption key.
	KEY_USAGE_PIN_ENCRYPTION string = "P0"
	// KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE is an asymmetric key pair for
	// digital signatures.
	KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE string = "S0"
	// KEY_USAGE_PIN_VERIFICATION_OTHER is a PIN verification key for other
	// algorithms.
	KEY_USAGE_PIN_VERIFICATION_OTHER string = "V0"
	// KEY_USAGE_PIN_VERIFICATION_IBM3624 is a PIN verification key for the IBM
	// 3624 method.
	KEY_USAGE_PIN_VERIFICATION_IBM3624 string = "V1"
	// KEY_USAGE_PIN_VERIFICATION_VISA_PVV is a PIN verification key for the
	// Visa PVV method.
	KEY_USAGE_PIN_VERIFICATION_VISA_PVV string = "V2"
)

// TR-31 mode of use codes (header byte 8): how the key in the block may be
// used, within what its key usage allows.
const (
	// MODE_OF_USE_ENCRYPT_DECRYPT allows encrypt/decrypt and wrap/unwrap.
	MODE_OF_USE_ENCRYPT_DECRYPT string = "B"
	// MODE_OF_USE_GENERATE_VERIFY allows generating and verifying values
	// (MACs, card verification values, PIN verification values).
	MODE_OF_USE_GENERATE_VERIFY string = "C"
	// MODE_OF_USE_DECRYPT allows decrypt and unwrap only.
	MODE_OF_USE_DECRYPT string = "D"
	// MODE_OF_USE_ENCRYPT allows encrypt and wrap only.
	MODE_OF_USE_ENCRYPT string = "E"
	// MODE_OF_USE_GENERATE allows generating values only.
	MODE_OF_USE_GENERATE string = "G"
	// MODE_OF_USE_NO_RESTRICTIONS places no restriction beyond what the key
	// usage implies.
	MODE_OF_USE_NO_RESTRICTIONS string = "N"
	// MODE_OF_USE_SIGN allows creating signatures only.
	MODE_OF_USE_SIGN string = "S"
	// MODE_OF_USE_VERIFY allows verifying values or signatures only.
	MODE_OF_USE_VERIFY string = "V"
	// MODE_OF_USE_DERIVE allows deriving other keys.
	MODE_OF_USE_DERIVE string = "X"
)

// HeaderErrKeyUsageModeOfUse is the message for a key usage that the key's
// mode of use cannot apply to.
const HeaderErrKeyUsageModeOfUse string = "mode of use (%s) is not valid for key usage (%s); expected one of: %s"

// allowedModesOfUse lists, for the key usages it covers, the modes of use
// that may accompany them. A mode is listed when IBM CCA or AWS Payment
// Cryptography documents it for that usage; the families are:
//
//   - derivation keys (B0, B1, B3, E0-E6): derive, or no restrictions
//   - encryption, wrapping and PIN keys (D0, D3, K0, K1, K4, P0): encrypt
//     and/or decrypt, or no restrictions
//   - MAC, card verification and PIN verification keys (C0, M*, V*):
//     generate and/or verify, or no restrictions
//   - asymmetric keys (D1, K2, K3, S0): as documented, without "no restrictions"
//
// Usages not listed here, including I0, are not checked: the published
// references do not cover them consistently, so rejecting them would risk
// refusing valid key blocks. This is a guard against obviously wrong headers,
// not a full implementation of X9.143.
var allowedModesOfUse = func() map[string][]string {
	derive := []string{MODE_OF_USE_DERIVE, MODE_OF_USE_NO_RESTRICTIONS}
	encrypt := []string{MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT, MODE_OF_USE_NO_RESTRICTIONS}
	generateVerify := []string{MODE_OF_USE_GENERATE_VERIFY, MODE_OF_USE_GENERATE, MODE_OF_USE_VERIFY, MODE_OF_USE_NO_RESTRICTIONS}

	m := map[string][]string{
		KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION:   {MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT},
		KEY_USAGE_TR34_ASYMMETRIC:              {MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT, MODE_OF_USE_DERIVE},
		KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT:     {MODE_OF_USE_DERIVE},
		KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE: {MODE_OF_USE_SIGN, MODE_OF_USE_VERIFY},
	}
	for _, u := range []string{
		KEY_USAGE_BDK, KEY_USAGE_INITIAL_DUKPT_KEY, KEY_USAGE_KEY_DERIVATION,
		KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS, KEY_USAGE_EMV_MKEY_CONFIDENTIALITY,
		KEY_USAGE_EMV_MKEY_INTEGRITY, KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE,
		KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS, KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION,
		KEY_USAGE_EMV_MKEY_OTHER,
	} {
		m[u] = derive
	}
	for _, u := range []string{
		KEY_USAGE_DATA_ENCRYPTION, KEY_USAGE_SENSITIVE_DATA_ENCRYPTION,
		KEY_USAGE_KEY_ENCRYPTION, KEY_USAGE_KEY_BLOCK_PROTECTION,
		KEY_USAGE_ISO20038_KEY_BLOCK_PROTECTION, KEY_USAGE_PIN_ENCRYPTION,
	} {
		m[u] = encrypt
	}
	for _, u := range []string{
		KEY_USAGE_CARD_VERIFICATION, KEY_USAGE_MAC_ISO16609, KEY_USAGE_MAC_ISO9797_1_ALG1,
		KEY_USAGE_MAC_ISO9797_1_ALG3, KEY_USAGE_MAC_CMAC, KEY_USAGE_MAC_HMAC,
		KEY_USAGE_PIN_VERIFICATION_OTHER, KEY_USAGE_PIN_VERIFICATION_IBM3624,
		KEY_USAGE_PIN_VERIFICATION_VISA_PVV,
	} {
		m[u] = generateVerify
	}
	return m
}()

// ValidateKeyUsageModeOfUse reports whether modeOfUse can apply to a key with
// keyUsage, returning a *HeaderError if not. For example, an Initial DUKPT
// Key (B1) is used to derive keys, so mode X (or N) is valid and mode E
// (encrypt only) is not.
//
// The check is optional: NewHeader does not call it, so existing callers are
// unaffected. Call it before wrapping a key, or after unwrapping one, to catch
// a header that does not describe the key. Key usages it has no rule for pass
// (see allowedModesOfUse).
//
//	if err := tr31.ValidateKeyUsageModeOfUse(tr31.KEY_USAGE_INITIAL_DUKPT_KEY, tr31.MODE_OF_USE_DERIVE); err != nil {
//		return err
//	}
func ValidateKeyUsageModeOfUse(keyUsage, modeOfUse string) error {
	allowed, ok := allowedModesOfUse[keyUsage]
	if !ok {
		return nil
	}
	for _, m := range allowed {
		if m == modeOfUse {
			return nil
		}
	}
	return &HeaderError{Message: fmt.Sprintf(HeaderErrKeyUsageModeOfUse, modeOfUse, keyUsage, strings.Join(allowed, ", "))}
}

// ValidateKeyUsageModeOfUse checks the header's key usage and mode of use
// against each other; see the package-level ValidateKeyUsageModeOfUse.
func (h *Header) ValidateKeyUsageModeOfUse() error {
	return ValidateKeyUsageModeOfUse(h.KeyUsage, h.ModeOfUse)
}
