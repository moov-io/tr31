package tr31

import (
	"fmt"
	"strings"
)

// TR-31 key usage codes (header bytes 5-6).
//
// The key usage says what kind of key is in the block, and so what it may be
// used for. Passing these constants to NewHeader, rather than raw strings,
// makes the choice readable and harder to get wrong. Two easy mistakes:
//
//   - "B0" is a Base Derivation Key (BDK), the DUKPT master key. The key a
//     terminal receives is an Initial DUKPT Key, "B1".
//   - "I0" is an Initialization Vector. It is not a key at all.
//
// The values and their allowed modes of use come from ASC X9 TR 31-2018,
// Annex A (Table 6), the report ANSI X9.143 replaced. B3, D3 and K4 were
// assigned after TR 31-2018. NewHeader accepts any two-character alphanumeric
// value, so a code without a constant here (including the numeric codes
// reserved for proprietary use) can still be used.
const (
	// KEY_USAGE_BDK is a Base Derivation Key: the DUKPT master key that
	// Initial DUKPT Keys are derived from. Mode of use X.
	KEY_USAGE_BDK string = "B0"
	// KEY_USAGE_INITIAL_DUKPT_KEY is an Initial DUKPT Key: the per-device key
	// loaded into a terminal, from which it derives its transaction keys. Mode
	// of use X. ANSI X9.24-3 recommends this usage for AES DUKPT initial keys.
	KEY_USAGE_INITIAL_DUKPT_KEY string = "B1"
	// KEY_USAGE_BASE_KEY_VARIANT is a Base Key Variant Key, used to create key
	// variants. Mode of use Y.
	KEY_USAGE_BASE_KEY_VARIANT string = "B2"
	// KEY_USAGE_KEY_DERIVATION is a key derivation key for derivations other
	// than X9.24 DUKPT. Assigned after TR 31-2018, so not checked by
	// ValidateKeyUsageModeOfUse.
	KEY_USAGE_KEY_DERIVATION string = "B3"
	// KEY_USAGE_CARD_VERIFICATION is a Card Verification Key (CVK), used to
	// compute and verify card verification codes (CVV, CVC, CSC). Modes C, G,
	// V.
	KEY_USAGE_CARD_VERIFICATION string = "C0"
	// KEY_USAGE_DATA_ENCRYPTION is a symmetric key for data encryption. Modes
	// B, D, E.
	KEY_USAGE_DATA_ENCRYPTION string = "D0"
	// KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION is an asymmetric key pair for data
	// encryption. Modes B, D, E.
	KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION string = "D1"
	// KEY_USAGE_DECIMALIZATION_TABLE is a key for encrypting a decimalization
	// table. Modes B, D, E.
	KEY_USAGE_DECIMALIZATION_TABLE string = "D2"
	// KEY_USAGE_SENSITIVE_DATA_ENCRYPTION is a symmetric key for encrypting
	// sensitive data. Assigned after TR 31-2018, so not checked by
	// ValidateKeyUsageModeOfUse.
	KEY_USAGE_SENSITIVE_DATA_ENCRYPTION string = "D3"
	// KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS is an EMV/chip issuer master key for
	// deriving the card keys behind application cryptograms (ARQC, TC, AAC).
	// Mode X.
	KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS string = "E0"
	// KEY_USAGE_EMV_MKEY_CONFIDENTIALITY is an EMV/chip issuer master key for
	// secure messaging confidentiality. Mode X.
	KEY_USAGE_EMV_MKEY_CONFIDENTIALITY string = "E1"
	// KEY_USAGE_EMV_MKEY_INTEGRITY is an EMV/chip issuer master key for secure
	// messaging integrity. Mode X.
	KEY_USAGE_EMV_MKEY_INTEGRITY string = "E2"
	// KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE is an EMV/chip issuer master key for
	// data authentication codes. Mode X.
	KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE string = "E3"
	// KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS is an EMV/chip issuer master key for
	// dynamic numbers. Mode X.
	KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS string = "E4"
	// KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION is an EMV/chip issuer master key
	// for card personalization. Mode X.
	KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION string = "E5"
	// KEY_USAGE_EMV_MKEY_OTHER is an EMV/chip issuer master key for other
	// purposes. Mode X.
	KEY_USAGE_EMV_MKEY_OTHER string = "E6"
	// KEY_USAGE_INITIALIZATION_VECTOR is an Initialization Vector (IV) for a
	// cipher mode that needs one. It is not a key. Mode N.
	KEY_USAGE_INITIALIZATION_VECTOR string = "I0"
	// KEY_USAGE_KEY_ENCRYPTION is a key encryption (wrapping) key. It is not
	// used for TR-31 key block protection keys (see K1). Modes B, D, E.
	KEY_USAGE_KEY_ENCRYPTION string = "K0"
	// KEY_USAGE_KEY_BLOCK_PROTECTION is a TR-31 Key Block Protection Key
	// (KBPK). Modes B, D, E.
	KEY_USAGE_KEY_BLOCK_PROTECTION string = "K1"
	// KEY_USAGE_TR34_ASYMMETRIC is an asymmetric key pair for TR-34 key
	// exchange. Modes B, D, E.
	KEY_USAGE_TR34_ASYMMETRIC string = "K2"
	// KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT is an asymmetric key pair for key
	// agreement or key wrapping. Modes B, D, E, X.
	KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT string = "K3"
	// KEY_USAGE_ISO20038_KEY_BLOCK_PROTECTION is an ISO 20038 key block
	// protection key. Assigned after TR 31-2018, so not checked by
	// ValidateKeyUsageModeOfUse.
	KEY_USAGE_ISO20038_KEY_BLOCK_PROTECTION string = "K4"
	// KEY_USAGE_MAC_ISO16609 is a MAC key for ISO 16609 algorithm 1 (TDEA).
	// Modes C, G, V.
	KEY_USAGE_MAC_ISO16609 string = "M0"
	// KEY_USAGE_MAC_ISO9797_1_ALG1 is a MAC key for ISO 9797-1 algorithm 1.
	// Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_ALG1 string = "M1"
	// KEY_USAGE_MAC_ISO9797_1_ALG2 is a MAC key for ISO 9797-1 algorithm 2.
	// Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_ALG2 string = "M2"
	// KEY_USAGE_MAC_ISO9797_1_ALG3 is a MAC key for ISO 9797-1 algorithm 3.
	// Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_ALG3 string = "M3"
	// KEY_USAGE_MAC_ISO9797_1_ALG4 is a MAC key for ISO 9797-1 algorithm 4.
	// Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_ALG4 string = "M4"
	// KEY_USAGE_MAC_ISO9797_1_1999_ALG5 is a MAC key for ISO 9797-1:1999
	// algorithm 5. Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_1999_ALG5 string = "M5"
	// KEY_USAGE_MAC_CMAC is a MAC key for ISO 9797-1:2011 algorithm 5, which
	// is CMAC. Modes C, G, V.
	KEY_USAGE_MAC_CMAC string = "M6"
	// KEY_USAGE_MAC_HMAC is an HMAC key. Modes C, G, V.
	KEY_USAGE_MAC_HMAC string = "M7"
	// KEY_USAGE_MAC_ISO9797_1_ALG6 is a MAC key for ISO 9797-1:2011
	// algorithm 6. Modes C, G, V.
	KEY_USAGE_MAC_ISO9797_1_ALG6 string = "M8"
	// KEY_USAGE_PIN_ENCRYPTION is a PIN encryption key, for PIN blocks only.
	// Modes B, D, E.
	KEY_USAGE_PIN_ENCRYPTION string = "P0"
	// KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE is an asymmetric key pair for
	// digital signatures. Modes S, V.
	KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE string = "S0"
	// KEY_USAGE_ASYMMETRIC_CA is an asymmetric key pair a certificate
	// authority signs with. Modes S, V.
	KEY_USAGE_ASYMMETRIC_CA string = "S1"
	// KEY_USAGE_ASYMMETRIC_NON_X924 is an asymmetric key pair for keys not
	// based on X9.24 part 2. Modes S, V, T, B, D, E.
	KEY_USAGE_ASYMMETRIC_NON_X924 string = "S2"
	// KEY_USAGE_PIN_VERIFICATION_OTHER is a PIN verification key (KPV) for an
	// algorithm other than IBM 3624 or Visa PVV. Modes C, G, V.
	KEY_USAGE_PIN_VERIFICATION_OTHER string = "V0"
	// KEY_USAGE_PIN_VERIFICATION_IBM3624 is a PIN verification key for the
	// IBM 3624 method. Modes C, G, V.
	KEY_USAGE_PIN_VERIFICATION_IBM3624 string = "V1"
	// KEY_USAGE_PIN_VERIFICATION_VISA_PVV is a PIN verification key for the
	// Visa PVV method. Modes C, G, V.
	KEY_USAGE_PIN_VERIFICATION_VISA_PVV string = "V2"
	// KEY_USAGE_PIN_VERIFICATION_X9132_ALG1 is a PIN verification key for
	// X9.132 algorithm 1 (AES). Modes C, G, V.
	KEY_USAGE_PIN_VERIFICATION_X9132_ALG1 string = "V3"
	// KEY_USAGE_PIN_VERIFICATION_X9132_ALG2 is a PIN verification key for
	// X9.132 algorithm 2 (AES). Modes C, G, V.
	KEY_USAGE_PIN_VERIFICATION_X9132_ALG2 string = "V4"
)

// TR-31 mode of use codes (header byte 8): how the key in the block may be
// used, within what its key usage allows. From ASC X9 TR 31-2018, Annex A
// (Table 8).
const (
	// MODE_OF_USE_ENCRYPT_DECRYPT allows encrypt and decrypt (wrap and unwrap).
	MODE_OF_USE_ENCRYPT_DECRYPT string = "B"
	// MODE_OF_USE_GENERATE_VERIFY allows generating and verifying (MACs, card
	// verification codes, PIN verification values).
	MODE_OF_USE_GENERATE_VERIFY string = "C"
	// MODE_OF_USE_DECRYPT allows decrypt (unwrap) only.
	MODE_OF_USE_DECRYPT string = "D"
	// MODE_OF_USE_ENCRYPT allows encrypt (wrap) only.
	MODE_OF_USE_ENCRYPT string = "E"
	// MODE_OF_USE_GENERATE allows generating only.
	MODE_OF_USE_GENERATE string = "G"
	// MODE_OF_USE_NO_RESTRICTIONS places no restriction beyond what the key
	// usage implies; it is the mode for an IV.
	MODE_OF_USE_NO_RESTRICTIONS string = "N"
	// MODE_OF_USE_SIGN allows digital signature operations only.
	MODE_OF_USE_SIGN string = "S"
	// MODE_OF_USE_SIGN_DECRYPT allows both signing and decrypting.
	MODE_OF_USE_SIGN_DECRYPT string = "T"
	// MODE_OF_USE_VERIFY allows verifying only.
	MODE_OF_USE_VERIFY string = "V"
	// MODE_OF_USE_DERIVE allows only deriving other keys.
	MODE_OF_USE_DERIVE string = "X"
	// MODE_OF_USE_CREATE_VARIANTS allows only creating key variants.
	MODE_OF_USE_CREATE_VARIANTS string = "Y"
)

// TR-31 exportability codes (header byte 11). From ASC X9 TR 31-2018,
// Annex A (Table 10).
const (
	// EXPORTABILITY_TRUSTED allows export under a key encryption key in a form
	// that meets X9.24 parts 1 or 2.
	EXPORTABILITY_TRUSTED string = "E"
	// EXPORTABILITY_NONE prevents the receiver from exporting the key (keys
	// derived from it may still be exported).
	EXPORTABILITY_NONE string = "N"
	// EXPORTABILITY_SENSITIVE allows export under a key encryption key in a
	// form that need not meet X9.24 parts 1 or 2.
	EXPORTABILITY_SENSITIVE string = "S"
)

// HeaderErrKeyUsageModeOfUse is the message for a mode of use that the key
// usage does not allow.
const HeaderErrKeyUsageModeOfUse string = "mode of use (%s) is not valid for key usage (%s); expected one of: %s"

// allowedModesOfUse is ASC X9 TR 31-2018, Annex A, Table 6: for each key usage
// it defines, the modes of use that key usage allows. Key usages it does not
// define (B3, D3 and K4, assigned later, and the numeric codes reserved for
// proprietary use) are not checked.
var allowedModesOfUse = func() map[string][]string {
	derive := []string{MODE_OF_USE_DERIVE}
	encrypt := []string{MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT}
	generateVerify := []string{MODE_OF_USE_GENERATE_VERIFY, MODE_OF_USE_GENERATE, MODE_OF_USE_VERIFY}
	signVerify := []string{MODE_OF_USE_SIGN, MODE_OF_USE_VERIFY}

	m := map[string][]string{
		KEY_USAGE_BASE_KEY_VARIANT:             {MODE_OF_USE_CREATE_VARIANTS},
		KEY_USAGE_INITIALIZATION_VECTOR:        {MODE_OF_USE_NO_RESTRICTIONS},
		KEY_USAGE_ASYMMETRIC_KEY_AGREEMENT:     {MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT, MODE_OF_USE_DERIVE},
		KEY_USAGE_ASYMMETRIC_DIGITAL_SIGNATURE: signVerify,
		KEY_USAGE_ASYMMETRIC_CA:                signVerify,
		KEY_USAGE_ASYMMETRIC_NON_X924: {
			MODE_OF_USE_SIGN, MODE_OF_USE_VERIFY, MODE_OF_USE_SIGN_DECRYPT,
			MODE_OF_USE_ENCRYPT_DECRYPT, MODE_OF_USE_DECRYPT, MODE_OF_USE_ENCRYPT,
		},
	}
	for _, u := range []string{
		KEY_USAGE_BDK, KEY_USAGE_INITIAL_DUKPT_KEY,
		KEY_USAGE_EMV_MKEY_APP_CRYPTOGRAMS, KEY_USAGE_EMV_MKEY_CONFIDENTIALITY,
		KEY_USAGE_EMV_MKEY_INTEGRITY, KEY_USAGE_EMV_MKEY_DATA_AUTH_CODE,
		KEY_USAGE_EMV_MKEY_DYNAMIC_NUMBERS, KEY_USAGE_EMV_MKEY_CARD_PERSONALIZATION,
		KEY_USAGE_EMV_MKEY_OTHER,
	} {
		m[u] = derive
	}
	for _, u := range []string{
		KEY_USAGE_DATA_ENCRYPTION, KEY_USAGE_ASYMMETRIC_DATA_ENCRYPTION,
		KEY_USAGE_DECIMALIZATION_TABLE, KEY_USAGE_KEY_ENCRYPTION,
		KEY_USAGE_KEY_BLOCK_PROTECTION, KEY_USAGE_TR34_ASYMMETRIC,
		KEY_USAGE_PIN_ENCRYPTION,
	} {
		m[u] = encrypt
	}
	for _, u := range []string{
		KEY_USAGE_CARD_VERIFICATION,
		KEY_USAGE_MAC_ISO16609, KEY_USAGE_MAC_ISO9797_1_ALG1, KEY_USAGE_MAC_ISO9797_1_ALG2,
		KEY_USAGE_MAC_ISO9797_1_ALG3, KEY_USAGE_MAC_ISO9797_1_ALG4,
		KEY_USAGE_MAC_ISO9797_1_1999_ALG5, KEY_USAGE_MAC_CMAC, KEY_USAGE_MAC_HMAC,
		KEY_USAGE_MAC_ISO9797_1_ALG6,
		KEY_USAGE_PIN_VERIFICATION_OTHER, KEY_USAGE_PIN_VERIFICATION_IBM3624,
		KEY_USAGE_PIN_VERIFICATION_VISA_PVV, KEY_USAGE_PIN_VERIFICATION_X9132_ALG1,
		KEY_USAGE_PIN_VERIFICATION_X9132_ALG2,
	} {
		m[u] = generateVerify
	}
	return m
}()

// ValidateKeyUsageModeOfUse reports whether modeOfUse is allowed for a key
// with keyUsage, per ASC X9 TR 31-2018 Table 6, returning a *HeaderError if
// not. For example, an Initial DUKPT Key (B1) only derives keys, so mode X is
// valid and mode E (encrypt only) is not.
//
// The check is optional: NewHeader and Load do not call it, so existing
// callers are unaffected. Call it before wrapping a key, or after unwrapping
// one, to catch a header that does not describe the key. Key usages Table 6
// does not define pass.
//
// Some products are more permissive than Table 6 (AWS Payment Cryptography,
// for example, also issues derivation keys with mode N); key blocks from them
// fail this check even though those products accept them.
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
