package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/moov-io/bertlv"
	"github.com/moov-io/tr31/pkg/tr31"
)

// KeyData represents the structure of the encrypted key data
type KeyData struct {
	ServerDateTime    string            `json:"serverDateTime"`
	TransactionID     string            `json:"transactionId"`
	ReaderIdentifier  string            `json:"readerIdentifier"`
	CardholderDataKey CardholderDataKey `json:"cardholderDataKey"`
}

// KeyData represents the structure of the encrypted key data
type CardholderDataKey struct {
	KeyBlock       string `json:"keyBlock"`
	KeyBlockFormat string `json:"keyBlockFormat"`
	KekID          string `json:"kekId"`
	CardDataHash   string `json:"cardDataHash"`
}

// TransactionData represents the structure of the encrypted transaction data
type TransactionData struct {
	VersionID      string         `json:"versionId"`
	TransactionID  string         `json:"transactionId"`
	CardholderData CardholderData `json:"cardholderData"`
	KeyData        string         `json:"keyData"`
}

// CardholderData contains the encrypted data and encryption details
type CardholderData struct {
	IV           string `json:"iv"`
	Algorithm    string `json:"algorithm"`
	CipheredData string `json:"cipheredData"`
}

// decryptKeyData decrypts the key data using TR-31
func decryptKeyData(keyData KeyData) ([]byte, error) {
	// mock lookup to key block preshared key
	kekIdKeyMap := map[string][]byte{
		"493C3AB4110BDA5BDD1B5DDB3DBC6E8778EA8821DC64AB9A53B049725D205DC3": {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	}

	// Get the kbpk from the kekID
	kbpk, ok := kekIdKeyMap[keyData.CardholderDataKey.KekID]
	if !ok {
		return nil, fmt.Errorf("could not find pbpk for kekid: %s", keyData.CardholderDataKey.KekID)
	}

	// Decrypt the key block using the KEK
	kBlock, err := tr31.NewKeyBlock(kbpk, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating key block: %v", err)
	}

	singleUseKey, err := kBlock.Unwrap(keyData.CardholderDataKey.KeyBlock)
	if err != nil {
		return nil, fmt.Errorf("error unwrapping key: %v", err)
	}
	return singleUseKey, nil
}

// decryptCardData decrypts the card data using AES-128-CBC
func decryptCardData(data CardholderData, keyHex string) ([]byte, error) {
	// Decode the IV
	iv, err := base64.StdEncoding.DecodeString(data.IV)
	if err != nil {
		return nil, fmt.Errorf("error decoding IV: %v", err)
	}

	// Decode the base64 ciphered data
	cipheredData, err := base64.StdEncoding.DecodeString(data.CipheredData)
	if err != nil {
		return nil, fmt.Errorf("error decoding ciphered data: %v", err)
	}

	// Decode the hex key
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("error decoding key: %v", err)
	}

	// Create a new cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher block: %v", err)
	}

	// Create a new CBC mode decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Create a buffer for the decrypted data
	decrypted := make([]byte, len(cipheredData))

	// Decrypt the data
	mode.CryptBlocks(decrypted, cipheredData)

	// Remove PKCS#7 padding
	decrypted = removePKCS7Padding(decrypted)

	return decrypted, nil
}

// removePKCS7Padding removes PKCS#7 padding from decrypted data
// Current code
func removePKCS7Padding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return data
	}
	padding := int(data[length-1])
	if padding > length {
		return data
	}
	return data[:length-padding]
}

func main() {
	// Example key lookup (you would implement your own key lookup logic)

	// transactionKeyMap maps transaction IDs to encryption tr31 key
	transactionKeyMap := map[string]string{
		"903909e2-7b83-435a-a7f4-9d856beb8601": "B9517FF24FD4C71833478D424C29751D",
	}

	jsonCardHolderKeyData := `{
		"cardholderDataKey":{
		  "keyBlock":"D0112D0AD00E00009ef4ff063d9757987d1768a1e317a6530de7d8ac81972c19a3659afb28e8d35f48aaa5b0f124e73893163e9a020ae5f3",
		  "keyBlockFormat":"TR-31",
		  "kekId":"493C3AB4110BDA5BDD1B5DDB3DBC6E8778EA8821DC64AB9A53B049725D205DC3",
		  "cardDataHash":"7NJSPgwILSwjZO4BG2GFBFPwuzE/Air4HJu61VaP+9I="
		},
		"serverDateTime":"20240718163738",
		"transactionId":"903909e2-7b83-435a-a7f4-9d856beb8601",
		"readerIdentifier":"ce1b546a8b2e5525cae7f191d285c4be9acd1f69815388b9ffb253a4ac982386"
	  }`

	var keyData KeyData
	err := json.Unmarshal([]byte(jsonCardHolderKeyData), &keyData)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	singleUseKey, err := decryptKeyData(keyData)
	if err != nil {
		log.Fatalf("Error decrypting key data: %v", err)
	}

	// add the key to the transaction key map
	transactionKeyMap[keyData.TransactionID] = hex.EncodeToString(singleUseKey)

	// Example JSON data
	jsonCardholderData := `{
		"versionId": "4_1",
		"transactionId":"903909e2-7b83-435a-a7f4-9d856beb8601",
			"cardholderData": {
				"iv": "tNTKK6IDYOlGEzUb7lVK/g==",
				"algorithm": "AES128-CBC",
				"cipheredData": "RxnK6NDu8RHT8/j/g9i2LNaYTCNvUemwEJ09C1AkxtCj0Ke+CKqL5qPfEC2t/ONEIUWm7Kw6Nf3vuVjrdOx74ZsHhtXTIF9SweTYdxuc3Jg3k5YYGeTkNK/OXv6AjhOlVVuSyfxs4/8LdXln4O0HmEoeydJcofYSk0WDVLFIjpxnw7i6ZSTY6SZLHglwMrxnJYsdq9y5ni4RCqTW767Yfk7SIjlzSvWdy6qVv6pZQ4za4UMlH8c6Mgc7B/9gybQDNuTHztIypXEf6N+1QsiqBHh2uKqDrKVQxEGg0kx8vyT6w4i+v+jTsvCcrWXdd655"
			}
	}`

	// Parse the JSON data
	var transactionData TransactionData
	err = json.Unmarshal([]byte(jsonCardholderData), &transactionData)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Get the key from the key map (in a real implementation, this would be your key lookup logic)
	key, ok := transactionKeyMap[transactionData.TransactionID]
	if !ok {
		log.Fatal("Key not found")
	}

	// Decrypt the data
	result, err := decryptCardData(transactionData.CardholderData, key)
	if err != nil {
		log.Fatalf("Error decrypting data: %v", err)
	}
	tlv, err := bertlv.Decode(result)
	if err != nil {
		log.Fatalf("Error decoding TLV: %v", err)
	}
	fmt.Printf("Decrypted data: \n")
	bertlv.PrettyPrint(tlv)
}
