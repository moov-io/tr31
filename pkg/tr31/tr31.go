package tr31

import "C"
import (
	"github.com/moov-io/psec/encryption"
)

func wrap(kbpk []byte, header string, key []byte, maskedKeyLen *int) (string, error) {
	//	Wrap key into a TR-31 key block version A, B, C or D.
	//
	//		Parameters
	//	----------
	//kbpk : bytes
	//	Key Block Protection Key.
	//		Must be a Single, Double or Triple DES key for versions A and C.
	//		Must be a Double or Triple DES key for versions B.
	//		Must be an AES key for version D.
	//		header : Header or str
	//	TR-31 key block header either in TR-31 string format or
	//	as a Header class.
	//		A full TR-31 key block in string format can be provided
	//	to extract header from.
	//		key : bytes
	//	A key to be wrapped.
	//		masked_key_len : int, optional
	//	Desired key length in bytes to mask true key length.
	//		Defaults to max key size for algorithm:
	//
	//	- Triple DES for DES algorithm (24 bytes)
	//	- AES-256 for AES algorithm (32 bytes)
	//
	//	Returns
	//	-------
	//		key_block : str
	//	Key formatted in a TR-31 key block and encrypted
	//	under the KBPK.
	//
	//		Raises
	//	------
	//	KeyBlockError
	//	HeaderError
	//
	//	Notes
	//	-----
	//		It's highly recommended that the length of the KBPK is equal or greater
	//	than the length of the key to be protected. E.g. do not protect AES-256 key
	//	with AES-128 KBPK.
	//
	//		Examples
	//	--------
	//	>>> import psec
	//	>>> psec.tr31.wrap(
	//	...     kbpk=b"\xAB" * 16,
	//	...     header="B0096P0TE00N0000",
	//	...     key=b"\xCD" * 16)  # doctest: +SKIP
	//	'B0096P0TE00N0000471D4FBE35E5865BDE20DBF4C15503161F55D681170BF8DD14D01B6822EF8550CB67C569DE8AC048'
	// Create a new KeyBlock instance
	kb, _ := encryption.NewKeyBlock(kbpk, header)
	// Call the Wrap method on the KeyBlock instance
	return kb.Wrap(key, maskedKeyLen)
}
func unwrap(kbpk []byte, key_block string) (encryption.Header, []byte, error) {
	//	Unwrap key from a TR-31 key block version A, B, C or D.
	//
	//		Parameters
	//	----------
	//kbpk : bytes
	//	Key Block Protection Key.
	//		Must be a Single, Double or Triple DES key for versions A and C.
	//		Must be a Double or Triple DES key for versions B.
	//		Must be an AES key for version D.
	//		key_block : str
	//	A TR-31 key block.
	//
	//		Returns
	//	-------
	//		header : Header
	//	TR-31 key block header.
	//		key : bytes
	//	Unwrapped key. The unwrapped key is guaranteed to be what the sender
	//	wrapped into the block. However, it does not guarantee that the sender
	//	wrapped a valid key.
	//
	//		Raises
	//	------
	//	KeyBlockError
	//	HeaderError
	//
	//	Notes
	//	-----
	//		It's highly recommended that the length of the KBPK is equal or greater
	//	than the length of the key to be protected. E.g. do not protect AES-256 key
	//	with AES-128 KBPK.
	//
	//		Examples
	//	--------
	//	>>> import psec
	//	>>> header, key = psec.tr31.unwrap(
	//	...     kbpk=b"\xAB" * 16,
	//	...     key_block="B0096P0TE00N0000471D4FBE35E5865BDE20DBF4C15503161F55D681170BF8DD14D01B6822EF8550CB67C569DE8AC048")
	//	>>> key
	//	b'\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd'
	//	>>> header.version_id
	//	'B'
	//	>>> header.key_usage
	//	'P0'
	//	>>> header.algorithm
	//	'T'
	//	>>> header.mode_of_use
	//	'E'
	//	>>> header.version_num
	//	'00'
	//	>>> header.exportability
	//	'N'

	kb, _ := encryption.NewKeyBlock(kbpk, nil)
	unwrappedData, err := kb.Unwrap(key_block)
	return kb.GetHeader(), unwrappedData, err
}
