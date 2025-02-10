[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://moov-io.github.io/psec/">Project Documentation</a>
  ·
  <a href="https://moov-io.github.io/psec/api/#overview">API Endpoints</a>
  ·
  <a href="https://slack.moov.io/">Community</a>
  ·
  <a href="https://moov.io/blog/">Blog</a>
  <br>
  <br>
</p>


# moov-io/psec
package provides tools for protecting sensitive data and cardholder authentication in retail payment transactions.

## Table of contents

- [Project status](#project-status)
- [Usage](#usage)
    - [Go library](#go-library)
    - [DUPKT apis](#dupkt-apis)
    - [How to](#how-to)
    - [Command lines](#command-lines)
    - [Service Instance](#service-instance)
    - [Rest APIs](#rest-apis)
- [Supported and tested platforms](#supported-and-tested-platforms)
- [Contributing](#contributing)
- [Releasing](#releasing)
- [Testing](#testing)
- [Related projects](#related-projects)
- [License](#license)

[//]: # (## Project status)

[//]: # ()
[//]: # (Moov dukpt is actively used for validation and debugging. Please star the project if you are interested in its progress. If you have layers above dukpt to simplify tasks, perform business operations, or found bugs we would appreciate an issue or pull request. Thanks!)

[//]: # ()
[//]: # (## Usage)

[//]: # ()
[//]: # (### Go library)

[//]: # ()
[//]: # (This project uses [Go Modules]&#40;https://go.dev/blog/using-go-modules&#41; and Go v1.18 or newer. See [Golang's install instructions]&#40;https://golang.org/doc/install&#41; for help setting up Go. You can download the source code and we offer [tagged and released versions]&#40;https://github.com/moov-io/dupkt/releases/latest&#41; as well. We highly recommend you use a tagged release for production.)

[//]: # ()
[//]: # (```)

[//]: # ($ git@github.com:moov-io/dupkt.git)

[//]: # ()
[//]: # ($ go get -u github.com/moov-io/dupkt)

[//]: # (```)

[//]: # ()
[//]: # (### DUPKT apis)

[//]: # ()
[//]: # (Moov dukpt project supported general utility functions for managing transaction key. The functions divided into two group as aes and des)

[//]: # ()
[//]: # (- Functions for triple data encryption algorithm &#40;des&#41;)

[//]: # (```)

[//]: # (    func DerivationOfInitialKey&#40;bdk, ksn []byte&#41; &#40;[]byte, error&#41;)

[//]: # (    func DeriveCurrentTransactionKey&#40;ik, ksn []byte&#41; &#40;[]byte, error&#41;)

[//]: # (    func EncryptPin&#40;currentKey []byte, pin, pan string, format string&#41; &#40;[]byte, error&#41;)

[//]: # (    func DecryptPin&#40;currentKey, ciphertext []byte, pan string, format string&#41; &#40;string, error&#41;)

[//]: # (    func GenerateMac&#40;currentKey []byte, plainText, action string&#41; &#40;[]byte, error&#41;)

[//]: # (    func EncryptData&#40;currentKey, iv []byte, plainText, action string&#41; &#40;[]byte, error&#41;)

[//]: # (    func DecryptData&#40;currentKey, ciphertext, iv []byte, action string&#41; &#40;string, error&#41;)

[//]: # (```)

[//]: # ()
[//]: # (- Functions for advanced encryption standard &#40;aes&#41;)

[//]: # (```)

[//]: # (    func DerivationOfInitialKey&#40;bdk, kid []byte&#41; &#40;[]byte, error&#41;)

[//]: # (    func DeriveCurrentTransactionKey&#40;ik, ksn []byte&#41; &#40;[]byte, error&#41;)

[//]: # (    func EncryptPin&#40;currentKey, ksn []byte, pin, pan string, keyType string&#41; &#40;[]byte, error&#41;)

[//]: # (    func DecryptPin&#40;currentKey, ksn, ciphertext []byte, pan string, keyType string&#41; &#40;string, error&#41;)

[//]: # (    func GenerateCMAC&#40;currentKey, ksn []byte, plaintext string, keyType string, action string&#41; &#40;[]byte, error&#41;)

[//]: # (    func GenerateHMAC&#40;currentKey, ksn []byte, plaintext string, keyType string, action string&#41; &#40;[]byte, error&#41;)

[//]: # (    func EncryptData&#40;currentKey, ksn, iv []byte, plaintext, keyType, action string&#41; &#40;[]byte, error&#41;)

[//]: # (    func DecryptData&#40;currentKey, ksn, iv, ciphertext []byte, keyType, action string&#41; &#40;string, error&#41;)

[//]: # (```)

[//]: # ()
[//]: # (- Utility function that used to get next key serial number )

[//]: # (```)

[//]: # (    GenerateNextAesKsn&#40;ksn []byte&#41; &#40;[]byte, error&#41;)

[//]: # (```)

[//]: # ()
[//]: # (### How to)

[//]: # ()
[//]: # (First step is to derive initial key in from base derivative key and key serial number &#40;or initial key id&#41;. Base derivative key &#40;BKD&#41; can get from base derivative key id. The package don't specify how to get base derivative key.  )

[//]: # ()
[//]: # (- des)

[//]: # (```)

[//]: # (    ik, err := DerivationOfInitialKey&#40;bdk, ksn&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # (```)

[//]: # ()
[//]: # (- aes)

[//]: # (```)

[//]: # (    ik, err := DerivationOfInitialKey&#40;bdk, initialKeyID&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # (```)

[//]: # ()
[//]: # (Second step is to generate transaction key in from generated initial key and key serial number.)

[//]: # ()
[//]: # (```)

[//]: # (    transactionKey, err := DeriveCurrentTransactionKey&#40;ik, ksn&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # (```)

[//]: # ()
[//]: # (Data &#40;pin, mac, normal data&#41; is encrypted/decrypted using generated initial key and transaction key)

[//]: # ()
[//]: # (- des)

[//]: # (```)

[//]: # (    eryptedPin, err := EncryptPin&#40;transactionKey, pin, pan, FormatVersion&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # ()
[//]: # (    decryptedPin, err := DecryptPin&#40;transactionKey, encryptedPin, pan, FormatVersion&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # (```)

[//]: # ()
[//]: # (- aes)

[//]: # (```)

[//]: # (	encPinblock, err := EncryptPin&#40;transactionKey, ksn, pin, pan, KeyAES128Type&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # ()
[//]: # (	decPinblock, err := DecryptPin&#40;transactionKey, ksn, encPinblock, pan, KeyAES128Type&#41;)

[//]: # (    if err != nil {)

[//]: # (        return err)

[//]: # (    })

[//]: # (```)

[//]: # ()
[//]: # (### Command lines)

[//]: # ()
[//]: # (```)

[//]: # (dukptcli is a tool for both tdes and aes derived unique key per transaction &#40;dukpt&#41; key management.)

[//]: # ()
[//]: # (USAGE)

[//]: # (   dukptcli [-v] [-algorithm] [-ik] [-tk] [-ep] [-dp] [-gm] [-en] [-de])

[//]: # ()
[//]: # (EXAMPLES)

[//]: # (  dukptcli -v          Print the version of dukptcli &#40;Example: v1.0.0&#41;)

[//]: # (  dukptcli -algorithm  Data encryption algorithm &#40;options: des, aes&#41;)

[//]: # (  dukptcli -ik         Derive initial key from base derivative key and key serial number &#40;or initial key id&#41;  )

[//]: # (  dukptcli -tk         Derive transaction key &#40;current transaction key&#41; from initial key and key serial number)

[//]: # (  dukptcli -ep         Encrypt pin block using dukpt transaction key)

[//]: # (  dukptcli -dp         Decrypt pin block using dukpt transaction key)

[//]: # (  dukptcli -gm         Generate mac using dukpt transaction key)

[//]: # (  dukptcli -en         Encrypt data using dukpt transaction key)

[//]: # (  dukptcli -de         Decrypt data using dukpt transaction key)

[//]: # ()
[//]: # (FLAGS)

[//]: # (  -algorithm string)

[//]: # (        data encryption algorithm &#40;options: des, aes&#41; &#40;default "des"&#41;)

[//]: # (  -algorithm.key_type string)

[//]: # (        key type of aes &#40;options: aes128, aes192, aes256 &#40;default "aes128"&#41;)

[//]: # (  -de)

[//]: # (        decrypt data using dukpt transaction key)

[//]: # (  -de.action string)

[//]: # (        request or response action &#40;default "request"&#41;)

[//]: # (  -de.data string)

[//]: # (        encrypted text transformed from plaintext using an encryption algorithm)

[//]: # (  -de.iv string)

[//]: # (        initial vector &#40;not formatted string&#41;)

[//]: # (  -de.ksn string)

[//]: # (        key serial number)

[//]: # (  -de.tk string)

[//]: # (        current transaction key)

[//]: # (  -dp)

[//]: # (        decrypt pin block using dukpt transaction key)

[//]: # (  -dp.format string)

[//]: # (        pin block format &#40;ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4&#41;)

[//]: # (  -dp.ksn string)

[//]: # (        key serial number)

[//]: # (  -dp.pan string)

[//]: # (        not formatted pan string)

[//]: # (  -dp.pin string)

[//]: # (        encrypted text transformed from plaintext using an encryption algorithm)

[//]: # (  -dp.tk string)

[//]: # (        current transaction key)

[//]: # (  -en)

[//]: # (        encrypt data using dukpt transaction key)

[//]: # (  -en.action string)

[//]: # (        request or response action &#40;default "request"&#41;)

[//]: # (  -en.data string)

[//]: # (        not formatted request data)

[//]: # (  -en.iv string)

[//]: # (        initial vector &#40;not formatted string&#41;)

[//]: # (  -en.ksn string)

[//]: # (        key serial number)

[//]: # (  -en.tk string)

[//]: # (        current transaction key)

[//]: # (  -ep)

[//]: # (        encrypt pin block using dukpt transaction key)

[//]: # (  -ep.format string)

[//]: # (        pin block format &#40;ISO-0, ISO-1, ISO-2, ISO-3, ISO-4, ANSI, ECI1, ECI2, ECI3, ECI4, VISA1, VISA2, VISA3, VISA4&#41;)

[//]: # (  -ep.ksn string)

[//]: # (        key serial number)

[//]: # (  -ep.pan string)

[//]: # (        not formatted pan string)

[//]: # (  -ep.pin string)

[//]: # (        not formatted pin string)

[//]: # (  -ep.tk string)

[//]: # (        current transaction key)

[//]: # (  -gm)

[//]: # (        generate mac using dukpt transaction key)

[//]: # (  -gm.action string)

[//]: # (        request or response action &#40;default "request"&#41;)

[//]: # (  -gm.data string)

[//]: # (        not formatted request data)

[//]: # (  -gm.ksn string)

[//]: # (        key serial number)

[//]: # (  -gm.tk string)

[//]: # (        current transaction key)

[//]: # (  -gm.type string)

[//]: # (        cmac or hmac style &#40;is valid using aes algorithm&#41; &#40;default "cmac"&#41;)

[//]: # (  -ik)

[//]: # (        derive initial key from base derivative key and key serial number &#40;or initial key id&#41;)

[//]: # (  -ik.bdk string)

[//]: # (        base derivative key)

[//]: # (  -ik.kid string)

[//]: # (        initial key id)

[//]: # (  -ik.ksn string)

[//]: # (        key serial number)

[//]: # (  -tk)

[//]: # (        derive transaction key &#40;current transaction key&#41; from initial key and key serial number)

[//]: # (  -tk.ik string)

[//]: # (        initial key)

[//]: # (  -tk.ksn string)

[//]: # (        key serial number)

[//]: # (  -v    Print dupkt cli version)

[//]: # (```)

[//]: # ()
[//]: # (User should use main flag and sub flag. algorithm.key_type flag is a sub flag of algorithm flag.)

[//]: # ()
[//]: # (There are some execution flags in this cli)

[//]: # (```)

[//]: # (    dukptcli -ik         Derive initial key from base derivative key and key serial number &#40;or initial key id&#41;  )

[//]: # (    dukptcli -tk         Derive transaction key &#40;current transaction key&#41; from initial key and key serial number)

[//]: # (    dukptcli -ep         Encrypt pin block using dukpt transaction key)

[//]: # (    dukptcli -dp         Decrypt pin block using dukpt transaction key)

[//]: # (    dukptcli -gm         Generate mac using dukpt transaction key)

[//]: # (    dukptcli -en         Encrypt data using dukpt transaction key)

[//]: # (    dukptcli -de         Decrypt data using dukpt transaction key)

[//]: # (```)

[//]: # (Execution flags &#40;ik, tk, ep, dp, gm, en, de&#41; can use with algorithm. These flags can't run simultaneously. )

[//]: # (That is that will do a main execution only.)

[//]: # (Execution priority is ik, tk, ep, dp, gm, en, de when setting several main flags.)

[//]: # ()
[//]: # (Example:)

[//]: # (```)

[//]: # (    dukptcli -algorithm=des  -gm=true  -ik=true -ik.bdk=0123456789ABCDEFFEDCBA9876543210 -ik.ksn=FFFF9876543210E00001)

[//]: # (    RESULT: 6ac292faa1315b4d858ab3a3d7d5933a)

[//]: # (```)

[//]: # (In above example, the execution is to derive initial key with specified algorithm although set two execution flags)

[//]: # ()
[//]: # (### Service instance)

[//]: # (DUKPT library provided service instance that support multi dukpt encrypt machines. )

[//]: # (```)

[//]: # (type Service interface {)

[//]: # (	CreateMachine&#40;m *Machine&#41; error)

[//]: # (	GetMachine&#40;ik string&#41; &#40;*Machine, error&#41;)

[//]: # (	GetMachines&#40;&#41; []*Machine)

[//]: # (	MakeNextKSN&#40;ik string&#41; &#40;*Machine, error&#41;)

[//]: # (	DeleteMachine&#40;ik string&#41; error)

[//]: # (	EncryptPin&#40;ik, pin, pan, format string&#41; &#40;string, error&#41;)

[//]: # (	DecryptPin&#40;ik, ciphertext, pan, format string&#41; &#40;string, error&#41;)

[//]: # (	GenerateMac&#40;ik, data, action, macType string&#41; &#40;string, error&#41;)

[//]: # (	EncryptData&#40;ik, data, action, iv string&#41; &#40;string, error&#41;)

[//]: # (	DecryptData&#40;ik, ciphertext, action, iv string&#41; &#40;string, error&#41;)

[//]: # (})

[//]: # (```)

[//]: # ()
[//]: # (User can use the service instance using special logger)

[//]: # (```)

[//]: # (	logger := log.NewLogger&#40;kitlogger&#41;)

[//]: # (	logger.Logf&#40;"Starting dukpt server version %s", dukpt.Version&#41;)

[//]: # ()
[//]: # (	// Setup underlying dukpt service)

[//]: # (	r := server.NewRepositoryInMemory&#40;logger&#41;)

[//]: # (	svc = server.NewService&#40;r&#41;)

[//]: # (```)

[//]: # ()
[//]: # (### Rest APIs)

[//]: # (DUKPT library provided web server. Please check following http endpoints)

[//]: # ()
[//]: # (| Method | Request Body | Route              | Action         |)

[//]: # (|--------|--------------|--------------------|----------------|)

[//]: # (| GET    |              | /machines          | Get Machines   |)

[//]: # (| GET    |              | /machine/{ik}      | Get Machine    |)

[//]: # (| POST   |              | /machine           | Create Machine |)

[//]: # (| POST   | JSON         | /generate_ksn/{ik} | Generate KSN   |)

[//]: # (| POST   | JSON         | /encrypt_pin/{ik}  | Encrypt PIN    | )

[//]: # (| POST   | JSON         | /decrypt_pin/{ik}  | Decrypt Pin    |)

[//]: # (| POST   | JSON         | /generate_mac/{ik} | Generate Mac   |)

[//]: # (| POST   | JSON         | /encrypt_data/{ik} | Encrypt Data   |)

[//]: # (| POST   | JSON         | /decrypt_data/{ik} | Decrypt Data   |)

[//]: # ()
[//]: # (User can create web service using following http handler )

[//]: # (```)

[//]: # (	handler = server.MakeHTTPHandler&#40;svc&#41;)

[//]: # (```)

[//]: # ()
[//]: # (## Supported and tested platforms)

[//]: # ()
[//]: # (- 64-bit Linux &#40;Ubuntu, Debian&#41;, macOS, and Windows)

[//]: # (- Raspberry Pi)

[//]: # ()
[//]: # (Note: 32-bit platforms have known issues and are not supported.)

[//]: # ()
[//]: # (## Contributing)

[//]: # ()
[//]: # (Yes please! Please review our [Contributing guide]&#40;CONTRIBUTING.md&#41; and [Code of Conduct]&#40;CODE_OF_CONDUCT.md&#41; to get started!)

[//]: # ()
[//]: # (This project uses [Go Modules]&#40;https://go.dev/blog/using-go-modules&#41; and Go v1.18 or newer. See [Golang's install instructions]&#40;https://golang.org/doc/install&#41; for help setting up Go. You can download the source code and we offer [tagged and released versions]&#40;https://github.com/moov-io/imagecashletter/releases/latest&#41; as well. We highly recommend you use a tagged release for production.)

[//]: # ()
[//]: # (### Releasing)

[//]: # ()
[//]: # (To make a release of dupkt simply open a pull request with `CHANGELOG.md` and `version.go` updated with the next version number and details. You'll also need to push the tag &#40;i.e. `git push origin v1.0.0`&#41; to origin in order for CI to make the release.)

[//]: # ()
[//]: # (### Testing)

[//]: # ()
[//]: # (We maintain a comprehensive suite of unit tests and recommend table-driven testing when a particular function warrants several very similar test cases. To run all test files in the current directory, use `go test`. Current overall coverage can be found on [Codecov]&#40;https://app.codecov.io/gh/moov-io/imagecashletter/&#41;.)

[//]: # ()
[//]: # ()
[//]: # (## Related projects)

[//]: # (As part of Moov's initiative to offer open source fintech infrastructure, we have a large collection of active projects you may find useful:)

[//]: # ()
[//]: # (- [Moov DUPKT]&#40;https://github.com/moov-io/pinblock&#41; offers functions for personal identification management &#40;PIN&#41; and security.)

[//]: # ()
[//]: # (## License)

[//]: # ()
[//]: # (Apache License 2.0 - See [LICENSE]&#40;LICENSE&#41; for details.)
