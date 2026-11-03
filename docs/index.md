# go-pkcs7

go-pkcs7 is a Go library that parses and builds the parts of the Cryptographic Message Syntax
(CMS, RFC 5652) that certificate enrollment protocols use. SCEP (RFC 8894) wraps every request and
response in these messages. [go-pki-scep](https://misiektoja.github.io/go-pki-scep/) is built on
this library.

It handles three content types:

* **SignedData**: signing with RSA PKCS #1 v1.5 or ECDSA keys and verification of RSA PKCS #1
  v1.5, RSASSA-PSS (RFC 4055) and ECDSA signatures. Content may be attached or detached and a
  message may have several signers or carry only certificates or a CRL.
* **EnvelopedData**: content encrypted for RSA recipient certificates with PKCS #1 v1.5 or
  RSAES-OAEP (RFC 8017) key transport.
* **EncryptedData**: content encrypted with a pre-shared key.

Algorithm choices are made per call through option structs, so two parts of one program can apply
different policies. Signing keys are `crypto.Signer` and decryption keys `crypto.Decrypter`
values, so they may live in an HSM. Input may be BER or DER. The module needs Go 1.27.3 or newer
and has no dependencies outside the standard library.

## Where to go next

| I want to | Page |
| --- | --- |
| Add the module and sign, verify and encrypt a first message | [Getting started](getting-started.md) |
| See which algorithms and message forms are supported | [Support matrix](support-matrix.md) |
| Sign content, add a certificate chain or build a certificate bundle | [Signing](guide/signing.md) |
| Verify a signature against trust anchors or at the signing time | [Verification](guide/verification.md) |
| Encrypt for recipient certificates or decrypt with an HSM key | [Encryption and decryption](guide/encryption.md) |
| Encrypt with a key both sides already hold | [Pre-shared keys](guide/pre-shared-keys.md) |
| Read messages from other implementations | [Parsing](guide/parsing.md) |
| Look up an option, an algorithm identifier or an error | [Options](reference/options.md), [Algorithms](reference/algorithms.md) and [Errors](reference/errors.md) |
| Know what the library checks and what it leaves to the caller | [Security model](security/security-model.md) |
| Exchange messages with OpenSSL | [OpenSSL](interoperability/openssl.md) |
| Move code from smallstep/pkcs7 | [Migrating from smallstep/pkcs7](migrating.md) |
| Check what is not supported | [Known limitations](known-limitations.md) |
| Look up a type or function | [Package documentation](https://pkg.go.dev/github.com/misiektoja/go-pkcs7) |
| See what changed in a release | [Changelog](https://github.com/misiektoja/go-pkcs7/blob/main/CHANGELOG.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/go-pkcs7/blob/main/SUPPORT.md) |
| Report a vulnerability | [Security policy](https://github.com/misiektoja/go-pkcs7/blob/main/SECURITY.md) |
| Contribute | [Contributing](https://github.com/misiektoja/go-pkcs7/blob/main/CONTRIBUTING.md) |

## Credits

go-pkcs7 continues the work of these projects and their contributors:

* [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7), the original implementation by Andrew
  Smith.
* [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7), the Mozilla fork.
* [smallstep/pkcs7](https://github.com/smallstep/pkcs7), the Smallstep fork this repository
  started from.

All three are MIT licensed. [NOTICE](https://github.com/misiektoja/go-pkcs7/blob/main/NOTICE)
records the origins of the code, including the copies of Go 1.23 `crypto/x509` and
`golang.org/x/crypto/cryptobyte` under `internal/`.

## Related projects

Other PKI projects from the same maintainer:

* [certrally](https://misiektoja.github.io/certrally/): a command line client for certificate enrollment over CMP, EST and SCEP
* [cmp-issuer](https://misiektoja.github.io/cmp-issuer/): a cert-manager external issuer for CMP servers
* [go-acme-server](https://misiektoja.github.io/go-acme-server/): an embeddable ACME server library for Go (RFC 8555)
* [go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/): a Go library for the Certificate Management Protocol (CMP) with a client and a server
* [go-pki-est](https://misiektoja.github.io/go-pki-est/): a Go library for Enrollment over Secure Transport (EST, RFC 7030) with a client and a server
* [go-pki-scep](https://misiektoja.github.io/go-pki-scep/): a Go library for SCEP (RFC 8894) with a client and a server handler
* [go-composite-mldsa](https://misiektoja.github.io/go-composite-mldsa/): a Go library for post-quantum composite ML-DSA signatures
* [go-tls-srp](https://github.com/misiektoja/go-tls-srp): TLS 1.2 with SRP password authentication (RFC 5054) for Go
