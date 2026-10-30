# go-pkcs7

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pkcs7?style=flat-square&color=blue)](https://github.com/misiektoja/go-pkcs7/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pkcs7.svg)](https://pkg.go.dev/github.com/misiektoja/go-pkcs7)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pkcs7/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkcs7/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/go-pkcs7/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pkcs7/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pkcs7&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pkcs7)

go-pkcs7 is a Go library that parses and builds the parts of the Cryptographic Message Syntax
(CMS, RFC 5652) that certificate enrollment protocols use. SCEP (RFC 8894) wraps every request and
response in these messages. [go-pki-scep](https://github.com/misiektoja/go-pki-scep) is built on
this library.

It signs and verifies SignedData, encrypts and decrypts EnvelopedData for RSA recipients and
encrypts and decrypts EncryptedData with a pre-shared key. Algorithm choices are made per call
through option structs, so two parts of one program can apply different policies. Nothing is
configured through package variables.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
* [Security defaults](#security-defaults)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [Credits](#credits)
* [Support](#support)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-pkcs7
```

The module needs Go 1.27.3 or newer and has no dependencies outside the standard library. The
package is imported as `pkcs7`. The API may still change before v1.0.0, as
[CHANGELOG.md](CHANGELOG.md) records.

## Scope

| Content type | Coverage |
| --- | --- |
| SignedData (RFC 5652 section 5) | Signing with RSA PKCS #1 v1.5 or ECDSA keys through `crypto.Signer`. Verification of RSA PKCS #1 v1.5, RSASSA-PSS (RFC 4055) and ECDSA signatures. Attached and detached content, several signers and messages that carry only certificates or a CRL |
| EnvelopedData (RFC 5652 section 6) | RSA key transport with PKCS #1 v1.5 or RSAES-OAEP (RFC 8017). Decryption through `crypto.Decrypter`, so the recipient key may live in an HSM |
| EncryptedData (RFC 5652 section 8) | Content encrypted with a pre-shared key |

Digests are SHA-256, SHA-384, SHA-512, SHA-224 and SHA-1, plus MD5 on request. Content ciphers are
AES-128-CBC, AES-192-CBC, AES-256-CBC, DES-EDE3-CBC and DES-CBC. Input may be BER, including
indefinite lengths, and is converted to DER before parsing.

The tests check the library against OpenSSL whenever `openssl` is on the `PATH`. OpenSSL reads the
signed messages and decrypts the enveloped messages this library builds. This library verifies
OpenSSL signatures, including RSASSA-PSS, and decrypts OpenSSL RSAES-OAEP messages.

## Getting started

Sign content with a certificate and its key, then verify the result against a trust anchor:

```go
sd, err := pkcs7.NewSignedData(content)
if err != nil {
	return err
}
if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
	return err
}
signed, err := sd.Finish()
if err != nil {
	return err
}

p7, err := pkcs7.Parse(signed)
if err != nil {
	return err
}
roots := x509.NewCertPool()
roots.AddCert(caCert)
if err := p7.Verify(pkcs7.VerifyOptions{Roots: roots}); err != nil {
	return err
}
```

Encrypt for a recipient certificate and decrypt with the recipient's key:

```go
enveloped, err := pkcs7.Encrypt(content, []*x509.Certificate{recipient}, pkcs7.EncryptOptions{
	ContentEncryption: pkcs7.AES256CBC,
	KeyEncryption:     pkcs7.RSAOAEP,
})
if err != nil {
	return err
}

p7, err := pkcs7.Parse(enveloped)
if err != nil {
	return err
}
plaintext, err := p7.Decrypt(recipient, recipientKey, pkcs7.DecryptOptions{})
```

`ExampleSignedData` in the package documentation builds a detached signature.

## Security defaults

The defaults suit current peers. Each relaxation is an option on the call that needs it.

* **Signing** uses SHA-256 unless `SetDigestAlgorithm` names another digest.
* **Verification** checks signer chains at the current time. `VerifyOptions.VerifyAtSigningTime`
  uses the signing-time attribute instead. The signer chooses that time, so set it only for
  archived signatures. Without `VerifyOptions.Roots` the signatures are checked and no chain is
  built.
* **MD5 signatures** are refused unless `VerifyOptions.AllowMD5` is set.
* **Signed attributes** must carry exactly one content type, equal to the encapsulated content
  type, and exactly one message digest. They are verified in the order received.
* **Decryption** accepts AES-CBC and DES-EDE3-CBC. Single DES needs
  `DecryptOptions.ContentEncryptionAlgorithms`. Every key transport and padding failure returns
  `ErrDecryptionFailed`. PKCS #1 v1.5 key transport uses the RFC 3218 countermeasure, so the error
  does not tell a sender which step failed.
* **Encryption** uses AES-128-CBC with PKCS #1 v1.5 key transport by default. `EncryptOptions`
  selects AES-256-CBC or RSAES-OAEP for peers that accept them.
* **Embedded certificates** are parsed by `crypto/x509`. `ParseOptions.LegacyCertificateParser`
  also accepts certificates that mark the authority key identifier critical, which some Windows
  SCEP clients send.

## Documentation

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pkcs7)
describes every exported type and option. Repository files:

* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists the copied third-party code and its licenses.
* [CHANGELOG.md](CHANGELOG.md) records user-visible changes per release.

## Limitations

* No AuthEnvelopedData (RFC 5083) and no AES-GCM content encryption.
* No key agreement or key encryption key recipients. EnvelopedData recipients are RSA certificates.
* No signing with RSASSA-PSS or Ed25519 and no verification of Ed25519 or DSA signatures.
* No countersignatures, signed receipts or other CMS content types such as DigestedData and
  AuthenticatedData.
* No streaming. Messages are held in memory while they are parsed or built.

## Credits

go-pkcs7 continues the work of these projects and their contributors:

* [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7), the original implementation by Andrew
  Smith.
* [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7), the Mozilla fork.
* [smallstep/pkcs7](https://github.com/smallstep/pkcs7), the Smallstep fork this repository
  started from.

All three are MIT licensed. [NOTICE](NOTICE) records the origins of the code, including the Go
standard library code copied under `internal/`.

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security
reports.

## License

Licensed under the [MIT License](LICENSE). The copies of Go code under `internal/` keep the Go
BSD-style license, as [NOTICE](NOTICE) describes.
