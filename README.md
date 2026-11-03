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
through option structs, so two parts of one program can apply different policies. Signing and
decryption keys may live in an HSM.

## Contents

* [Install](#install)
* [Scope](#scope)
* [Getting started](#getting-started)
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
package is imported as `pkcs7`.

## Scope

| Content type | Coverage |
| --- | --- |
| SignedData | Signing with RSA PKCS #1 v1.5 and ECDSA. Verification of RSA PKCS #1 v1.5, RSASSA-PSS and ECDSA. Attached and detached content, several signers, certificate and CRL bundles |
| EnvelopedData | RSA key transport with PKCS #1 v1.5 or RSAES-OAEP. AES-CBC and DES-EDE3-CBC content |
| EncryptedData | Content encrypted with a pre-shared key |

Input may be BER or DER. The tests check the library against OpenSSL, see
[OpenSSL](https://misiektoja.github.io/go-pkcs7/interoperability/openssl/). The API may still
change before v1.0.0 as described in the
[Compatibility policy](https://misiektoja.github.io/go-pkcs7/reference/compatibility/).

## Getting started

Sign content with a certificate and its key, then verify the result against the CA certificate:

```go
sd, err := pkcs7.NewSignedData([]byte("hello, CMS"))
if err != nil {
	log.Fatal(err)
}
if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
	log.Fatal(err)
}
signed, err := sd.Finish()
if err != nil {
	log.Fatal(err)
}

p7, err := pkcs7.Parse(signed)
if err != nil {
	log.Fatal(err)
}
roots := x509.NewCertPool()
roots.AddCert(caCert)
if err := p7.Verify(pkcs7.VerifyOptions{Roots: roots}); err != nil {
	log.Fatal(err)
}
```

[Getting started](https://misiektoja.github.io/go-pkcs7/getting-started/) continues with
encryption. The code runs as `Example_signAndVerify` in `example_test.go`.

## Documentation

Full documentation is at [misiektoja.github.io/go-pkcs7](https://misiektoja.github.io/go-pkcs7/).

* [Getting started](https://misiektoja.github.io/go-pkcs7/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-pkcs7/support-matrix/)
* [Signing](https://misiektoja.github.io/go-pkcs7/guide/signing/) and [Verification](https://misiektoja.github.io/go-pkcs7/guide/verification/)
* [Encryption and decryption](https://misiektoja.github.io/go-pkcs7/guide/encryption/) and [Pre-shared keys](https://misiektoja.github.io/go-pkcs7/guide/pre-shared-keys/)
* [Parsing](https://misiektoja.github.io/go-pkcs7/guide/parsing/)
* [Options](https://misiektoja.github.io/go-pkcs7/reference/options/), [Algorithms](https://misiektoja.github.io/go-pkcs7/reference/algorithms/) and [Errors](https://misiektoja.github.io/go-pkcs7/reference/errors/)
* [Security model](https://misiektoja.github.io/go-pkcs7/security/security-model/)
* [Migrating from smallstep/pkcs7](https://misiektoja.github.io/go-pkcs7/migrating/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pkcs7)
describes every exported type. Repository files:

* [SUPPORT.md](SUPPORT.md) explains where to ask and what to include.
* [CONTRIBUTING.md](CONTRIBUTING.md) lists the development checks.
* [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
* [DEPENDENCIES.md](DEPENDENCIES.md) lists the copied third-party code and its licenses.
* [CHANGELOG.md](CHANGELOG.md) records user-visible changes per release.

## Limitations

* No AuthEnvelopedData (RFC 5083) and no AES-GCM content encryption.
* No key agreement, key encryption key or password recipients. EnvelopedData recipients are RSA
  certificates.
* No signing with RSASSA-PSS or Ed25519 and no verification of Ed25519 or DSA signatures.
* No streaming. Messages are held in memory while they are parsed or built.

[Known limitations](https://misiektoja.github.io/go-pkcs7/known-limitations/) lists the rest.

## Credits

go-pkcs7 continues the work of these projects and their contributors:

* [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7), the original implementation by Andrew
  Smith.
* [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7), the Mozilla fork.
* [smallstep/pkcs7](https://github.com/smallstep/pkcs7), the Smallstep fork this repository
  started from.

All three are MIT licensed. [NOTICE](NOTICE) records the origins of the code, including the copies of
Go 1.23 `crypto/x509` and `golang.org/x/crypto/cryptobyte` under `internal/`.

## Support

[SUPPORT.md](SUPPORT.md) directs usage questions, bug reports, feature requests and security
reports.

## License

Licensed under the [MIT License](LICENSE). The copies of Go code under `internal/` keep the Go
BSD-style license, as [NOTICE](NOTICE) describes.
