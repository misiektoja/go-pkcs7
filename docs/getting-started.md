# Getting started

This page adds the module to a project, signs and verifies a message and encrypts content for a
recipient certificate.

## Install

```bash
go get github.com/misiektoja/go-pkcs7
```

The module needs Go 1.27.3 or newer and has no dependencies outside the standard library. The
package is imported as `pkcs7`:

```go
import "github.com/misiektoja/go-pkcs7"
```

The API may still change before v1.0.0, as the [Compatibility policy](reference/compatibility.md)
describes.

## Sign and verify

`NewSignedData` starts a message over the content. `AddSigner` signs it with the signer
certificate `cert` and its private key `key`, an RSA or ECDSA `crypto.Signer`. `Finish` returns the
encoded message:

```go
--8<-- "example_test.go:sign"
```

The receiver parses the message and verifies it against the CA certificate it trusts:

```go
--8<-- "example_test.go:verify"
```

`Verify` checks the message digest, the signed attributes and the signature of every signer. With
`Roots` set it also builds a chain from each signer certificate to one of the roots. Without
`Roots` it checks the signatures only, so the caller must decide whether to trust the signer.
[Verification](guide/verification.md) covers the options.

## Encrypt and decrypt

`Encrypt` creates an EnvelopedData message for one or more RSA recipient certificates:

```go
--8<-- "example_test.go:encrypt"
```

The recipient decrypts it with its certificate and private key:

```go
--8<-- "example_test.go:decrypt"
```

The defaults are AES-128-CBC and PKCS #1 v1.5 key transport, which SCEP peers expect. This example
selects AES-256-CBC and RSAES-OAEP instead. [Encryption and decryption](guide/encryption.md)
explains the choices.

## Run the examples

Apart from the import line above, the Go listings on this site come from `example_test.go` in the
repository, where each one runs as a Go example and checks its output. Run them from a clone:

```bash
go test -run Example -v .
```

## Next steps

* [Support matrix](support-matrix.md) lists the algorithms and message forms.
* [Security model](security/security-model.md) explains what `Verify` and `Decrypt` guarantee and
  what they leave to the caller.
* [Known limitations](known-limitations.md) lists what is not supported.
