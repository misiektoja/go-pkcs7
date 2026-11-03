# Parsing

`Parse` decodes one CMS ContentInfo into a `*PKCS7`. It reads the structure only. Signatures,
chains and CRLs are not checked until the caller asks for it.

## Input

`Parse` takes binary BER or DER. The input must hold exactly one ContentInfo with nothing after it.
PEM, the form OpenSSL writes with `-outform PEM`, must be decoded first:

```go
--8<-- "example_test.go:parse-pem"
```

`pem.Decode` ignores the block type, so it reads both the `PKCS7` blocks of `openssl smime` and
`openssl pkcs7` and the `CMS` blocks of `openssl cms`.

## BER

OpenSSL with `-stream` and Apple App Attest receipts, among others, use BER indefinite lengths.
`Parse` converts the input to DER lengths first and joins content that is split into
several OCTET STRING segments. The conversion refuses input that is malformed or built to exhaust
the parser:

* nesting deeper than 64 levels
* lengths longer than 4 octets or longer than the remaining data
* indefinite lengths on primitive elements
* end-of-contents octets outside an indefinite-length element
* data after the message

## What Parse fills in

| Content type | Fields and methods |
| --- | --- |
| SignedData | `Content`, `Certificates`, `CRLs` and `Signers`. Then `Verify`, `GetOnlySigner` and `UnmarshalSignedAttribute` |
| EnvelopedData | No fields. `Recipients`, `ContentEncryptionAlgorithm` and `Decrypt` |
| EncryptedData | No fields. `ContentEncryptionAlgorithm` and `DecryptUsingPSK` |

Any other content type fails with `ErrUnsupportedContentType`. An EnvelopedData message with a
recipient type other than an RSA certificate identified by issuer and serial number fails to parse
with an `encoding/asn1` error.

`Content` holds the encapsulated content of a SignedData message. It is empty for a detached
signature or a certificate bundle.

## Certificates and CRLs

The certificates in a SignedData message are parsed with `crypto/x509`. A certificate it
refuses makes `Parse` fail. They are not checked further until `Verify` builds a chain.

Some Windows SCEP clients send certificates whose authority key identifier extension is marked
critical, which RFC 5280 forbids and `crypto/x509` refuses. With `LegacyCertificateParser`,
`ParseWithOptions` then parses every certificate of the message again with a copy of the Go 1.23
parser that skips that check:

```go
--8<-- "example_test.go:legacy-parser"
```

The retry happens only for that one error. All certificates of such a message then come from the
old parser, which gets no fixes from later Go releases. Enable the option only where those clients
must be served.

`CRLs` holds the decoded revocation lists without any signature check. Encode one again and parse
it with `crypto/x509` to check it against the issuer:

```go
--8<-- "example_test.go:crl"
```

A certificate bundle is read the same way through `Certificates`. Nothing in a bundle is signed, so
treat its certificates as untrusted until a chain check accepts them.
