# Verification

`Verify` checks the signers of a parsed SignedData message. Parsing alone checks nothing, so call
`Verify` before using the content or the signed attributes.

```go
--8<-- "example_test.go:verify"
```

## What Verify checks

`Verify` fails when the message has no signers. Otherwise it checks every signer and returns the
first failure, so a message is accepted only when all of its signatures are valid. For each signer
it:

1. Finds the signer certificate by issuer and serial number, first among the certificates in the
   message and then in `VerifyOptions.SignerCertificates`.
2. Refuses the MD5 digest unless `VerifyOptions.AllowMD5` is set.
3. When the signer has signed attributes, requires exactly one content-type attribute equal to the
   encapsulated content type and exactly one message-digest attribute equal to the digest of
   `p7.Content`. A signing-time attribute, when present, must fall within the validity of the
   signer certificate.
4. Checks the signature over the signed attributes as they were received. A signer without signed
   attributes signs the content itself. The signature algorithm must suit the key and the digest.
5. When `VerifyOptions.Roots` is set, builds a chain from the signer certificate to one of the
   roots.

Without `Roots`, step 5 is skipped. The signatures are then known to come from the keys of the
certificates the message names, but nothing says those certificates are trustworthy. Set `Roots`
unless the caller checks the signer certificate itself, for example by comparing it with a
certificate it already holds.

## Trust anchors and intermediates

The chain is built with `crypto/x509` from the signer certificate through the certificates in the
message and `VerifyOptions.Intermediates` to a certificate in `Roots`. A CA that does not send its
intermediates can still be verified when the receiver supplies them in `Intermediates`.

`KeyUsages` lists the extended key usages to accept, for example
`[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}`. The chain passes when it allows at least one
of them. When the list is empty, any usage is accepted. `crypto/x509` treats a certificate without
an extended key usage extension as valid for any usage.

Chain errors wrap the `crypto/x509` error, so `errors.As` finds an `x509.CertificateInvalidError`
or an `x509.UnknownAuthorityError`.

## Check time

The chain is checked at the current time by default. Two options change that:

* `CurrentTime` checks the chain at a fixed time.
* `VerifyAtSigningTime` checks it at the time in the signing-time attribute when `CurrentTime` is
  zero. A signer without that attribute is checked at the current time.

The signer chooses the signing time, so it proves nothing about when the signature was made. Use
`VerifyAtSigningTime` only for archived signatures whose signing time you have reason to trust,
such as documents you stored yourself:

```go
--8<-- "example_test.go:signing-time"
```

The signing time is always compared with the signer certificate validity, with or without `Roots`.
A signing time outside it fails with a `*SigningTimeNotValidError`.

## Detached content

A detached signature carries no content, so `p7.Content` is empty after `Parse`. Set it to the
signed bytes before calling `Verify`, as [Signing](signing.md#detached-signatures) shows. The bytes
must match exactly. OpenSSL, for example, converts line endings to CRLF when it signs without
`-binary`.

## Signer certificates outside the message

Some SCEP servers answer without their signer certificate. The receiver passes the certificate it
expects in `SignerCertificates`:

```go
--8<-- "example_test.go:without-certificates"
```

A certificate in `SignerCertificates` is used only when the message does not carry a certificate
with the same issuer and serial number. It still goes through the chain check when `Roots` is set.

## Reading signer information

* `p7.Signers` holds the parsed signer infos. Its length is the number of signers.
* `GetOnlySigner` returns the signer certificate when the message has exactly one signer and
  carries its certificate. It returns nil otherwise.
* `UnmarshalSignedAttribute` decodes a signed attribute of the first signer. The attribute must
  appear once with a single value. It returns `ErrAttributeNotFound` when the attribute is absent.
  [Signing](signing.md#signed-attributes) shows an example.

## Custom hashing

`p7.Hasher` replaces the standard library hash when `Verify` computes the content digest for the
message-digest attribute. It does not apply to the hash of the signed attributes or to signers
without signed attributes.

## Errors

| Error | Cause |
| --- | --- |
| `*MessageDigestMismatchError` | The content does not match the message-digest attribute. The content was changed or a detached signature was given the wrong bytes |
| `*SigningTimeNotValidError` | The signing time is outside the signer certificate validity |
| `pkcs7: no certificate for signer` | Neither the message nor `SignerCertificates` holds the signer certificate |
| `pkcs7: signer uses the MD5 digest, which is not allowed` | The signer uses MD5 and `AllowMD5` is not set |
| `pkcs7: failed to verify certificate chain: ...` | The chain to `Roots` cannot be built at the check time or allows none of the usages in `KeyUsages` |

[Errors](../reference/errors.md) lists more errors and how to compare them.
