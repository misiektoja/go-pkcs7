# Migrating from smallstep/pkcs7

go-pkcs7 started from [smallstep/pkcs7](https://github.com/smallstep/pkcs7) v0.2.3. The package
name is still `pkcs7`, but the module path, several signatures and some defaults changed. This page
lists what code written for smallstep/pkcs7 needs. The
[changelog](https://github.com/misiektoja/go-pkcs7/blob/main/CHANGELOG.md) for 0.3.0 has the full
list.

## Module path

Replace the import path `github.com/smallstep/pkcs7` with `github.com/misiektoja/go-pkcs7` and run:

```bash
go get github.com/misiektoja/go-pkcs7
```

The module needs Go 1.27.3 or newer.

## API changes

These changes stop the old code from compiling:

| smallstep/pkcs7 | go-pkcs7 |
| --- | --- |
| `p7.Verify()` | `p7.Verify(pkcs7.VerifyOptions{})` |
| `p7.VerifyWithChain(roots)` | `p7.Verify(pkcs7.VerifyOptions{Roots: roots})`, see [Chain time](#chain-time) |
| `p7.VerifyWithChainAtTime(roots, t)` | `p7.Verify(pkcs7.VerifyOptions{Roots: roots, CurrentTime: t})` |
| `pkcs7.Encrypt(content, recipients)` | `pkcs7.Encrypt(content, recipients, pkcs7.EncryptOptions{})` |
| `pkcs7.EncryptUsingPSK(content, key)` | `pkcs7.EncryptUsingPSK(content, key, pkcs7.EncryptOptions{})` |
| `p7.Decrypt(cert, privateKey)` | `p7.Decrypt(cert, key, pkcs7.DecryptOptions{})` |
| `p7.DecryptUsingPSK(key)` | `p7.DecryptUsingPSK(key, pkcs7.DecryptOptions{})` |
| `pkcs7.ContentEncryptionAlgorithm = ...` | `EncryptOptions.ContentEncryption` |
| `pkcs7.KeyEncryptionAlgorithm = ...` | `EncryptOptions.KeyEncryption`, such as `pkcs7.RSAOAEP` |
| `pkcs7.KeyEncryptionHash = ...` | `EncryptOptions.OAEPHash` |
| `pkcs7.SetDefaultDigestAlgorithm(oid)` | `sd.SetDigestAlgorithm(oid)` on each `SignedData` |
| `pkcs7.SetFallbackLegacyX509CertificateParserEnabled(true)` | `pkcs7.ParseWithOptions(data, pkcs7.ParseOptions{LegacyCertificateParser: true})` |
| `pkcs7.EncryptionAlgorithmDESCBC`, `EncryptionAlgorithmAES128CBC`, `EncryptionAlgorithmAES256CBC` | `pkcs7.DESCBC`, `pkcs7.AES128CBC`, `pkcs7.AES256CBC` |
| `pkcs7.EncryptionAlgorithmAES128GCM`, `EncryptionAlgorithmAES256GCM` | Removed, see [Removed features](#removed-features) |
| `OIDDigestAlgorithmDSA`, `OIDDigestAlgorithmDSASHA1`, `OIDEncryptionAlgorithmAES128GCM`, `OIDEncryptionAlgorithmAES256GCM` | Removed |

`AddSigner`, `AddSignerChain` and `SignWithoutAttr` take a `crypto.Signer` and `Decrypt` takes a
`crypto.Decrypter` instead of `crypto.PrivateKey`. `*rsa.PrivateKey` is both and `*ecdsa.PrivateKey`
is a `crypto.Signer`, so code that passes them keeps compiling unless it holds the key in a
`crypto.PrivateKey` variable. A type assertion fixes that. `*dsa.PrivateKey` is not a
`crypto.Signer`, so code that signs with a DSA key no longer compiles.

## Changed defaults

These changes compile without errors but change the messages:

| Setting | smallstep/pkcs7 | go-pkcs7 |
| --- | --- | --- |
| Signing digest | SHA-1 | SHA-256 |
| Content cipher for `Encrypt` and `EncryptUsingPSK` | DES-CBC | AES-128-CBC |
| Content ciphers `Decrypt` and `DecryptUsingPSK` accept | All implemented | AES-CBC and DES-EDE3-CBC. DES-CBC must be listed in `DecryptOptions` |

A peer that only understands the old defaults needs them set explicitly, through
`SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)` or `EncryptOptions{ContentEncryption:
pkcs7.DESCBC}`.

## Chain time

`VerifyWithChain` checked the chain at the time in the signing-time attribute. Without that
attribute it used the current time. `Verify` with `Roots` checks it at the current time. Set
`VerifyAtSigningTime` to keep the old behavior for archived signatures, after reading
[Check time](guide/verification.md#check-time).

## Stricter checks

Messages that smallstep/pkcs7 accepted may now fail:

* Signed attributes must contain exactly one message-digest attribute and exactly one content-type
  attribute. The content type must equal the encapsulated content type.
* A digest algorithm field holding `rsaEncryption` or an ECDSA signature identifier is no longer
  read as a digest. RSA signature identifiers such as `sha256WithRSAEncryption` there are still
  accepted.
* Malformed BER, nesting deeper than 64 levels and trailing data after the message are refused.
* `Decrypt` returns `ErrDecryptionFailed` for every key or padding failure instead of a specific
  error.

The texts of several error variables changed, including `ErrNotEncryptedContent` and
`ErrUnsupportedAlgorithm`. Compare errors with `errors.Is`.

## New features

MD5 and SHA-224 digests, RSASSA-PSS verification, AES-192-CBC, encryption with DES-EDE3-CBC,
AES-CBC for `EncryptUsingPSK`, `VerifyOptions` with intermediates, signer certificates and key
usages, `Recipients`, `ContentEncryptionAlgorithm`, `DegenerateCRL`, `RemoveCertificates` and
`SignerInfoConfig.SigningTime` are new. RSAES-OAEP with a
hash other than SHA-1 now names the matching MGF1 hash, so OpenSSL can decrypt it.

## Removed features

* **AES-GCM.** The encoding smallstep/pkcs7 used did not follow RFC 5084, so its GCM messages cannot
  be decrypted here. Use AES-CBC.
* **DSA.** Signing with `*dsa.PrivateKey` and verifying DSA signatures are no longer supported.
