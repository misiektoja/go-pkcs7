# Security model

This page states what the library guarantees, what it leaves to the caller and how it treats
hostile input. Report a suspected vulnerability as the
[security policy](https://github.com/misiektoja/go-pkcs7/blob/main/SECURITY.md) describes.

## What a successful Verify means

When `Verify` returns nil, every signer of the message passed these checks:

* The signature is valid for the public key in the signer certificate, with a signature algorithm
  that suits the key type and the digest.
* With signed attributes, the message-digest attribute equals the digest of `p7.Content` and the
  content-type attribute equals the encapsulated content type. Each appears exactly once. The
  digests are compared in constant time.
* A signing-time attribute, when present, falls within the signer certificate validity.
* When `VerifyOptions.Roots` is set, `crypto/x509` built a chain from the signer certificate to a
  root at the check time and the chain allows at least one of the extended key usages in
  `KeyUsages`.

## What the caller decides

* **Trust.** Without `Roots` no chain is built. The caller must then decide whether the signer
  certificate is acceptable, for example by comparing it with a certificate it already holds.
* **Revocation.** `Verify` does not consult CRLs or OCSP. CRLs carried in a message are returned
  without any check.
* **Key usage.** `Verify` checks extended key usages only through `KeyUsages`. It does not check the
  key usage extension or certificate policies of the signer certificate.
* **Signing time.** The signer chooses the signing-time value. `VerifyAtSigningTime` should be used
  only when that time is trusted for another reason.
* **Recipients.** `Encrypt` does not check the validity or the key usage of recipient
  certificates.
* **Input size.** The library holds the whole message in memory and does not limit its size. Bound
  the input before calling `Parse`, for example with `http.MaxBytesReader` for an HTTP body.

## Algorithms

The defaults avoid broken algorithms. Each relaxation is an option on the call that needs it.

| Algorithm | Default behavior |
| --- | --- |
| MD5 digest | Refused by `Verify` unless `AllowMD5` is set. Signing with it requires `SetDigestAlgorithm` |
| SHA-1 digest | Accepted by `Verify`. Signing with it requires `SetDigestAlgorithm` |
| DES-CBC content | Refused by `Decrypt` and `DecryptUsingPSK` unless listed in `DecryptOptions`. Encryption with it requires `EncryptOptions` |
| DES-EDE3-CBC content | Accepted by `Decrypt` and `DecryptUsingPSK` |
| PKCS #1 v1.5 key transport | The default for `Encrypt` because SCEP peers expect it. Accepted by `Decrypt` with the countermeasure below |

## Decryption failures

PKCS #1 v1.5 key transport is open to Bleichenbacher's padding oracle attack when a receiver
reveals whether the padding was valid. `Decrypt` applies the RFC 3218 countermeasure. It asks the
key for a random content key of the right length when the padding is bad and then continues as
it would with any wrong key. Every failure to decrypt the content key or the
content returns the same `ErrDecryptionFailed`. The content padding is removed in constant
time.

A `crypto.Decrypter` other than `*rsa.PrivateKey` receives `*rsa.PKCS1v15DecryptOptions` with
`SessionKeyLen` set and must implement the countermeasure itself to be safe.

## Confidentiality without integrity

EnvelopedData and EncryptedData use CBC mode, which hides the content but does not authenticate it.
A changed ciphertext or a wrong key is usually reported as `ErrDecryptionFailed` but can also
decrypt to garbage. Sign the message when the receiver must detect changes. AuthEnvelopedData with
AES-GCM is not supported.

## Hostile input

`Parse` accepts input from untrusted peers. The BER converter refuses nesting deeper than 64
levels, lengths longer than four octets or beyond the end of the input, indefinite lengths on
primitive elements, stray end-of-contents octets and trailing data.

Two fuzz targets cover this code. `FuzzBer2Der` checks that the converter never panics and that its
output converts to itself. `FuzzParse` checks that parsing, verification and decryption of
arbitrary input return errors instead of panicking. CI runs each for 30 seconds on every push and
pull request to `dev` and `main`.

## Certificates

Embedded certificates are parsed by `crypto/x509`. One it refuses makes `Parse` fail.
`ParseOptions.LegacyCertificateParser` acts only when `crypto/x509` refuses a certificate because
its authority key identifier is marked critical. It then parses every certificate of the message
again with a copy of the Go 1.23 parser, not only the refused one. That copy lives under
`internal/legacy/x509` and gets no fixes from later Go releases, so enable the option only where
the Windows SCEP clients that need it must be served.

## Randomness

Content keys, IVs, RSA encryption padding and signatures use `crypto/rand`.
