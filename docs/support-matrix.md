# Support matrix

## Content types

| Content type | Create | Read |
| --- | --- | --- |
| SignedData (RFC 5652 section 5) | `NewSignedData`, `DegenerateCertificate` and `DegenerateCRL` | `Parse`, then `Verify` |
| EnvelopedData (RFC 5652 section 6) | `Encrypt` | `Parse`, then `Decrypt` |
| EncryptedData (RFC 5652 section 8) | `EncryptUsingPSK` | `Parse`, then `DecryptUsingPSK` |

`Parse` returns `ErrUnsupportedContentType` for every other content type, including DigestedData,
AuthenticatedData and AuthEnvelopedData (RFC 5083).

## Signatures

| Algorithm | Signing | Verification |
| --- | --- | --- |
| RSA PKCS #1 v1.5 | MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 | The same digests. MD5 only with `VerifyOptions.AllowMD5` |
| RSASSA-PSS (RFC 4055) | No | SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 with explicit parameters |
| ECDSA | SHA-1, SHA-256, SHA-384 and SHA-512 | The same digests |
| Ed25519, DSA and others | No | No |

Signing uses SHA-256 unless `SetDigestAlgorithm` selects another digest. The tests sign and verify
with RSA keys of 2048, 3072 and 4096 bits and ECDSA keys on P-256, P-384 and P-521.

The signature algorithm identifier written for a signer is `sha256WithRSAEncryption` or
`ecdsa-with-SHA256` for the default digest. `SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSA)`
writes `rsaEncryption` instead for RSA signers. Verification accepts both forms for RSA. For ECDSA
it also accepts a curve identifier in place of the signature algorithm, which some signers write.
That form works with any supported digest.
[Algorithms](reference/algorithms.md) lists every identifier.

## Key transport

EnvelopedData recipients are RSA certificates identified by issuer and serial number.

| Key transport | Encrypt | Decrypt |
| --- | --- | --- |
| RSAES-PKCS1-v1_5 | Yes, the default | Yes, with the RFC 3218 countermeasure |
| RSAES-OAEP (RFC 8017) | SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 for the hash and MGF1, SHA-256 by default | The same hashes. The OAEP hash and the MGF1 hash may differ and a label is accepted |

Recipients identified by subject key identifier, key agreement (ECDH), key encryption key and
password recipients are not supported. `Parse` fails on a message that contains one.

## Content ciphers

| Constant | Cipher | Key | Encrypt | Decrypt by default |
| --- | --- | --- | --- | --- |
| `AES128CBC` | AES-128-CBC | 16 bytes | Yes, the default | Yes |
| `AES192CBC` | AES-192-CBC | 24 bytes | Yes | Yes |
| `AES256CBC` | AES-256-CBC | 32 bytes | Yes | Yes |
| `DESEDE3CBC` | DES-EDE3-CBC | 24 bytes | Yes | Yes |
| `DESCBC` | DES-CBC | 8 bytes | Yes | No, it must be listed in `DecryptOptions` |

The same ciphers apply to EnvelopedData and EncryptedData. AES-GCM and other authenticated modes are
not supported.

## Message forms

| Form | Supported |
| --- | --- |
| Attached content | Yes |
| Detached content | Yes, `Detach` when signing and `p7.Content` when verifying |
| Several signers | Yes, each with its own digest algorithm |
| Signer without signed attributes | Yes, `SignWithoutAttr` |
| Signer certificate left out of the message | Yes, `RemoveCertificates` when signing and `VerifyOptions.SignerCertificates` when verifying |
| Certificates only, the form of a `.p7b` file | Yes, `DegenerateCertificate` |
| One CRL only, the form of a SCEP GetCRL response | Yes, `DegenerateCRL` |
| Encapsulated content type other than id-data | Read and verify only. Signing always uses id-data |
| Countersignatures and signed receipts | No |

## Encodings

`Parse` accepts BER and DER. Indefinite lengths are converted to definite ones and constructed OCTET
STRINGs that hold the content are joined. PEM is not read directly: decode it with `encoding/pem`
first, as [Parsing](guide/parsing.md) shows.

The library writes definite lengths and sorts signed and unsigned attributes as DER requires. Its
output is not always strict DER:

* Certificates are written in the order they were added, not sorted.
* `DegenerateCertificate` copies its input bytes without parsing them.
* RSAES-OAEP parameters with SHA-1 spell out the SHA-1 default instead of omitting it.

## Platforms

CI builds and tests the module on Linux and macOS and builds it on Windows, with the Go version
`go.mod` declares. The tests that call OpenSSL run where `openssl` is on the `PATH`.
