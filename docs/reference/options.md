# Options

Every algorithm choice and every relaxation is made per call through these structs. Their zero
values select the defaults listed here. Construct them with field names, because new fields may be
added, as the [Compatibility policy](compatibility.md) describes.

## SignerInfoConfig

Passed to `AddSigner`, `AddSignerChain` and `SignWithoutAttr`. `SignWithoutAttr` ignores it.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ExtraSignedAttributes` | `[]Attribute` | none | Signed attributes added after content-type, message-digest and signing-time |
| `ExtraUnsignedAttributes` | `[]Attribute` | none | Attributes outside the signature |
| `SigningTime` | `time.Time` | the current time | Value of the signing-time attribute, stored in UTC |

`Attribute` has a `Type` (an `asn1.ObjectIdentifier`) and a `Value` that `encoding/asn1` must be
able to encode.

## SignedData settings

Two methods on `SignedData` apply to the signers added after the call:

| Method | Default | Meaning |
| --- | --- | --- |
| `SetDigestAlgorithm(oid)` | `OIDDigestAlgorithmSHA256` | Digest of the content and the signed attributes |
| `SetEncryptionAlgorithm(oid)` | derived from the key and the digest | Signature algorithm identifier. For RSA keys `OIDEncryptionAlgorithmRSA` is also accepted. Any other value must equal the derived one |

## VerifyOptions

Passed to `Verify`.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `Roots` | `*x509.CertPool` | nil, no chain check | Trust anchors for the signer certificate chains |
| `Intermediates` | `[]*x509.Certificate` | none | Certificates that may complete a chain, in addition to those in the message |
| `SignerCertificates` | `[]*x509.Certificate` | none | Signer certificates for messages that do not carry them |
| `CurrentTime` | `time.Time` | the current time | Time at which chains are checked |
| `VerifyAtSigningTime` | `bool` | false | Check chains at the signing-time attribute when `CurrentTime` is zero |
| `KeyUsages` | `[]x509.ExtKeyUsage` | any usage | Extended key usages to accept. The chain must allow at least one of them |
| `AllowMD5` | `bool` | false | Accept signers that use the MD5 digest |

`Intermediates`, `CurrentTime`, `VerifyAtSigningTime` and `KeyUsages` matter only when `Roots` is
set. [Verification](../guide/verification.md) explains each check.

## EncryptOptions

Passed to `Encrypt` and `EncryptUsingPSK`.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ContentEncryption` | `ContentEncryptionAlgorithm` | `AES128CBC` | Content cipher |
| `KeyEncryption` | `KeyEncryptionAlgorithm` | `RSAPKCS1v15` | Key transport for each recipient. `EncryptUsingPSK` ignores it |
| `OAEPHash` | `crypto.Hash` | `crypto.SHA256` | RSAES-OAEP hash and MGF1 hash. Used only with `RSAOAEP` |

`OAEPHash` accepts `crypto.SHA1`, `crypto.SHA224`, `crypto.SHA256`, `crypto.SHA384` and
`crypto.SHA512`. Another value fails with `ErrUnsupportedKeyEncryptionHash`.

## DecryptOptions

Passed to `Decrypt` and `DecryptUsingPSK`.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ContentEncryptionAlgorithms` | `[]ContentEncryptionAlgorithm` | `DefaultContentDecryptionAlgorithms` | Content ciphers to accept |

`DefaultContentDecryptionAlgorithms` is `AES128CBC`, `AES192CBC`, `AES256CBC` and `DESEDE3CBC`. A
non-empty list replaces it, so add the defaults to the list when extending it, as
[Encryption and decryption](../guide/encryption.md#accepted-ciphers) shows. The key transport is
read from the message and needs no option.

`DefaultContentDecryptionAlgorithms` is an exported variable that every `Decrypt` and
`DecryptUsingPSK` call reads. Do not modify it. Pass `ContentEncryptionAlgorithms` instead.

## ParseOptions

Passed to `ParseWithOptions`. `Parse` uses the zero value.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `LegacyCertificateParser` | `bool` | false | When `crypto/x509` refuses a certificate because its authority key identifier is marked critical, parse every certificate of the message again with a copy of the Go 1.23 parser |

## PKCS7.Hasher

A parsed message has a `Hasher` field. When it is set, `Verify` calls its
`Hash(crypto.Hash, io.Reader) ([]byte, error)` method to compute the content digest that the
message-digest attribute is compared with. It is nil by default, which uses the standard library
hash.
