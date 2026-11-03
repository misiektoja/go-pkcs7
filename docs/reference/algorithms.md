# Algorithms

## Content ciphers

`ContentEncryptionAlgorithm` selects the symmetric cipher of EnvelopedData and EncryptedData
content. Its zero value selects `AES128CBC`. `String` returns the name in the second column.

| Constant | Name | OID variable | Key length |
| --- | --- | --- | --- |
| `AES128CBC` | AES-128-CBC | `OIDEncryptionAlgorithmAES128CBC` (2.16.840.1.101.3.4.1.2) | 16 bytes |
| `AES192CBC` | AES-192-CBC | `OIDEncryptionAlgorithmAES192CBC` (2.16.840.1.101.3.4.1.22) | 24 bytes |
| `AES256CBC` | AES-256-CBC | `OIDEncryptionAlgorithmAES256CBC` (2.16.840.1.101.3.4.1.42) | 32 bytes |
| `DESEDE3CBC` | DES-EDE3-CBC | `OIDEncryptionAlgorithmDESEDE3CBC` (1.2.840.113549.3.7) | 24 bytes |
| `DESCBC` | DES-CBC | `OIDEncryptionAlgorithmDESCBC` (1.3.14.3.2.7) | 8 bytes |

Every cipher runs in CBC mode with PKCS #7 padding and a random IV, which the algorithm parameter
carries. `DefaultContentDecryptionAlgorithms` lists the ciphers decryption accepts by default, all
of these except `DESCBC`.

## Key transport

`KeyEncryptionAlgorithm` selects how `Encrypt` protects the content key for each recipient. Its zero
value selects `RSAPKCS1v15`.

| Constant | Name | OID variable |
| --- | --- | --- |
| `RSAPKCS1v15` | RSAES-PKCS1-v1_5 | `OIDEncryptionAlgorithmRSA` (1.2.840.113549.1.1.1) |
| `RSAOAEP` | RSAES-OAEP | `OIDEncryptionAlgorithmRSAESOAEP` (1.2.840.113549.1.1.7) |

RSAES-OAEP parameters use `OIDMaskGenerationFunctionMGF1` (1.2.840.113549.1.1.8) and, when a
message carries a label, `OIDOAEPSourcePSpecified` (1.2.840.113549.1.1.9).

## Digests

| OID variable | Digest | OID |
| --- | --- | --- |
| `OIDDigestAlgorithmMD5` | MD5 | 1.2.840.113549.2.5 |
| `OIDDigestAlgorithmSHA1` | SHA-1 | 1.3.14.3.2.26 |
| `OIDDigestAlgorithmSHA224` | SHA-224 | 2.16.840.1.101.3.4.2.4 |
| `OIDDigestAlgorithmSHA256` | SHA-256, the signing default | 2.16.840.1.101.3.4.2.1 |
| `OIDDigestAlgorithmSHA384` | SHA-384 | 2.16.840.1.101.3.4.2.2 |
| `OIDDigestAlgorithmSHA512` | SHA-512 | 2.16.840.1.101.3.4.2.3 |

Some signers, such as the Azure instance metadata attestation service, put an RSA signature
algorithm identifier in the digest algorithm field. `Verify` accepts that and uses its hash.

## Signature algorithms

RSA PKCS #1 v1.5:

| OID variable | Algorithm | OID |
| --- | --- | --- |
| `OIDEncryptionAlgorithmRSA` | rsaEncryption, with any digest | 1.2.840.113549.1.1.1 |
| `OIDEncryptionAlgorithmRSAMD5` | md5WithRSAEncryption | 1.2.840.113549.1.1.4 |
| `OIDEncryptionAlgorithmRSASHA1` | sha1WithRSAEncryption | 1.2.840.113549.1.1.5 |
| `OIDEncryptionAlgorithmRSASHA224` | sha224WithRSAEncryption | 1.2.840.113549.1.1.14 |
| `OIDEncryptionAlgorithmRSASHA256` | sha256WithRSAEncryption | 1.2.840.113549.1.1.11 |
| `OIDEncryptionAlgorithmRSASHA384` | sha384WithRSAEncryption | 1.2.840.113549.1.1.12 |
| `OIDEncryptionAlgorithmRSASHA512` | sha512WithRSAEncryption | 1.2.840.113549.1.1.13 |

`OIDEncryptionAlgorithmRSASSAPSS` (1.2.840.113549.1.1.10) is RSASSA-PSS. `Verify` accepts it when
its parameters are present, their hash and MGF1 hash both equal the signer digest, the trailer
field is 1 and the salt length is not negative. The library does not sign with it.

ECDSA:

| OID variable | Algorithm | OID |
| --- | --- | --- |
| `OIDDigestAlgorithmECDSASHA1` | ecdsa-with-SHA1 | 1.2.840.10045.4.1 |
| `OIDDigestAlgorithmECDSASHA256` | ecdsa-with-SHA256 | 1.2.840.10045.4.3.2 |
| `OIDDigestAlgorithmECDSASHA384` | ecdsa-with-SHA384 | 1.2.840.10045.4.3.3 |
| `OIDDigestAlgorithmECDSASHA512` | ecdsa-with-SHA512 | 1.2.840.10045.4.3.4 |

Despite the `OIDDigestAlgorithm` prefix these are signature algorithm identifiers. The curve
identifiers `OIDEncryptionAlgorithmECDSAP256` (1.2.840.10045.3.1.7), `OIDEncryptionAlgorithmECDSAP384`
(1.3.132.0.34) and `OIDEncryptionAlgorithmECDSAP521` (1.3.132.0.35) are accepted in the signature
algorithm field when verifying, because some signers write them there. They are never written.

When signing, the identifier is derived from the key and the digest:

| Key | Digest | Identifier written |
| --- | --- | --- |
| RSA | MD5, SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 | The matching `sha*WithRSAEncryption`. `rsaEncryption` after `SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSA)` |
| ECDSA | SHA-1, SHA-256, SHA-384 or SHA-512 | The matching `ecdsa-with-SHA*` |

## Content types and attributes

| OID variable | Meaning | OID |
| --- | --- | --- |
| `OIDData` | id-data | 1.2.840.113549.1.7.1 |
| `OIDSignedData` | id-signedData | 1.2.840.113549.1.7.2 |
| `OIDEnvelopedData` | id-envelopedData | 1.2.840.113549.1.7.3 |
| `OIDEncryptedData` | id-encryptedData | 1.2.840.113549.1.7.6 |
| `OIDAttributeContentType` | content-type attribute | 1.2.840.113549.1.9.3 |
| `OIDAttributeMessageDigest` | message-digest attribute | 1.2.840.113549.1.9.4 |
| `OIDAttributeSigningTime` | signing-time attribute | 1.2.840.113549.1.9.5 |

The OID variables are exported so callers can compare against them. Do not modify them, because the
library reads the same variables.
