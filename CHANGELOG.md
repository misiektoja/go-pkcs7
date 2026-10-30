# Changelog

Notable changes to go-pkcs7, a continuation of
[smallstep/pkcs7](https://github.com/smallstep/pkcs7).

## [0.3.0] - 2026-10-30

First release as `github.com/misiektoja/go-pkcs7`. It lists the changes since smallstep/pkcs7
v0.2.3. Algorithms are chosen per call through option structs. The defaults are SHA-256 and
AES-128-CBC. Weak or malformed input is refused. Code written for smallstep/pkcs7 needs the
changes under Changed and Removed.

### Added
- **RSASSA-PSS signature verification** (RFC 4055).
- **`VerifyOptions`** set trust anchors, intermediates, the check time and required extended key
  usages. `SignerCertificates` verifies messages that leave out their signer certificate.
- **`EncryptOptions`** choose the cipher and PKCS #1 v1.5 or RSAES-OAEP key transport.
  **`DecryptOptions`** list the ciphers a decryption accepts. DES-EDE3-CBC and AES-192-CBC are new.
- **`Recipients`** and **`ContentEncryptionAlgorithm`** report who a message is encrypted for and
  with which cipher.
- **`DegenerateCRL`**, **`RemoveCertificates`** and **`SignerInfoConfig.SigningTime`** build the
  message forms SCEP answers use.
- **`ParseOptions.LegacyCertificateParser`** accepts certificates with a critical authority key
  identifier.

### Changed
- **Module path** `github.com/misiektoja/go-pkcs7`. Go 1.27.3 or newer is required.
- **`Verify` takes `VerifyOptions`** and replaces `VerifyWithChain` and `VerifyWithChainAtTime`.
  Chains are checked at the current time. Set `VerifyAtSigningTime` for archived signatures.
- **Keys are `crypto.Signer` and `crypto.Decrypter`**, so they can live in an HSM.
- **Signing uses SHA-256 and encryption uses AES-128-CBC** by default. They were SHA-1 and DES-CBC.
  The cipher constants are now `AES128CBC`, `AES192CBC`, `AES256CBC`, `DESEDE3CBC` and `DESCBC`.
- **MD5 signatures and DES-CBC content are refused** unless the options allow them.
- **Every decryption failure returns `ErrDecryptionFailed`**, so a sender cannot tell which step
  failed.

### Removed
- **AES-GCM content encryption** and **DSA**. The AES-GCM encoding did not follow RFC 5084.
- **Package-level settings** `ContentEncryptionAlgorithm`, `KeyEncryptionAlgorithm`,
  `KeyEncryptionHash`, `SetDefaultDigestAlgorithm` and
  `SetFallbackLegacyX509CertificateParserEnabled`. Use the option structs.

### Fixed
- **Signatures over unsorted signed attributes verify.**
- **RSAES-OAEP with SHA-256** names the matching MGF1 hash, so OpenSSL can decrypt it.
- **PKCS #1 v1.5 key transport** uses the RFC 3218 padding oracle countermeasure.
- **Malformed input is refused**: bad BER lengths, nesting deeper than 64 levels, trailing data,
  repeated signed attributes and a content-type attribute that does not match the content.
