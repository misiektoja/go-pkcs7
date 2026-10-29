# Changelog

Notable changes to go-pkcs7. The library continues
[smallstep/pkcs7](https://github.com/smallstep/pkcs7), and the first release lists its changes
relative to smallstep/pkcs7 v0.2.3.

## [Unreleased] - TBD

The module is now `github.com/misiektoja/go-pkcs7` and needs Go 1.27.3. Algorithms are chosen per
call through option structs instead of package variables. Defaults move to SHA-256 signing and
AES-128-CBC encryption. Verification and decryption refuse malformed and weak input that
smallstep/pkcs7 accepted. Callers need code changes, which the Changed section lists.

### Added
- **RSASSA-PSS verification** (RFC 4055), with the hash, mask generation function and salt length
  taken from the signature parameters.
- **`VerifyOptions`** for `Verify`: trust anchors, extra intermediates, the check time, required
  extended key usages, MD5 acceptance and `SignerCertificates` for responses that do not carry
  their signer certificate, which some SCEP servers send.
- **`EncryptOptions`** for `Encrypt` and `EncryptUsingPSK`: the content cipher, PKCS #1 v1.5 or
  RSAES-OAEP key transport and the OAEP hash. **DES-EDE3-CBC** and **AES-192-CBC** encryption
  are new.
- **`DecryptOptions`** for `Decrypt` and `DecryptUsingPSK`, listing the content ciphers to accept.
  A cipher the options leave out returns `ErrContentEncryptionNotAllowed`.
- **`Recipients`** lists the issuer and serial number of each recipient of an enveloped message,
  so a server that holds several keys can pick the one that decrypts it.
- **`ContentEncryptionAlgorithm`** reports the cipher of a received message, so a responder can
  answer with the cipher the requester chose.
- **`ParseOptions.LegacyCertificateParser`** enables the parser for certificates that mark the
  authority key identifier critical, for one call. `ParseWithOptions` takes it.
- **`SignerInfoConfig.SigningTime`** sets the signing-time attribute.
- **`DegenerateCRL`** builds a message that carries one CRL and no signers, the form of a SCEP
  GetCRL response.
- **`RemoveCertificates`** leaves every certificate out of a signed message, for recipients that
  already hold the signer certificate.

### Changed
- **The module path** is `github.com/misiektoja/go-pkcs7`. Go 1.27.3 is the minimum.
- **`Verify` takes `VerifyOptions`** and replaces `VerifyWithChain` and `VerifyWithChainAtTime`.
  Chains are checked at the current time. smallstep/pkcs7 checked them at the signing time, which
  the signer chooses. Set `VerifyAtSigningTime` for archived signatures.
- **`AddSigner`, `AddSignerChain` and `SignWithoutAttr` take a `crypto.Signer`** and
  **`Decrypt` takes a `crypto.Decrypter`**, so keys may live in an HSM.
- **Signing uses SHA-256** unless `SetDigestAlgorithm` names another digest. It used SHA-1.
- **Encryption uses AES-128-CBC** with PKCS #1 v1.5 key transport by default. It used DES-CBC.
  The cipher constants are `AES128CBC`, `AES192CBC`, `AES256CBC`, `DESEDE3CBC` and `DESCBC` in
  place of `EncryptionAlgorithmAES128CBC` and the others.
- **MD5 signatures** are verified only with `VerifyOptions.AllowMD5`.
- **Single DES content** is decrypted only when `DecryptOptions` lists `DESCBC`.
- **Decryption failures** return `ErrDecryptionFailed` for every key transport and padding error,
  so the error does not tell a sender which step failed.

### Removed
- **AES-GCM content encryption.** Its encoding did not follow RFC 5084 and OpenSSL refuses AEAD
  ciphers in EnvelopedData. AuthEnvelopedData (RFC 5083) is the standard form and is not
  implemented.
- **DSA signing and verification.**
- **The package variables** `ContentEncryptionAlgorithm`, `KeyEncryptionAlgorithm` and
  `KeyEncryptionHash` and the functions `SetDefaultDigestAlgorithm` and
  `SetFallbackLegacyX509CertificateParserEnabled`. The option structs replace them. The first two
  names are now the types of the option fields.

### Fixed
- **Signed attributes are verified in the order received.** A signature from a client that did not
  sort its attributes failed to verify.
- **The content-type attribute must match the content type**, and every signed attribute must
  appear once with one value (RFC 5652 section 5.3).
- **RSAES-OAEP parameters name the MGF1 hash.** Messages encrypted with OAEP and SHA-256 declared
  SHA-1 for the mask, so OpenSSL could not decrypt them.
- **PKCS #1 v1.5 key transport uses the padding oracle countermeasure** of RFC 3218 section 2.3.2,
  and the content padding is checked in constant time.
- **Malformed BER is refused.** Lengths that overrun their parent, nesting deeper than 64 levels,
  misplaced end-of-contents octets and trailing data return errors. Indefinite lengths convert in
  linear time.
- **Messages with trailing data after the content info** are refused.
