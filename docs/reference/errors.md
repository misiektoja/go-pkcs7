# Errors

Compare errors with `errors.Is` and `errors.As`, not by their text. Some sentinel errors are
returned wrapped. The texts of other errors may change in any release.

## Sentinel errors

| Error | Returned by | Meaning |
| --- | --- | --- |
| `ErrUnsupportedContentType` | `Parse`, `ParseWithOptions` | The content type is not SignedData, EnvelopedData or EncryptedData |
| `ErrAttributeNotFound` | `UnmarshalSignedAttribute`, `Verify` | The first signer has no signed attribute of that type. `Verify` returns it wrapped when a signer lacks the content-type or message-digest attribute |
| `ErrUnsupportedEncryptionAlgorithm` | `Encrypt`, `EncryptUsingPSK` | `EncryptOptions.ContentEncryption` is not a known constant |
| `ErrUnsupportedKeyEncryptionAlgorithm` | `Encrypt` | `EncryptOptions.KeyEncryption` is not a known constant |
| `ErrUnsupportedKeyEncryptionHash` | `Encrypt` | `EncryptOptions.OAEPHash` is not SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 |
| `ErrUnsupportedKeyType` | `Encrypt` | A recipient certificate does not hold an RSA key |
| `ErrPSKNotProvided` | `EncryptUsingPSK` | The key is nil |
| `ErrNotEncryptedContent` | `Decrypt`, `DecryptUsingPSK`, `Recipients`, `ContentEncryptionAlgorithm` | The message is not of the content type the method needs |
| `ErrUnsupportedAlgorithm` | `Decrypt`, `DecryptUsingPSK`, `ContentEncryptionAlgorithm` | The content cipher is not one this library implements |
| `ErrContentEncryptionNotAllowed` | `Decrypt`, `DecryptUsingPSK` | The content cipher is not in `DecryptOptions.ContentEncryptionAlgorithms`. Returned wrapped with the cipher name |
| `ErrUnsupportedAsymmetricEncryptionAlgorithm` | `Decrypt` | The recipient uses a key transport other than PKCS #1 v1.5 or RSAES-OAEP |
| `ErrDecryptionFailed` | `Decrypt`, `DecryptUsingPSK` | The content key or the content could not be decrypted |

`ErrDecryptionFailed` covers every failure that depends on the key: an error from the
`crypto.Decrypter`, a content key of the wrong length and bad padding. It does not say which one
happened, so a sender cannot use it as a padding oracle.

## Error types

`Verify` returns these as pointers. Read their fields with `errors.As`.

| Type | Fields | Meaning |
| --- | --- | --- |
| `MessageDigestMismatchError` | `ExpectedDigest`, `ActualDigest` | The message-digest attribute does not match the digest of `p7.Content` |
| `SigningTimeNotValidError` | `SigningTime`, `NotBefore`, `NotAfter` | The signing-time attribute is outside the validity of the signer certificate |

## Other errors

These errors have no sentinel value. Their text identifies the cause.

| Error text | Returned by | Cause |
| --- | --- | --- |
| `pkcs7: input data is empty` | `Parse` | The input is empty |
| `ber2der: ...` | `Parse` | The BER structure is malformed, too deep or followed by trailing data |
| `pkcs7: constructed OCTET STRING holds an element that is not a primitive OCTET STRING` | `Parse`, `Decrypt`, `DecryptUsingPSK` | Content split into segments holds something other than OCTET STRINGs |
| `asn1: ...` | `Parse` | The structure does not match what the content type requires, for example an unsupported recipient type |
| `x509: ...` | `Parse` | `crypto/x509` refuses an embedded certificate |
| `pkcs7: unsupported signer key type ...` | `AddSigner`, `Verify` | The key is not RSA or ECDSA |
| `pkcs7: digest ... cannot be used with signer key type ...` | `AddSigner` | The digest does not suit the key, for example SHA-224 with ECDSA |
| `pkcs7: unsupported digest algorithm ...` | `AddSigner`, `AddSignerChain`, `SignWithoutAttr`, `Verify` | `SetDigestAlgorithm` or the signer names a digest the library does not implement |
| `pkcs7: signature algorithm ... cannot be used with digest ... and key type ...` | `AddSigner`, `Verify` | The signature algorithm identifier does not suit the key and the digest |
| `pkcs7: certificate signature from parent is invalid: ...` | `AddSignerChain` | A parent did not sign the certificate before it |
| `pkcs7: payload is not signedData content` | `Verify`, `UnmarshalSignedAttribute` | The message is EnvelopedData or EncryptedData |
| `pkcs7: payload has no signers` | `UnmarshalSignedAttribute` | The message has no signer infos |
| `pkcs7: message has no signers` | `Verify` | The message has no signer infos, for example a certificate bundle |
| `pkcs7: no certificate for signer` | `Verify` | Neither the message nor `SignerCertificates` holds the signer certificate |
| `pkcs7: signer uses the MD5 digest, which is not allowed` | `Verify` | MD5 without `VerifyOptions.AllowMD5` |
| `pkcs7: content-type attribute ...` | `Verify` | The content-type attribute is missing, repeated or does not match the content |
| `pkcs7: message-digest attribute: ...` | `Verify` | The message-digest attribute is missing or repeated |
| `pkcs7: signing-time attribute: ...` | `Verify` | The signing-time attribute is repeated or malformed |
| `pkcs7: attribute ... appears more than once`, `... values are not a SET`, `... has more than one value` | `UnmarshalSignedAttribute` and `Verify` inside the attribute errors above | An attribute does not appear once with a single value |
| `pkcs7: ... RSASSA-PSS ...` | `Verify` | The RSASSA-PSS parameters are missing, malformed or name a hash other than the signer digest |
| `pkcs7: unsupported RSA parameter hash ...`, `pkcs7: unsupported mask generation function ...`, `pkcs7: malformed MGF1 parameters`, `pkcs7: unsupported MGF1 hash ...` | `Verify`, `Decrypt` | RSASSA-PSS or RSAES-OAEP parameters name a hash or mask generation function the library does not accept. MD5 is refused there |
| `pkcs7: signature verification failed: ...` | `Verify` | The signature does not match |
| `pkcs7: failed to verify certificate chain: ...` | `Verify` | No chain to `Roots` at the check time. Wraps the `crypto/x509` error |
| `pkcs7: no recipients` | `Encrypt` | The recipient list is empty |
| `pkcs7: ... needs a ...-byte key, got ... bytes` | `EncryptUsingPSK`, `DecryptUsingPSK` | The key length does not match the cipher |
| `pkcs7: no enveloped recipient for provided certificate` | `Decrypt` | No recipient matches the issuer and serial number of the certificate |
| `pkcs7: failed unmarshaling key encryption algorithm parameters: ...`, `pkcs7: trailing data after RSA OAEP parameters`, `pkcs7: unsupported RSA OAEP label source ...`, `pkcs7: malformed RSA OAEP label` | `Decrypt` | The RSAES-OAEP parameters are malformed or take the label from a source other than pSpecified |
| `pkcs7: encryption algorithm parameters are malformed` | `Decrypt`, `DecryptUsingPSK` | The IV is not an OCTET STRING of one cipher block |
| `pkcs7: ciphertext is not a whole number of cipher blocks` | `Decrypt`, `DecryptUsingPSK` | The encrypted content is empty or not a multiple of the block size |
| `pkcs7: malformed CRL: ...` | `DegenerateCRL` | The input is not a CRL |
| `pkcs7: trailing data after the CRL` | `DegenerateCRL` | Bytes follow the CRL |
