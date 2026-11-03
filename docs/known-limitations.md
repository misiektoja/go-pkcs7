# Known limitations

## Content types

* **No AuthEnvelopedData (RFC 5083) and no AES-GCM.** `Parse` returns `ErrUnsupportedContentType`
  for AuthEnvelopedData, which is what `openssl cms -encrypt -aes-128-gcm` produces.
* **No DigestedData, AuthenticatedData or other content types.** `Parse` returns
  `ErrUnsupportedContentType`.
* **Signing always uses the id-data content type.** Messages with another encapsulated content
  type can be parsed and verified but not created.

## Signatures

* **Signing supports RSA PKCS #1 v1.5 and ECDSA only.** No RSASSA-PSS, Ed25519, DSA or post-quantum
  signing.
* **Verification supports RSA PKCS #1 v1.5, RSASSA-PSS and ECDSA.** Ed25519 and DSA signatures
  fail. An ECDSA signature with SHA-224 fails unless the signature algorithm field names the curve.
* **Signers are identified by issuer and serial number.** `Parse` fails on a signer identified by
  subject key identifier, which is what `openssl cms -sign -keyid` produces.
* **No countersignatures, signed receipts or timestamps.** Unsigned attributes can be added but are
  not interpreted.
* **No revocation checking.** `Verify` does not consult CRLs or OCSP. CRLs carried in a message are
  not checked either.

## Encryption

* **Recipients must hold RSA keys.** No key agreement (ECDH), key encryption key or password
  recipients. `Encrypt` refuses other keys with `ErrUnsupportedKeyType`. `Parse` fails on a message
  that contains such a recipient, even when another recipient uses RSA.
* **Recipients are identified by issuer and serial number.** `Parse` fails on a recipient identified
  by subject key identifier, which `openssl cms -encrypt -keyid` produces.
* **CBC content is not authenticated.** A changed ciphertext or a wrong key can decrypt to garbage
  instead of failing. Sign the message when integrity matters.
* **No key derivation for pre-shared keys.** `EncryptUsingPSK` takes raw key bytes.

## Processing

* **No streaming.** Messages are held in memory while they are parsed or built. The library does
  not limit their size.
* **`DegenerateCertificate` does not parse its input.** It wraps whatever bytes it receives.
* **Embedded certificates must parse with `crypto/x509`.** The only exception is a critical
  authority key identifier with `ParseOptions.LegacyCertificateParser`.
