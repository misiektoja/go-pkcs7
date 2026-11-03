# Signing

A SignedData message carries content, one or more signatures over it and usually the certificates
a receiver needs to check them. This page builds such messages and the certificate and CRL bundles
that use the same structure without signers.

## Sign content

```go
--8<-- "example_test.go:sign"
```

`NewSignedData` takes the content. `AddSigner` adds one signer with its certificate, its private key
and a `SignerInfoConfig`. `Finish` returns the encoded ContentInfo. Every message this library
signs has the encapsulated content type id-data.

## Signer keys

The key is a `crypto.Signer` whose public key is an `*rsa.PublicKey` or an `*ecdsa.PublicKey`. Any
other key type fails with `pkcs7: unsupported signer key type`. The library hashes the data and
calls `Sign` with the digest and the hash as options:

* For RSA it expects a PKCS #1 v1.5 signature, which `*rsa.PrivateKey` returns for these options.
  RSASSA-PSS signing is not supported.
* For ECDSA it expects the ASN.1 encoded signature that `*ecdsa.PrivateKey` returns.

A key held in an HSM or a remote signing service works when its `crypto.Signer` follows the same
contract. The library does not check that the key matches the certificate, so a mismatch shows up
only when the message is verified.

## Digest algorithm

Signers use SHA-256 unless `SetDigestAlgorithm` names another digest. The setting applies to
signers added after the call, so each signer of one message may use a different digest. For example,
`sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA384)` selects SHA-384.

RSA signers accept MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512. ECDSA signers accept SHA-1,
SHA-256, SHA-384 and SHA-512. Another combination fails when the signer is added. MD5 and SHA-1
remain available for old peers, but `Verify` refuses MD5 unless the receiver allows it.

## Signature algorithm identifier

The signer info names the signature algorithm. By default it is derived from the key and the
digest, for example `sha256WithRSAEncryption` or `ecdsa-with-SHA256`. Some peers expect the plain
`rsaEncryption` identifier for RSA signatures, which is also what OpenSSL writes.
`sd.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)` selects it for signers added afterwards. Any
other value must equal the derived identifier. Otherwise `AddSigner` fails.

## Signed attributes

`AddSigner` signs a set of attributes rather than the content itself. The set always holds:

* content-type, with the value id-data
* message-digest, the digest of the content
* signing-time, the current time or `SignerInfoConfig.SigningTime`, stored in UTC

`SignerInfoConfig.ExtraSignedAttributes` adds more. `ExtraUnsignedAttributes` adds attributes
outside the signature. Each `Attribute` value must be encodable by `encoding/asn1`. The set is
sorted into DER order before it is signed. The receiver reads an attribute back with
`UnmarshalSignedAttribute` after verifying the message:

```go
--8<-- "example_test.go:attributes"
```

Do not put content-type, message-digest or signing-time into `ExtraSignedAttributes`. `AddSigner`
accepts the duplicate, but `Verify` then fails because each of them must appear only once.

`GetSignedData` returns the structure being built. The `SetUnauthenticatedAttributes` method of an
entry in its `SignerInfos` replaces the unsigned attributes of a signer that is already added,
for example `sd.GetSignedData().SignerInfos[0].SetUnauthenticatedAttributes(attrs)`. The signature
does not cover them, so it stays valid.

## Certificate chains

`AddSigner` puts the signer certificate into the message. `AddSignerChain` also adds the issuing CA
certificates, so a receiver that trusts only the root can build the chain:

```go
--8<-- "example_test.go:chain"
```

List the parents in order, starting with the issuer of the signer certificate. `AddSignerChain`
checks that each certificate is signed by the next one and fails otherwise. It does not require the
last parent to be a root. `AddCertificate` adds any other certificate to the message.

## Messages without certificates

RFC 5652 allows a message without certificates when the receiver already holds the signer
certificate. SCEP clients, for example, have the CA certificate from GetCACert.
`RemoveCertificates` leaves out every certificate added so far:

```go
--8<-- "example_test.go:without-certificates"
```

Call it after the last `AddSigner`, because signers added later put their certificates back. The
receiver passes the expected signer certificate in `VerifyOptions.SignerCertificates`.

## Detached signatures

A detached signature leaves the content out of the message. The receiver gets the content another
way and sets `p7.Content` before calling `Verify`:

```go
--8<-- "example_test.go:detached"
```

Call `Detach` after the signers are added and right before `Finish`.

## Several signers

Call `AddSigner` once per signer. Each signer has its own certificate, digest and attributes.
`Verify` requires every signature to be valid.

## Signatures without signed attributes

`SignWithoutAttr` signs the digest of the content directly, without signed attributes. Old Android
APK signatures use this form. It ignores its `SignerInfoConfig`.

`RemoveAuthenticatedAttributes` deletes the signed attributes from signers that already exist. Their
signatures cover those attributes, so the resulting message fails verification in this library and
in OpenSSL. Use `SignWithoutAttr` to build a message without signed attributes.
`RemoveUnauthenticatedAttributes` deletes the unsigned attributes, which the signatures do not cover.

## Certificate and CRL bundles

A SignedData message without signers is a common way to ship certificates, as in a `.p7b` file or
an EST or SCEP certificate response. `DegenerateCertificate` takes one or more DER certificates
concatenated into one byte slice:

```go
--8<-- "example_test.go:degenerate"
```

It does not parse the certificates, so check them before building the bundle.

`DegenerateCRL` wraps one DER encoded CRL, the form of a SCEP GetCRL response. It fails when the
input is not a single well-formed CRL structure. It does not check the CRL signature.
[Parsing](parsing.md#certificates-and-crls) shows how a receiver checks it.
