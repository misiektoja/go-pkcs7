# Encryption and decryption

An EnvelopedData message carries content encrypted with a random content key and that key
encrypted once for each recipient. This library supports recipients with RSA certificates.

## Encrypt for a recipient

```go
--8<-- "example_test.go:encrypt"
```

`Encrypt` generates a content key and an IV, encrypts the content in CBC mode with PKCS #7 padding
and encrypts the content key for every certificate in the list. Each recipient is identified by the
issuer and serial number of its certificate.

`Encrypt` fails with `pkcs7: no recipients` for an empty list and with `ErrUnsupportedKeyType` when
a certificate does not hold an RSA key. It does not check the validity period or the key usage of
the certificates, so check them before encrypting.

## Choosing the algorithms

`EncryptOptions` selects the content cipher and the key transport:

| Field | Default | Choices |
| --- | --- | --- |
| `ContentEncryption` | `AES128CBC` | `AES128CBC`, `AES192CBC`, `AES256CBC`, `DESEDE3CBC` and `DESCBC` |
| `KeyEncryption` | `RSAPKCS1v15` | `RSAPKCS1v15` and `RSAOAEP` |
| `OAEPHash` | SHA-256 | SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512. Used only with `RSAOAEP` |

AES-128-CBC with PKCS #1 v1.5 key transport is the default because SCEP peers expect it. Use
AES-256-CBC and RSAES-OAEP when the receiver supports them. RSAES-OAEP uses `OAEPHash` for both the
OAEP hash and MGF1. The parameters name both hashes explicitly and carry no label, which OpenSSL
reads correctly.

A responder that answers in the cipher the requester chose reads it with
`ContentEncryptionAlgorithm`:

```go
--8<-- "example_test.go:reply-cipher"
```

## Decrypt

```go
--8<-- "example_test.go:decrypt"
```

`Decrypt` picks the recipient whose issuer and serial number match the certificate and fails with
`pkcs7: no enveloped recipient for provided certificate` when there is none. It does not check
that the key belongs to the certificate. A wrong key is treated like corrupted input, as
[Integrity](#integrity) describes.

The key transport is read from the message. PKCS #1 v1.5 and RSAES-OAEP are accepted. For
RSAES-OAEP the hash, the MGF1 hash and the label come from the parameters. Absent parameters
mean SHA-1 as RFC 8017 specifies.

## Accepted ciphers

`Decrypt` accepts AES-128-CBC, AES-192-CBC, AES-256-CBC and DES-EDE3-CBC by default, the list in
`DefaultContentDecryptionAlgorithms`. A message encrypted with another cipher fails with an error
that wraps `ErrContentEncryptionNotAllowed`. `DecryptOptions.ContentEncryptionAlgorithms` replaces
the list. Single DES must be listed explicitly:

```go
--8<-- "example_test.go:legacy-ciphers"
```

Accept DES-CBC only from peers that cannot do better. Its 56-bit key is broken.

Do not modify `DefaultContentDecryptionAlgorithms` itself. Every `Decrypt` and `DecryptUsingPSK`
call reads it, so a change affects the whole program. Pass `ContentEncryptionAlgorithms` instead.

## Several keys

A receiver that holds several keys, for example during a key rollover, reads the recipients first
and decrypts with the key that matches:

```go
--8<-- "example_test.go:recipients"
```

`Recipients` lists them in encoded order. DER sorts the recipient set, so the order need not match
the certificates given to `Encrypt`.

## Keys in an HSM

`Decrypt` takes a `crypto.Decrypter`, so the private key may stay in an HSM. The library calls its
`Decrypt` method with these options:

* `*rsa.PKCS1v15DecryptOptions` with `SessionKeyLen` set to the content key length, for PKCS #1
  v1.5 key transport.
* `*rsa.OAEPOptions` with `Hash`, `MGFHash` and `Label` from the message, for RSAES-OAEP.

The `crypto.Decrypter` must honor them. With `SessionKeyLen` set, `*rsa.PrivateKey` returns a
random key of that length when the padding is wrong instead of an error, which is the RFC 3218
countermeasure against Bleichenbacher's attack. A `crypto.Decrypter` that returns an error instead
still produces `ErrDecryptionFailed`, but whether it leaks timing then depends on that
implementation.

## Errors

Every failure to decrypt the content key or the content returns `ErrDecryptionFailed`, without
saying which step failed. That includes an error from the `crypto.Decrypter`, a content key of the
wrong length and bad padding. A sender therefore cannot use the error as a padding oracle.

Other errors describe the message rather than the keys:

| Error | Cause |
| --- | --- |
| `ErrNotEncryptedContent` | The message is not EnvelopedData |
| `ErrUnsupportedAsymmetricEncryptionAlgorithm` | The recipient uses a key transport other than PKCS #1 v1.5 or RSAES-OAEP |
| `ErrUnsupportedAlgorithm` | The content cipher is not one this library implements |
| `ErrContentEncryptionNotAllowed` | The content cipher is not in the accepted list |
| `pkcs7: encryption algorithm parameters are malformed` | The IV is missing or has the wrong length |
| `pkcs7: ciphertext is not a whole number of cipher blocks` | The ciphertext is truncated or empty |

## Integrity

CBC mode does not authenticate the content. A wrong key or a changed ciphertext usually ends in
`ErrDecryptionFailed`, but sometimes the padding happens to be valid and `Decrypt` returns garbage.
When the receiver must detect changes, sign the EnvelopedData message, as SCEP does.
