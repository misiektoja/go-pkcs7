# Pre-shared keys

An EncryptedData message carries content encrypted with a symmetric key that both sides already
hold. The message names the cipher but not the key, so the parties agree on the key outside the
message.

```go
--8<-- "example_test.go:psk"
```

## Keys

The key must have exactly the length the cipher needs:

| `ContentEncryption` | Key length |
| --- | --- |
| `AES128CBC`, the default | 16 bytes |
| `AES192CBC` | 24 bytes |
| `AES256CBC` | 32 bytes |
| `DESEDE3CBC` | 24 bytes |
| `DESCBC` | 8 bytes |

`EncryptUsingPSK` fails with `ErrPSKNotProvided` for a nil key and with an error such as
`pkcs7: AES-256-CBC needs a 32-byte key, got 16 bytes` for a key of the wrong length.
`DecryptUsingPSK` returns the same length error. Use random key bytes, for example from
`crypto/rand`. The library does not derive keys from passwords.

`EncryptOptions.KeyEncryption` and `OAEPHash` have no effect here.

## Decryption

`DecryptUsingPSK` takes the same `DecryptOptions` as `Decrypt`, so DES-CBC is refused unless it is
listed. It returns `ErrNotEncryptedContent` for a message that is not EncryptedData and
`ErrDecryptionFailed` when the padding is wrong.

As with EnvelopedData, CBC mode does not authenticate the content. A wrong key or a changed
ciphertext usually fails with `ErrDecryptionFailed` but can also yield garbage. Sign the message
when the receiver must detect changes.

## OpenSSL

OpenSSL reads and writes these messages with `openssl cms -EncryptedData_decrypt` and
`-EncryptedData_encrypt`, with the key given in hex through `-secretkey`.
[OpenSSL](../interoperability/openssl.md) lists the tested commands.
