# OpenSSL

The tests exchange messages with the `openssl` command found on the `PATH`. They skip when it is
missing, so run `make test TESTFLAGS=-v` to see whether they ran. They pass with OpenSSL 3.0 and
4.1. This page lists only what those tests check.

## Messages this library creates

| Message | OpenSSL command | Test |
| --- | --- | --- |
| SignedData from RSA and ECDSA P-256 signers with SHA-256, attached | `openssl cms -verify -binary -inform DER -in signed.der -CAfile root.pem` | `TestOpenSSLVerifiesSignedData` |
| The same, detached | The same with `-content content.txt` | `TestOpenSSLVerifiesSignedData` |
| The same, without signed attributes (`SignWithoutAttr`) | The same as attached | `TestOpenSSLVerifiesSignedData` |
| EnvelopedData with AES-256-CBC and PKCS #1 v1.5, AES-128-CBC and RSAES-OAEP SHA-256, DES-EDE3-CBC and RSAES-OAEP SHA-512 | `openssl cms -decrypt -inform PEM -in enveloped.pem -recip recipient.pem`, where `recipient.pem` holds the certificate and the key | `TestEncryptAndDecryptWithOpenSSL` |
| EncryptedData with AES-128-CBC, AES-192-CBC, AES-256-CBC and DES-EDE3-CBC | `openssl cms -EncryptedData_decrypt -inform DER -in encrypted.der -secretkey <hex key>` | `TestEncryptUsingPSKWithOpenSSL` |
| Certificate bundle from `DegenerateCertificate` and CRL message from `DegenerateCRL` | `openssl pkcs7 -inform DER -in bundle.p7b` | `TestDegenerateCertificate`, `TestDegenerateCRL` |

OpenSSL accepts every message. Where a message carries content, the tests compare what OpenSSL
returns with the original.

## Messages OpenSSL creates

| OpenSSL command | Library call | Test |
| --- | --- | --- |
| `openssl smime -sign -nodetach -signer signer.pem -inkey signer.key -certfile intermediate.pem -outform PEM` with RSA 2048 and 4096 and ECDSA P-256, P-384 and P-521 keys in every root, intermediate and signer combination | `Verify` with the root in `Roots` | `TestSignWithOpenSSLAndVerify` |
| `openssl cms -sign -binary -nodetach -md sha256 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:digest`, also with `-md sha384` and with a salt length of 20 | `Verify` | `TestVerifyRSAPSSFromOpenSSL` |
| `openssl cms -EncryptedData_encrypt -binary -aes128 -secretkey <hex key> -outform DER`, also with `-aes192`, `-aes256` and `-des3` | `DecryptUsingPSK` | `TestEncryptUsingPSKWithOpenSSL` |
| `openssl cms -encrypt -binary -aes128 -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha1 -keyopt rsa_oaep_label:0102030405`, also with `rsa_mgf1_md:sha512` | `Decrypt` | `TestDecryptOpenSSLOAEPParameters` |

`TestDecrypt` also decrypts four EnvelopedData messages that OpenSSL produced when the tests were
written. They are stored in `decrypt_test.go` with the commands that made them:

| Command | Content cipher | Key transport |
| --- | --- | --- |
| `openssl cms -encrypt -in test.txt cert.pem` | DES-EDE3-CBC | PKCS #1 v1.5 |
| `openssl smime -encrypt -in test.txt -aes256 -outform pem certificate.pem` | AES-256-CBC | PKCS #1 v1.5 |
| `openssl cms -encrypt ... -aes256 -keyopt rsa_padding_mode:oaep` | AES-256-CBC | RSAES-OAEP with SHA-1 |
| The same with `-keyopt rsa_oaep_md:sha256` | AES-256-CBC | RSAES-OAEP with SHA-256 |

## Line endings

OpenSSL treats the input as text unless `-binary` is given and converts line endings to CRLF before
signing. The signed content then differs from the file on disk, so a detached signature made that
way verifies only against the converted bytes. The tests pass `-binary` when they sign with
`openssl cms`.

## What OpenSSL can produce but this library cannot read

OpenSSL also writes structures outside the [Support matrix](../support-matrix.md), such as
recipients identified by subject key identifier (`-keyid`), AES-GCM content in AuthEnvelopedData and
recipients with EC keys. [Known limitations](../known-limitations.md) lists them.
