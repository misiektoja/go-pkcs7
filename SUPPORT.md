# Getting help

Start with the [README](README.md), which covers the supported content types, the algorithms and
the security defaults. The package documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pkcs7) describes every exported type.

## Check your setup first

Many problems come from limits the library applies on purpose. Before asking, confirm that:

* A signature with an MD5 digest is verified with `VerifyOptions.AllowMD5`.
* A message encrypted with single DES is decrypted with DES-CBC listed in
  `DecryptOptions.ContentEncryptionAlgorithms`.
* A response without its signer certificate, which some SCEP servers send, is verified with the
  expected signer in `VerifyOptions.SignerCertificates`.
* A signer chain that has expired since signing is checked with `VerifyOptions.CurrentTime` or
  `VerifyOptions.VerifyAtSigningTime`.
* A certificate whose authority key identifier is marked critical is parsed with
  `ParseOptions.LegacyCertificateParser`.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/go-pkcs7/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-pkcs7/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-pkcs7/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-pkcs7/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-pkcs7 version, the Go version, the software on the other side and its version and
the algorithms involved. Attach the error and, where you can, a PEM sample made with a throwaway
key.

Never post private keys, passwords or messages captured from a production system. See
[SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time
attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so
reproduce the problem on the current version before reporting it.
