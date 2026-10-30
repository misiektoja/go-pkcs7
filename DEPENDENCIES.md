# Dependencies

The module has no dependencies outside the Go standard library. It derives from
[smallstep/pkcs7](https://github.com/smallstep/pkcs7) and carries two copies of Go code, as
[NOTICE](NOTICE) records.

| Copied code | Use | License |
| --- | --- | --- |
| `internal/legacy/x509`, parts of Go 1.23 `crypto/x509` | Parsing embedded certificates that newer `crypto/x509` refuses, when `ParseOptions.LegacyCertificateParser` is set | BSD-3-Clause |
| `internal/cryptobyte`, `golang.org/x/crypto/cryptobyte` | DER parsing inside the legacy certificate parser | BSD-3-Clause |

Each copy keeps its upstream license file. The release SBOM lists the module and its licenses.
