# Development

How to build, check and change the library. Contribution rules are in
[CONTRIBUTING.md](https://github.com/misiektoja/go-pkcs7/blob/main/CONTRIBUTING.md).

## Prerequisites

* Go at the version `go.mod` declares. Go downloads that toolchain on first use when the installed
  version is older.
* `openssl` on the `PATH` for the interoperability tests. Without it they skip.
* Python 3 with the pinned MkDocs dependencies for the documentation site, installed by
  `make docs-deps`. CI uses Python 3.13.

Linters and other tools are downloaded into `bin/` at pinned versions by the Make targets that need
them.

## Repository layout

| Path | Content |
| --- | --- |
| `pkcs7.go` | Types, OIDs, `Parse` and `ParseWithOptions` |
| `ber.go` | The BER to DER converter |
| `sign.go` | `SignedData` and the certificate and CRL bundles |
| `verify.go` | `Verify` and the signed attribute checks |
| `encrypt.go` and `decrypt.go` | EnvelopedData and EncryptedData |
| `example_test.go` | The examples included in this site |
| `internal/legacy/x509` | A copy of the Go 1.23 certificate parser for `LegacyCertificateParser` |
| `internal/cryptobyte` | A copy of `golang.org/x/crypto/cryptobyte` used by that parser |
| `testdata/fuzz` | Fuzz inputs kept as regression tests |
| `docs/` | This site |

[DEPENDENCIES.md](https://github.com/misiektoja/go-pkcs7/blob/main/DEPENDENCIES.md) and
[NOTICE](https://github.com/misiektoja/go-pkcs7/blob/main/NOTICE) record where the copied code
comes from.

## Common commands

```bash
make fmt-check     # fail when a tracked Go file is not gofmt formatted
make test          # go vet and the tests under the race detector
make lint          # golangci-lint at the version CI uses
make fuzz          # each fuzz target for FUZZTIME, 30s by default
make actionlint    # lint the GitHub Actions workflows
make docs-build    # strict MkDocs build
make help          # every target
```

`make tidy-check` fails when `go.mod` is not tidy. `make govulncheck` reports known vulnerabilities
that reach the code and `make gitleaks` scans the tree and the history for credentials.

## Documentation

The site is built with MkDocs and the Material theme from `docs/` and `mkdocs.yml`. Set `PYTHON`
when the MkDocs toolchain lives in a virtual environment:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

`make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from the
navigation fails the build. CI runs the same build on every change to the documentation and
publishes the site from `main`. The build job holds a read-only token and hands the site to a
separate publish job, so the only job that can write to the repository runs no code from PyPI or
from the checkout.

The Go listings on the site are named sections of `example_test.go`, which the
[pymdownx.snippets](https://facelessuser.github.io/pymdown-extensions/extensions/snippets/)
extension includes by file and section name. Start and end marker comments delimit each section.
Each listing belongs to an example with an `// Output:` comment, so `make test` fails when a listing
stops compiling or its output changes. Keep a blank line between the end marker and the
`// Output:` comment, because Go reads the expected output only from a comment group that starts
with it.

`docs/requirements.txt` pins every package, including the transitive ones, by version and SHA-256
hash. `make docs-deps` installs it with `--require-hashes`. To change a direct dependency, edit
`docs/requirements.in` and run `make docs-requirements`, which needs
[pip-tools](https://pypi.org/project/pip-tools/) in the `PYTHON` environment.

Package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pkcs7) comes from
the Go doc comments. A user-facing change updates both.

## Code style

`.editorconfig` records the whitespace rules. `gofmt` and golangci-lint enforce the rest. A change
to a message format cites the RFC section and comes with a negative test.
