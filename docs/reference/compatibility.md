# Compatibility policy

The module uses semantic versioning. The public API is every exported identifier of the package
`pkcs7`. The packages under `internal/` are not part of it and cannot be imported from other
modules.

## Before v1.0.0

A minor release may change the public API. The
[changelog](https://github.com/misiektoja/go-pkcs7/blob/main/CHANGELOG.md) describes every change
that affects callers, including any that needs a code change.

## Rules for every release

* **Option structs may gain fields.** Construct `SignerInfoConfig`, `VerifyOptions`,
  `EncryptOptions`, `DecryptOptions` and `ParseOptions` with field names.
* **Constants may be added.** A switch over `ContentEncryptionAlgorithm` or
  `KeyEncryptionAlgorithm` needs a default case.
* **Parsing and verification may become stricter** when a message breaks RFC 5652 or a related
  RFC. The changelog names such a change.
* **Error texts may change.** Compare errors with `errors.Is` and `errors.As`, as
  [Errors](errors.md) describes.
* **Defaults may change in a minor release.** The changelog names the change. Version 0.3.0, for
  example, moved signing from SHA-1 to SHA-256 and encryption from DES-CBC to AES-128-CBC.

## Upgrading

1. Read the changelog section for the new version.
2. Run `go get github.com/misiektoja/go-pkcs7@vX.Y.Z` and build.
3. Run your tests against the peers you exchange messages with.

## Go version

The module declares its minimum Go version in `go.mod`, currently Go 1.27.3. CI builds and tests
with exactly that version. The changelog names every change of the minimum.

## Module path and older tags

The module path is `github.com/misiektoja/go-pkcs7`. Releases of smallstep/pkcs7 up to v0.2.3 use
another module path and are not versions of this module.
[Migrating from smallstep/pkcs7](../migrating.md) lists the changes.
