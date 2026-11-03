# Testing

The library is tested with unit tests, examples, recorded messages from other software, OpenSSL and
fuzzing. This page explains how to run each and what it covers.

## Unit tests and examples

```bash
make test
```

Runs `go vet` and every test under the race detector. `TESTFLAGS` passes extra flags, for example
`make test TESTFLAGS=-v` to see which tests skipped. The tests cover:

* signing and verification with RSA and ECDSA signers through root, intermediate and signer chains,
  attached and detached, with several digests
* the signed attribute rules, signing time checks, `VerifyOptions` and RSASSA-PSS parameters
* encryption and decryption with every content cipher and key transport, padding errors and the
  inputs `Decrypt` must refuse without saying why
* the BER converter, including indefinite lengths and the limits on hostile input

The examples in `example_test.go` run as part of the same suite and compare their output with the
`// Output:` comments. They are the code shown on this site.

## Recorded messages

Several tests read messages that other software produced. The `TestParse` tests only parse them.
The others also verify them:

| Test | Message |
| --- | --- |
| `TestVerifyAppStore` | An Apple App Store receipt |
| `TestParseSignedOctetStringWithAppleAttestation` | An Apple App Attest receipt in BER with its content split into several OCTET STRINGs |
| `TestVerifyApkEcdsa` | A detached ECDSA signature from an Android APK |
| `TestVerifyFirefoxAddon` | A Firefox add-on signature, checked at the signing time and at fixed times |
| `TestAzureAttestationSignatureValidation` | An Azure instance metadata attested data document with an RSA signature identifier in the digest field |
| `TestParseWindowsSCEPCertificateRequest` | A Windows SCEP request whose certificate needs `LegacyCertificateParser` |

## OpenSSL

The OpenSSL tests run with the regular suite when `openssl` is on the `PATH` and skip otherwise.
[OpenSSL](../interoperability/openssl.md) lists the commands and what each test checks. To run only
them:

```bash
go test -count=1 -run 'OpenSSL|TestDegenerate' -v .
```

## Fuzzing

```bash
make fuzz
make fuzz FUZZTIME=2m
```

Runs `FuzzBer2Der` and `FuzzParse` for `FUZZTIME` each, 30 seconds by default. `FuzzBer2Der` checks
that the converter never panics and that converting its output again changes nothing. `FuzzParse`
checks that parsing, verification and decryption of arbitrary input return errors instead of
panicking. CI runs both on Linux for 30 seconds on every push and pull request to `dev` and
`main`.

Go writes a failing input under `testdata/fuzz/<target>`. Commit it with the fix so it stays a
regression test.

## CI

The table lists the workflows that check the code. The Release, Scorecard and Stale workflows are
left out.

| Workflow | Checks |
| --- | --- |
| Tests | Tidy check, formatting, build, `make test` and fuzzing on Linux. Build and `make test` on macOS. Build on Windows |
| Lint | golangci-lint configuration and run, actionlint |
| Supply chain | govulncheck, gitleaks and the SBOM |
| CodeQL | Static analysis |
| Documentation | The strict site build |
