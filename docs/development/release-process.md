# Release process

A release starts when a version tag reachable from `main` is pushed. `CHANGELOG.md` has one section
per version. That section becomes the release description.

## Versioning

The module follows semantic versioning under the [Compatibility policy](../reference/compatibility.md).
Clones made from smallstep/pkcs7 hold its tags up to `v0.2.3`. Those tags declare the old module
path, so `go get` cannot fetch them under this one. Number releases above them so a tag never names
two different trees. Push only the new tag.

## Steps

1. On `dev`, complete the `## [X.Y.Z] - YYYY-MM-DD` section in `CHANGELOG.md` and read it as a user
   of the library.
2. Merge `dev` into `main` and run the checks there:

    ```bash
    make fmt-check
    make lint
    make test
    VERSION=vX.Y.Z make release-check
    ```

    The release check fails when `go.mod` has a `replace` directive. It exports `HEAD` with
    `git archive` and verifies, builds, vets and tests the export. It then imports the export from a
    separate module, so it catches files that are ignored, untracked or only present locally. With
    `VERSION` set it also requires a dated changelog heading for the version and no Unreleased
    section.

3. Create a signed annotated tag and push `main` and the tag:

    ```bash
    git tag -s vX.Y.Z -m 'vX.Y.Z'
    git push origin main vX.Y.Z
    ```

4. The release workflow checks that the tag is reachable from the default branch, repeats the
   release check, builds the source archives, the SBOM and the checksums, attests their provenance
   and creates a **draft** release with the changelog section as its description. Review the draft
   and publish it.

!!! warning "Never publish a release in the GitHub UI"
    Publishing there creates the tag, which starts the workflow against a release that is already
    published. The workflow refuses to rebuild it. Delete the release and its tag with
    `gh release delete vX.Y.Z --cleanup-tag --yes`, then push the tag again.

When a draft release for the version already exists, the workflow updates that draft with the
changelog section and the artifacts instead of creating a new one.

## Artifacts

Each release carries:

| Artifact | Content |
| --- | --- |
| `go-pkcs7-<version>-source.zip` and `.tar.gz` | The complete tagged source tree |
| `go-pkcs7-<version>-sbom.cdx.json` | A CycloneDX software bill of materials with license information |
| `go-pkcs7-<version>_SHA256SUMS.txt` | SHA-256 checksums of the archives and the SBOM |
| `go-pkcs7-<version>.intoto.jsonl` | A signed provenance bundle covering the artifacts |

Verify a file with `gh attestation verify <file> --repo misiektoja/go-pkcs7`. Offline verification
takes `--bundle` and the provenance file.

## Documentation

The documentation workflow publishes this site from `main` to GitHub Pages whenever the pages,
`mkdocs.yml`, `example_test.go`, the `Makefile` or the workflow file change there. A manual run on
`main` publishes too. Pull requests, pushes to `dev` and manual runs on other branches run the
strict build without publishing. The site therefore describes `main`, which is the latest release
plus any fixes merged since.
