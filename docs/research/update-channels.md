# Update channels — 2026-11-17

Extend the existing updater with explicit stable (default), nightly/prerelease,
and main choices. Checks remain restricted to `knowlet/artex-ymh`; drafts are
never selected. Source checks and source downloads do not enable installation.

| Reference | Fit / license evidence | Decision |
| --- | --- | --- |
| ARTEX `selfupdate/github.go`, `server/update.go` at `1d7ec5d623c6643a0583f0d1767dfb3eda5c0d30` | Existing bounded HTTP, repository validation, error classification and cache | Extend directly; retain installation policy and stable API compatibility |
| [go-github-selfupdate `selfupdate/detect.go`](https://github.com/rhysd/go-github-selfupdate/blob/04a545f8ea38b52262e6ac4acfcb863c23ebd39a/selfupdate/detect.go) | MIT (`LICENSE` at same revision); inspected `findReleaseAndAsset` and `DetectVersion`. Lists releases and explicitly filters drafts/prereleases; creation ordering differs from version ordering. Reference is old, not a current dependency recommendation. | Design reference only; no copied code or new dependency. Its semantic-version selection does not fit mutable nightly tags or untagged main commits. |

Targeted GitHub source search: `prerelease` in `rhysd/go-github-selfupdate`.
Official contracts checked: [list/latest releases](https://docs.github.com/en/rest/releases/releases)
and [get a commit](https://docs.github.com/en/rest/commits/commits#get-a-commit).

Nightly selects published prereleases (also explicitly named `nightly` or
`nightly-*` releases), ordered by publication time, across bounded pages. Resolve
its tag to a commit rather than comparing the mutable tag as a stable version.
Main reads the fixed `main` ref and produces an immutable commit/source link.
Clean builds with Go VCS metadata can compare commit identity; different commits
mean a different target, not proof of ancestry. Unknown/dirty builds must not be
reported as current. Stable keeps existing semantic-version comparison.

Cache each channel independently. Persist the browser choice and synchronize the
settings card and top bar. Reject stale responses after switching or unmounting.
Missing releases are informational; access, rate-limit and invalid metadata
errors retain their classification. Source links use the resolved commit.

Validation: transport fixtures for release selection, pagination, draft/fork
rejection and commit parsing; server fixtures for cache isolation, force refresh,
channel validation and build identity; browser-store and stale-request tests;
existing selfupdate safety CI covers race tests, vet/build, TypeScript and static
frontend build. Local checkout is a selected-file snapshot acquired through the
GitHub connector: shell clone failed DNS resolution and Go is unavailable here.
Publish only changed paths onto the pinned full GitHub base tree, never push this
partial snapshot as a repository replacement. Deployment/browser/real installer
acceptance remains separate from fixture and CI verification.
