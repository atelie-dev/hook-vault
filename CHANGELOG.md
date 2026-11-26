# Changelog

Notable changes to hook-vault. Releases before 0.4.0 are the commit log; the
file starts here.

## [Unreleased]

### Added

- Static binaries for linux and macOS, amd64 and arm64, are attached to every
  tagged release with a `sha256sums.txt`, so a host without Nix can install by
  unpacking one. `go install github.com/atelie-dev/hook-vault/cmd/hook-vault@latest`
  stays the source route.

### Internal

- GitHub Actions: lint, build/vet/unit tests, the integration suite against
  PostgreSQL 18, and `nix build` on every pull request. A pushed `v*` tag builds
  the four binaries and publishes them, taking the release notes from this
  file's section for that version.

## [0.4.0] - 2026-11-26

### Added

- `HEAD /in/{slug}` answers the availability check a provider makes before it
  accepts a webhook URL: `200` with no body, `404` for an unknown slug, `410`
  for a disabled endpoint. It stores nothing and needs no credential. Receita
  Federal's async APIs probe the URL this way and reject the whole solicitation
  when it fails, so a webhook from them could not be registered at all.
- `docs/connecting.md` gains the probe as a diagnostic: `curl -I` on the ingest
  URL is the check to run before blaming the provider.

### Fixed

- A `HEAD` on the ingest URL no longer lands in the Meta handshake and is no
  longer answered `400 not_a_handshake`. `net/http` matches a `GET` pattern
  against `HEAD`, so the probe was silently answered by the wrong handler, which
  a provider reads as an unavailable endpoint.
