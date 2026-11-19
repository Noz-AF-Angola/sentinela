# Contributing

Bug reports, fixes and small features are welcome. For anything bigger, open an issue first so we can agree on the approach before you spend time on it.

## Getting started

You need Go 1.26 or newer. No CrowdSec installation is required for development:

```bash
go run ./cmd/sentinela demo     # fake data on 127.0.0.1:8080
go test -race ./...
go vet ./...
golangci-lint run               # v2
```

## Ground rules

- **Keep it small.** One binary, standard library first. A new dependency needs a good reason.
- **No shell, ever.** cscli is executed as an argument vector. Any new value that reaches cscli or the LAPI goes through `internal/validate` first, with a test for the bad inputs.
- **Server-rendered pages.** Templates use `html/template`; no inline `<script>` or `style=""` (the CSP forbids them). JavaScript stays optional.
- **Every change is a POST** with the CSRF token and goes through `s.admin(...)`, and is written to the audit log with `s.audit(...)`.
- **Tests.** New handlers get a test in `internal/web` using the demo backend; new parsing of cscli output gets a test with a real sample of that output.
- **Example data only.** Use `example.com` and the documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) in code, tests and docs. Never commit real addresses, hostnames or secrets; CI runs gitleaks.

## Commits and pull requests

Write commit messages that say what changed and why. Update `CHANGELOG.md` under "Unreleased" when users would notice the change. CI (tests, lint, gitleaks, image build) must pass before merge.

By contributing you agree that your work is released under the MIT license of this project.

## Releases (maintainer)

1. Move the "Unreleased" notes in `CHANGELOG.md` under the new version and commit.
2. Tag with a signed tag: `git tag -s vX.Y.Z -m "Sentinela X.Y.Z"`, push the commit and the tag.
3. Build and sign the release files, then attach them: `scripts/release.sh X.Y.Z --upload`. Only the release key in `docs/release-key.asc` can sign `SHA256SUMS`, and `instalar.sh` refuses anything else.
4. The container image is built by the `release` workflow (or by hand with `docker build --build-arg VERSION=X.Y.Z`).

If the release key ever changes, the new key must be signed by the old one and `instalar.sh` updated in the same release.
