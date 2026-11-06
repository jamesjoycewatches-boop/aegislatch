# Public developer-preview release checklist

AegisLatch v0.1.0 is an **experimental public developer preview**, not a production security product.
The repository owner explicitly authorized public release of this project only. Other repositories must remain untouched.

## Local preflight completed

- [x] Confirm exact new repository owner/name and public visibility.
- [x] Limit the release to the isolated AegisLatch source tree.
- [x] Check tracked filenames and contents for common secret patterns (basic gate only).
- [x] Run 25 automated tests under Python 3.13 and the demo CLI.
- [x] Review security scope and known limitations in `SECURITY.md` and `docs/THREAT_MODEL.md`.
- [x] Use read-only permissions and pinned commit SHAs for GitHub Actions.

## Recommended before production use or a stable release

- [ ] Independent secret scan (`gitleaks`, `trufflehog`) and Git-history scan.
- [ ] Independent security review and penetration testing.
- [ ] Confirm CI passes on supported Python 3.11–3.13.
- [ ] Configure and verify repository branch protection, Dependabot, code scanning and private vulnerability reporting.
- [ ] Publish signed SBOM/build attestations when packages are distributed.
- [ ] Test full host integration with network sandboxing, filesystem enforcement and concurrency/TOCTOU controls.
- [ ] Review branding, name availability, and maintainer/security contact details.
- [ ] Confirm licensing and supply-chain provenance before publishing packages to PyPI.

**Never** embed real API keys, user records, internal URLs or private-project code in this public repository.
