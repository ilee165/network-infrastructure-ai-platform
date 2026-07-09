# Contributing

Thank you for your interest in the AI Network Operations Platform. This
document explains how to contribute code, documentation, and other improvements.

## Before you start

1. Read [README.md](README.md) for architecture overview and local development setup.
2. Review [CLAUDE.md](CLAUDE.md) for platform mission, design principles, and development standards.
3. For architecture or design changes, add or update an ADR in [docs/adr/](docs/adr/README.md) before implementation.

## Development standards

Every feature merged into the repository must include:

- **Tests** — unit and/or integration coverage for the behavior you add or change.
- **Documentation** — user-facing or operator-facing docs when behavior is visible outside the code.
- **API documentation** — OpenAPI-visible changes must be reflected in endpoint schemas and descriptions.

CI (GitHub Actions) gates on lint, type checks, tests, builds, and image vulnerability scans. Pull requests should pass all required checks before review.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make focused changes with clear commit messages.
3. Run the relevant local checks (see README **Development** for backend and frontend commands).
4. Open a pull request with a concise summary, test plan, and links to related ADRs or issues.
5. Address review feedback; maintainers merge when checks pass and the change meets project standards.

## License

By submitting a contribution to this repository — including pull requests, issues
with attached patches, or other submitted materials — you agree that your
contribution is licensed under the [Apache License, Version 2.0](LICENSE), the
same license that covers this project.

Unless you explicitly state otherwise in writing, any contribution intentionally
submitted for inclusion in the work shall be under the Apache License 2.0 terms
without additional terms or conditions (see LICENSE §5).

You represent that you have the right to license your contribution under these
terms. If your employer owns the copyright in your work, you are responsible for
obtaining any required authorization before contributing.

See [NOTICE](NOTICE) for copyright attribution.
