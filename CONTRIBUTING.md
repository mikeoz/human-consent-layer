# Contributing to the Human Consent Layer

Thank you for your interest in contributing to the Human Consent Layer. This project aims to make human consent the default for every AI agent interaction. Contributions that advance that goal are welcome.

## What This Repo Contains

This repository holds the HCL specification, CARD schemas, the DevKit, and example templates. It does not contain the Opnli Trust Network infrastructure or any proprietary enforcement mechanisms.

## How to Contribute

**Report issues.** If you find a problem in the spec, the schemas, or the DevKit, open a GitHub issue. Describe what you expected, what happened, and how to reproduce it.

**Propose spec changes.** If you believe the HCL specification should be amended, open an issue first describing the change and the reasoning. Do not submit a pull request for spec changes without prior discussion — the spec is normative and changes require review.

**Improve the DevKit.** Bug fixes, documentation improvements, and new platform integrations for the DevKit are welcome as pull requests. Please include tests for any code changes.

**Add CARD templates.** If you have a use case that would benefit from an example CARD Set template, submit it to the `templates/` directory with a descriptive filename and a comment block explaining the scenario.

**Improve documentation.** Typo fixes, clarity improvements, and additional examples are always welcome.

## Pull Request Process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep commits focused — one logical change per commit.
3. If you changed code in `packages/atl-devkit/`, run the existing tests and confirm they pass.
4. Submit a pull request with a clear description of what you changed and why.
5. A maintainer will review your PR. Expect questions — they are part of the process, not a rejection.

## What We Will Not Accept

**Patented mechanism internals.** This repository describes the HCL standard — the WHAT. It does not describe the internal implementation of specific enforcement mechanisms — the HOW. Pull requests that add implementation details of consent gate internals, detection algorithms, or proxy architectures will be declined. If you are unsure whether your contribution crosses this line, open an issue to ask before writing code.

**Breaking changes to the CARD schema.** The CARD schema is a contract. Changes that would break existing implementations require an RFC-style proposal and community review before merging.

**Scope expansion without discussion.** New features, new CARD types, or new invariants should be proposed as issues before implementation. The HCL is deliberately minimal — every addition must earn its place.

## Code Style

- JavaScript: no external dependencies in the DevKit. Node 18+.
- JSON Schema: draft-07 or later.
- Markdown: ATX headings, one sentence per line in source where practical.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license that covers this repository.

## Code of Conduct

Be respectful, be constructive, be honest about what works and what does not. The HCL is built on the principle that trust requires transparency — that applies to how we work together too.

## Questions

If you have questions about the project, the spec, or how to contribute, open a GitHub issue. For questions about the Opnli Trust Network or commercial licensing, contact opn4@opn.li.
