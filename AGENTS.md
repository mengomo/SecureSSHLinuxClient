# Repository Guidelines

## Project Structure & Module Organization
This repository is currently minimal. Keep the top level clean and add code in predictable locations as the project grows:

- `src/` for application or library code
- `tests/` for automated tests mirroring `src/`
- `docs/` for design notes and operational guidance
- `assets/` for static files such as sample configs or diagrams

Example layout:
`src/ssh/`, `tests/ssh/test_connection.*`, `docs/architecture.md`.

## Build, Test, and Development Commands
No build system is committed yet. When tooling is added, expose a small stable command set and document it here. Recommended defaults:

- `make setup` installs local dependencies
- `make test` runs the full test suite
- `make lint` runs formatting and lint checks
- `make run` starts the project locally

If `make` is not used, provide equivalents in the primary toolchain such as `npm test`, `pytest`, or `cargo test`.

## Coding Style & Naming Conventions
Use 4 spaces for Python and 2 spaces for JavaScript, JSON, YAML, and Markdown indentation. Prefer descriptive module names and keep files focused on one responsibility.

- Python: `snake_case` for files, functions, and variables; `PascalCase` for classes
- JavaScript/TypeScript: `camelCase` for variables/functions; `PascalCase` for components/classes
- Markdown docs: short, task-oriented filenames such as `setup.md`

Adopt a formatter early and run it before opening a PR, for example `ruff format`, `prettier --write`, or project-specific equivalents.

## Testing Guidelines
Place tests under `tests/` and mirror the source tree so ownership is obvious. Name tests after the behavior they verify, such as `test_key_rotation.py` or `connection.spec.ts`.

Target meaningful coverage for critical SSH, authentication, and configuration flows. Every bug fix should include a regression test. Prefer fast unit tests first, then add integration coverage for network-facing behavior.

## Commit & Pull Request Guidelines
There is no visible git history in this directory, so use a consistent convention from the start. Recommended commit format:

- `feat: add SSH session bootstrap`
- `fix: handle invalid host key`
- `docs: add local setup notes`

Pull requests should include a short summary, test evidence, and any config or security impact. Add screenshots only for UI changes. Link related issues when available.

## Security & Configuration Tips
Do not commit private keys, secrets, or real host inventories. Keep local credentials in ignored files such as `.env.local` or per-user SSH config. Sanitize logs and examples before committing anything security-sensitive.
