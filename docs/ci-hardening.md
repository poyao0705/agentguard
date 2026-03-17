# CI Hardening Pipeline

The CI pipeline now includes:

- tests on Python 3.11, 3.12, and 3.13
- Ruff linting
- mypy type checking
- package build validation with `python -m build`
- `twine check` for distribution metadata
- `pip-audit` dependency scanning

Jobs stay separated so failures are easier to read and fix.