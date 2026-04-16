# Contributing

Thanks for your interest in contributing to the Trace Python SDK.

## Setup

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```sh
# Clone the repo
git clone https://github.com/securewithtrace/trace-python.git
cd trace-python

# Install dependencies
uv sync
```

## Development

### Project structure

```
src/trace_python/        # Package source (src layout)
  webhooks/              # Webhook verification and event parsing
tests/                   # Test suite
```

### Running checks

The CI pipeline runs four checks. You can run them all locally:

```sh
# Formatting (ruff)
uv run ruff format --check .

# Linting (ruff)
uv run ruff check .

# Type checking (mypy, strict mode)
uv run mypy --strict .

# Tests with coverage
uv run pytest
```

To auto-fix formatting and lint issues:

```sh
uv run ruff format .
uv run ruff check --fix .
```

### Writing tests

Tests live in `tests/` and use [pytest](https://docs.pytest.org/). Run a specific test file or test function with:

```sh
uv run pytest tests/test_webhooks.py
uv run pytest tests/test_webhooks.py::test_valid_signature_passes_verification
```

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Make sure all four checks pass locally before opening a PR.
3. Keep PRs focused — one feature or fix per PR.

## Releases

Releases are managed by [release-please](https://github.com/googleapis/release-please). When PRs are merged to `main`, release-please opens a release PR that bumps the version and generates a changelog. Merging the release PR triggers a publish to PyPI.
