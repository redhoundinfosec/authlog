# Contributing to authlog

Thank you for your interest in contributing to authlog. This document covers how to get started, coding standards, and the pull request process.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/authlog`
3. **Create a branch**: `git checkout -b feat/my-feature`
4. **Install Go** 1.21+: https://go.dev/dl/
5. **Build and test**: `make build && make test`

## Development Workflow

```bash
# Run tests
make test

# Run tests with verbose output
make test-v

# Build the binary
make build

# Run against a sample log
./bin/authlog analyze examples/linux-auth.log
```

## Code Standards

- All Go code must pass `go vet ./...` and `golangci-lint run`
- New parsers must implement the `parser.Parser` interface
- All new functionality must include unit tests
- Keep zero external dependencies — stdlib only
- Follow the existing package structure:
  - `internal/parser/` — log format parsers
  - `internal/analyzer/` — analysis logic
  - `internal/output/` — rendering
  - `internal/cli/` — command-line interface

## Adding a New Log Format

1. Create `internal/parser/myformat.go` implementing `Parser`
2. Add detection heuristics to `internal/parser/detect.go`
3. Add a `NewParser(FormatMyFormat)` case to `detect.go`
4. Write comprehensive tests in `internal/parser/myformat_test.go`
5. Update `docs/supported-formats.md`
6. Add sample data to `examples/`

## Pull Request Process

1. Ensure `make test` passes with no failures
2. Ensure `go vet ./...` reports no issues
3. Add or update tests for any new behavior
4. Update `CHANGELOG.md` under `[Unreleased]`
5. Keep PRs focused — one feature or fix per PR
6. Write a clear PR description explaining the change and motivation

## Reporting Bugs

Open a GitHub issue with:
- authlog version (`authlog version`)
- Operating system and Go version
- Minimal reproduction case (sanitized log snippet if possible)
- Expected vs. actual behavior

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Code of Conduct

Be respectful, constructive, and professional. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
