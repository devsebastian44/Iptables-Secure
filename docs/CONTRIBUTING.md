# Contributing to Iptables-Secure

First off, thank you for considering contributing to Iptables-Secure! It's people like you that make this tool better for everyone.

## Code of Conduct

By participating in this project, you agree to abide by our professional and ethical standards. This project is for educational and ethical cybersecurity purposes only.

## How Can I Contribute?

### Reporting Bugs
- Check the issues to see if the bug has already been reported.
- If not, open a new issue. Include a clear title, a description of the problem, and steps to reproduce it.

### Suggesting Enhancements
- Open a new issue with the tag `enhancement`.
- Describe the feature and why it would be useful.

### Pull Requests
1. **Fork** the repository.
2. **Create a branch** for your feature or fix: `git checkout -b feature/amazing-feature`.
3. **Commit** your changes using [Conventional Commits](https://www.conventionalcommits.org/): `feat: add new rule module`.
4. **Push** to your branch: `git push origin feature/amazing-feature`.
5. **Open a Pull Request** against the `main` branch.

## Coding Standards

- Follow **PEP 8** for Python code.
- Ensure all functions have clear docstrings.
- Add unit tests for any new features.
- All tests must pass before a PR can be merged.

## Running Tests Locally

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run the test suite
pytest tests/ -v
```

## Security Disclosure

If you find a security vulnerability, please do **not** open an issue. Instead, contact the maintainer directly.
