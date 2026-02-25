# Contributing

Thank you for your interest in contributing to AlpenGuard! This document provides guidelines for contributing to the project.

## Development Workflow

### 1. Fork and Clone

```bash
git clone https://github.com/AlpenGuard/alpenguard-security-framework.git
cd alpenguard-security-framework
```

### 2. Create a Feature Branch

**Never commit directly to `main`** - the branch is protected.

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 3. Make Your Changes

- Keep changes small and focused
- Do not commit secrets (use `.env.example` as a template)
- Add tests for new logic
- Follow existing code style
- Run formatters before committing:
  ```bash
  # Rust
  cd services/oracle
  cargo fmt
  cargo clippy
  
  # TypeScript
  cd apps/console
  npm run format
  ```

### 4. Commit Your Changes

Use conventional commit messages:

```bash
git commit -m "feat: add KMS key rotation endpoint"
git commit -m "fix: resolve tenant isolation bug in list endpoint"
git commit -m "docs: update deployment guide for GCP KMS"
git commit -m "chore: upgrade jsonwebtoken to 10.2.0"
```

**Commit types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `chore`: Maintenance tasks
- `refactor`: Code refactoring
- `test`: Adding tests
- `ci`: CI/CD changes

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Pull Request Guidelines

### PR Title Format

Use conventional commit format:
- `feat: add payment verification endpoint`
- `fix: resolve CORS issue in Oracle`
- `docs: update README with KMS setup`

### PR Description

Include:
1. **What** - What does this PR do?
2. **Why** - Why is this change needed?
3. **How** - How does it work?
4. **Testing** - How was it tested?

Example:
```markdown
## What
Adds KMS envelope encryption support for per-tenant DEKs.

## Why
Enterprise deployments require proper key management with rotation support.

## How
- Created `kms.rs` module with GCP Cloud KMS integration
- Integrated KMS manager into Oracle AppState
- Added DEK caching with configurable TTL

## Testing
- Manual testing with GCP KMS test project
- Verified DEK caching and rotation
- Tested fallback to env-provided key
```

### Status Checks

Your PR must pass all CI/CD checks before merging:

- ✅ **Oracle Tests** - `cargo test`, `cargo clippy`, `cargo fmt`
- ✅ **Console Build** - `npm run build`, `npm run type-check`
- ✅ **Security Audit** - `cargo audit`

If checks fail, review the logs and fix the issues.

### Code Review

- At least **1 approval** required from maintainers
- Address all review comments
- Resolve all conversations before merging

### Merging

Maintainers will merge using **Squash and merge** or **Rebase and merge** to keep history clean.

## Branch Protection

The `main` branch is protected with the following rules:

- ❌ No force pushes
- ❌ No direct pushes (use PRs)
- ❌ No deletions
- ✅ Require status checks to pass
- ✅ Require 1 approval
- ✅ Require linear history

See [`BRANCH_PROTECTION.md`](BRANCH_PROTECTION.md) for detailed setup instructions.

## Development Guidelines

### Rust (Oracle)

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Add `#[cfg(test)]` modules for unit tests
- Follow AIUC-1 security standards (see user rules)

### TypeScript (Console)

- Use TypeScript strict mode
- Add type annotations
- Use functional components with hooks
- Follow existing UI patterns

### Solana Programs (Anchor)

- Use Anchor 0.30+
- Implement proper error handling
- Add comprehensive instruction validation
- Use PDAs for state accounts
- Document all instructions

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Follow the process in [`SECURITY.md`](SECURITY.md):
1. Email security contact privately
2. Provide detailed description
3. Wait for acknowledgment
4. Coordinate disclosure timeline

### Security Requirements

- ❌ Never commit secrets, API keys, or private keys
- ✅ Use `.env.example` for configuration templates
- ✅ Validate all user inputs
- ✅ Use parameterized queries (prevent injection)
- ✅ Implement rate limiting
- ✅ Add audit logging for sensitive operations

## Testing

### Running Tests

```bash
# Oracle (Rust)
cd services/oracle
cargo test

# Console (TypeScript)
cd apps/console
npm test

# Solana Programs
cd programs/alpenguard
anchor test
```

### Test Coverage

- Add tests for new features
- Add tests for bug fixes
- Aim for >80% coverage on critical paths

## Documentation

Update documentation when:
- Adding new features
- Changing APIs
- Updating configuration
- Modifying deployment procedures

Files to update:
- `README.md` - Overview and quick start
- `ARCHITECTURE.md` - System design
- `DEPLOY_*.md` - Deployment guides
- `CHANGELOG.md` - Version history
- `.env.example` - Configuration options

## Questions?

- Open a GitHub Discussion for general questions
- Open an issue for bug reports or feature requests
- Join our community channels (if available)

Thank you for contributing to AlpenGuard! 🎉
