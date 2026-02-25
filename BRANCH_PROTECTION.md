# Branch Protection Setup

This guide explains how to configure branch protection rules for the AlpenGuard repository to ensure code quality and prevent accidental force pushes or deletions.

## Why Branch Protection?

Branch protection rules help maintain code quality by:
- Preventing force pushes that could rewrite history
- Preventing accidental branch deletion
- Requiring status checks (CI/CD) to pass before merging
- Requiring code reviews before merging
- Ensuring a clean, linear commit history

## Recommended Settings for AlpenGuard

### Step 1: Navigate to Branch Protection Settings

1. Go to your GitHub repository: `https://github.com/AlpenGuard/alpenguard-security-framework`
2. Click **Settings** (top navigation)
3. Click **Branches** (left sidebar)
4. Under "Branch protection rules", click **Add rule**

### Step 2: Configure Protection Rules

**Branch name pattern:** `main`

#### ✅ Protect matching branches

**Enable the following settings:**

- [x] **Require a pull request before merging**
  - [x] Require approvals: `1` (at least one reviewer)
  - [ ] Dismiss stale pull request approvals when new commits are pushed (optional)
  - [ ] Require review from Code Owners (optional, requires CODEOWNERS file)

- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - **Required status checks:**
    - `Test Oracle (Rust) / test`
    - `Build Console (React/Vite) / build`
    - `Security Audit / security`

- [x] **Require conversation resolution before merging**
  - Ensures all PR comments are resolved

- [x] **Require signed commits** (optional, highly recommended for security)
  - Ensures commits are cryptographically signed

- [x] **Require linear history**
  - Prevents merge commits, enforces rebase or squash merges
  - Keeps commit history clean

- [x] **Do not allow bypassing the above settings**
  - Applies rules to administrators too

- [x] **Restrict who can push to matching branches**
  - Only allow specific users/teams to push directly
  - Recommended: `AlpenGuard/maintainers` team

#### ❌ Do NOT enable (unless needed)

- [ ] Require deployments to succeed before merging
  - Not needed unless you have deployment previews

- [ ] Lock branch
  - Only use for archived/frozen branches

- [ ] Allow force pushes
  - **NEVER enable this** - defeats the purpose of protection

- [ ] Allow deletions
  - **NEVER enable this** - prevents accidental branch deletion

### Step 3: Save Protection Rules

Click **Create** or **Save changes** at the bottom of the page.

## Verification

After setting up branch protection:

1. Try to force push to `main` (should be rejected):
   ```bash
   git push --force origin main
   # Error: protected branch hook declined
   ```

2. Try to delete `main` (should be rejected):
   ```bash
   git push origin --delete main
   # Error: protected branch hook declined
   ```

3. Create a test PR and verify status checks are required

## Working with Protected Branches

### For Contributors

1. **Always work in feature branches:**
   ```bash
   git checkout -b feature/my-feature
   git push origin feature/my-feature
   ```

2. **Create a Pull Request** on GitHub

3. **Wait for CI/CD checks** to pass:
   - Oracle tests (Rust)
   - Console build (React)
   - Security audit (cargo audit)

4. **Request review** from maintainers

5. **Merge via GitHub UI** (squash or rebase merge)

### For Maintainers

1. **Review PRs thoroughly**
2. **Ensure all status checks pass**
3. **Resolve all conversations**
4. **Merge using "Squash and merge" or "Rebase and merge"**
5. **Delete feature branch** after merging

## Status Checks Configuration

The following GitHub Actions workflows provide status checks:

| Workflow | File | Status Check Name |
|----------|------|-------------------|
| Oracle Tests | `.github/workflows/oracle-tests.yml` | `Test Oracle (Rust) / test` |
| Console Build | `.github/workflows/console-build.yml` | `Build Console (React/Vite) / build` |
| Security Audit | `.github/workflows/oracle-tests.yml` | `Security Audit / security` |

These checks run automatically on:
- Push to `main`
- Pull requests targeting `main`

## Troubleshooting

### "Status checks are required but no checks have run"

**Cause:** No commits have triggered the workflows yet.

**Solution:** Make a small change and push to trigger workflows:
```bash
git commit --allow-empty -m "chore: trigger CI checks"
git push origin main
```

### "Required status check is not present"

**Cause:** Workflow names changed or workflows haven't run yet.

**Solution:** 
1. Check workflow names in `.github/workflows/`
2. Trigger workflows by pushing a commit
3. Update required checks in branch protection settings

### "Cannot push to protected branch"

**Cause:** You're trying to push directly to `main`.

**Solution:** Use the PR workflow:
```bash
git checkout -b feature/my-fix
git push origin feature/my-fix
# Create PR on GitHub
```

## Additional Security: CODEOWNERS

Create a `CODEOWNERS` file to automatically request reviews from specific teams:

```
# .github/CODEOWNERS

# Default owners for everything
* @AlpenGuard/maintainers

# Oracle (Rust)
/services/oracle/ @AlpenGuard/rust-team

# Solana programs
/programs/ @AlpenGuard/solana-team

# Console (React)
/apps/console/ @AlpenGuard/frontend-team

# CI/CD
/.github/ @AlpenGuard/devops-team
```

## References

- [GitHub Branch Protection Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Required Status Checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging)
- [Signed Commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
