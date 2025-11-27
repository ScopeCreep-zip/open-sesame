# Contributing

Thank you for considering contributing to Open Sesame! This guide will help you get started.

## Code of Conduct

We value:

- **Quality over speed** - Take time to write excellent code
- **Clear documentation** - Code should be self-explanatory
- **Comprehensive testing** - All quality gates must pass
- **User empathy** - Features should solve real problems
- **Respectful collaboration** - Be kind and constructive

## Getting Started

### 1. Fork and Clone

```bash
# Fork on GitHub (click "Fork" button)

# Clone your fork
git clone https://github.com/YOUR_USERNAME/open-sesame.git
cd open-sesame

# Add upstream remote
git remote add upstream https://github.com/ScopeCreep-zip/open-sesame.git
```

### 2. Set Up Development Environment

```bash
# Install mise
curl https://mise.run | sh

# Install dependencies
mise run setup

# Verify setup
mise run test
```

### 3. Create a Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

## Development Workflow

### 1. Make Changes

```bash
# Edit code
$EDITOR src/...

# Format code
mise run fmt

# Run tests
mise run test

# Test manually
mise run dev
```

### 2. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: Add support for custom hint colors"
```

**Commit message format:**

```text
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code style changes (formatting, etc.)
- `refactor` - Code refactoring
- `test` - Adding or updating tests
- `chore` - Maintenance tasks

**Examples:**

```text
feat: Add window preview thumbnails

Implements thumbnail rendering in the overlay using the
wlr-screencopy protocol. Thumbnails are cached for performance.

Closes #42
```

```text
fix: Correct hint assignment for duplicate app IDs

Previously, windows with identical app IDs would get incorrect
hint sequences. Now uses window ID as tiebreaker.

Fixes #123
```

### 3. Push Changes

```bash
# Push to your fork
git push origin feature/your-feature-name
```

### 4. Create Pull Request

1. Go to <https://github.com/ScopeCreep-zip/open-sesame>
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill in the PR template:
   - Description of changes
   - Testing performed
   - Related issues

**PR Title Format:**

```text
feat: Add window preview thumbnails
fix: Correct hint assignment for duplicate app IDs
docs: Update configuration guide
```

## Quality Gates

All contributions must pass these checks:

### 1. Formatting

```bash
cargo fmt --check
```

Code must be formatted with `rustfmt`.

**Auto-format:**

```bash
mise run fmt
```

### 2. Linting

```bash
cargo clippy -- -D warnings
```

No clippy warnings allowed.

**Common issues:**

- Unused variables
- Unnecessary clones
- Non-idiomatic code

**Fix:**

```bash
# View warnings
cargo clippy

# Fix automatically (when possible)
cargo clippy --fix
```

### 3. Tests

```bash
cargo test
```

All tests must pass.

**Add tests for:**

- New features
- Bug fixes
- Edge cases

### 4. Documentation

```bash
cargo doc --no-deps
```

Public APIs must be documented.

**Required:**

- Module docs (`//!`)
- Public function docs (`///`)
- Examples in docs (when appropriate)

**Example:**

```rust
/// Parse a color from hex string.
///
/// # Arguments
///
/// * `s` - Hex string in format "#RRGGBB" or "#RRGGBBAA"
///
/// # Examples
///
/// ```
/// use open_sesame::config::Color;
/// let color = Color::from_hex("#ff0000").unwrap();
/// assert_eq!(color.r, 255);
/// ```
///
/// # Errors
///
/// Returns `Error::InvalidColor` if the string is not valid hex.
pub fn from_hex(s: &str) -> Result<Color> {
    // ...
}
```

## Contribution Guidelines

### Code Style

Follow Rust conventions:

- Use `snake_case` for functions and variables
- Use `CamelCase` for types
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefer explicit over implicit
- Keep functions small and focused

**Good:**

```rust
fn assign_hints(windows: &[Window], config: &Config) -> HintAssignment {
    // Clear, descriptive name
    // Single responsibility
}
```

**Avoid:**

```rust
fn do_stuff(w: &[Window], c: &Config) -> HintAssignment {
    // Unclear name
    // Abbreviated parameters
}
```

### Error Handling

- Use `Result` for fallible operations
- Use `anyhow::Result` for application errors
- Use custom error types for library code
- Provide context with `.context()`
- Never `unwrap()` in production code

**Good:**

```rust
pub fn load_config() -> Result<Config> {
    let file = std::fs::read_to_string(path)
        .context("Failed to read config file")?;

    let config: Config = toml::from_str(&file)
        .context("Failed to parse config")?;

    Ok(config)
}
```

**Avoid:**

```rust
pub fn load_config() -> Config {
    let file = std::fs::read_to_string(path).unwrap();
    toml::from_str(&file).unwrap()
}
```

### Testing

Write tests for all new code:

**Unit tests:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_color_rgb() {
        let color = Color::from_hex("#ff0000").unwrap();
        assert_eq!(color, Color::new(255, 0, 0, 255));
    }

    #[test]
    fn test_parse_color_invalid() {
        assert!(Color::from_hex("#xyz").is_err());
    }
}
```

**Integration tests:**

```rust
// tests/hint_assignment.rs
#[test]
fn test_hint_assignment_integration() {
    let config = Config::load().unwrap();
    let windows = enumerate_test_windows();
    let assignment = HintAssignment::assign(&windows, |app_id| {
        config.key_for_app(app_id)
    });
    assert!(assignment.hints.len() > 0);
}
```

### Documentation

- Document all public APIs
- Include examples for complex features
- Update user guide for user-facing changes
- Update CHANGELOG.md

**Module documentation:**

```rust
//! Window hint assignment algorithm.
//!
//! This module implements the core Vimium-style hint assignment logic.
//! Windows are assigned letter sequences (g, gg, ggg) based on configured
//! key bindings and app IDs.
//!
//! # Examples
//!
//! ```
//! use open_sesame::core::HintAssignment;
//!
//! let windows = vec![/* ... */];
//! let assignment = HintAssignment::assign(&windows, |_| None);
//! ```
```

## Common Contribution Types

### Adding a New Feature

1. Open an issue first to discuss the feature
2. Implement the feature in a new module if appropriate
3. Add comprehensive tests
4. Update documentation
5. Add to CHANGELOG.md

#### Example: Adding window thumbnails

1. Create issue: "Feature: Window preview thumbnails"
2. Implement in `src/preview.rs`
3. Add tests in `src/preview.rs` and `tests/preview.rs`
4. Update user guide: `docs/src/user-guide/basic-usage.md`
5. Add to CHANGELOG.md

### Fixing a Bug

1. Create a test that reproduces the bug
2. Fix the bug
3. Verify the test passes
4. Add to CHANGELOG.md

#### Example: Fixing hint assignment bug

```rust
// 1. Create test that reproduces bug
#[test]
fn test_duplicate_app_ids() {
    let windows = vec![
        Window { app_id: "firefox", /* ... */ },
        Window { app_id: "firefox", /* ... */ },
    ];
    let assignment = HintAssignment::assign(&windows, |_| Some('f'));

    // This should pass but currently fails
    assert_eq!(assignment.hints[0].hint, "f");
    assert_eq!(assignment.hints[1].hint, "ff");
}

// 2. Fix the bug in src/core/hint.rs
// ...

// 3. Verify test now passes
// cargo test test_duplicate_app_ids
```

### Improving Documentation

Documentation improvements are always welcome:

- Fix typos and grammar
- Add examples
- Clarify confusing sections
- Update outdated information

**No issue required for documentation PRs.**

### Refactoring Code

1. Ensure all tests pass before refactoring
2. Refactor incrementally
3. Ensure all tests still pass after refactoring
4. No functional changes in refactoring PRs

#### Example: Extract function

```rust
// Before
fn process_windows(&self) -> Vec<WindowHint> {
    let mut hints = Vec::new();
    for window in &self.windows {
        let key = self.config.key_for_app(&window.app_id);
        if let Some(k) = key {
            hints.push(WindowHint { hint: k.to_string(), /* ... */ });
        }
    }
    hints
}

// After
fn process_windows(&self) -> Vec<WindowHint> {
    self.windows
        .iter()
        .filter_map(|w| self.create_hint(w))
        .collect()
}

fn create_hint(&self, window: &Window) -> Option<WindowHint> {
    self.config
        .key_for_app(&window.app_id)
        .map(|k| WindowHint { hint: k.to_string(), /* ... */ })
}
```

## PR Review Process

### What to Expect

1. **Automated checks** - CI runs tests, formatting, and linting
2. **Code review** - Maintainer reviews code for quality and correctness
3. **Feedback** - You may be asked to make changes
4. **Approval** - Once approved, PR is merged

### Review Timeline

- Small PRs (< 100 lines): 1-3 days
- Medium PRs (100-500 lines): 3-7 days
- Large PRs (> 500 lines): 1-2 weeks

**Tip:** Smaller PRs get reviewed faster!

### Responding to Feedback

```bash
# Make requested changes
$EDITOR src/...

# Commit changes
git commit -m "Address review feedback"

# Push updates
git push origin feature/your-feature-name
```

**PR automatically updates when you push.**

### After Merge

```bash
# Update your main branch
git checkout main
git pull upstream main

# Delete feature branch
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name
```

## Communication

### Asking Questions

- **GitHub Issues** - Feature requests, bug reports
- **GitHub Discussions** - General questions, ideas
- **Pull Requests** - Code-related discussions

### Reporting Bugs

Use the bug report template:

```markdown
**Describe the bug**
A clear description of the bug.

**To Reproduce**
Steps to reproduce:
1. Launch sesame with config X
2. Press key Y
3. See error

**Expected behavior**
What should happen.

**System information**
- OS: Pop!_OS 24.04
- COSMIC version: X.Y
- Open Sesame version: (output of `sesame --version`)

**Debug log**
Attach output of: RUST_LOG=debug sesame --launcher
```

### Suggesting Features

Use the feature request template:

```markdown
**Feature Description**
Clear description of the feature.

**Use Case**
Why is this feature useful?

**Proposed Implementation**
How might this work?

**Alternatives Considered**
Other ways to solve the problem.
```

## Development Tips

### Debugging

```bash
# Run with debug logging
RUST_LOG=debug mise run dev

# View debug log
tail -f ~/.cache/open-sesame/debug.log

# Run with backtrace
RUST_BACKTRACE=1 mise run dev
```

### Testing Local Changes

```bash
# Install local build
mise run install

# Test it
sesame --launcher

# Uninstall
mise run uninstall
```

### Iterating Quickly

```bash
# Watch for changes and rebuild
cargo watch -x check -x test

# Or with mise
mise run dev  # Runs release build (faster)
```

## Recognition

Contributors are recognized in:

- CHANGELOG.md (for each release)
- GitHub contributors page
- Release notes

Thank you for contributing to Open Sesame!

## See Also

- [Architecture](./architecture.md) - Understand the codebase structure
- [Building Guide](./building.md) - Build from source
- [Testing Guide](./testing.md) - Run and write tests
