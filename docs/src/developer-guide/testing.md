# Testing

Comprehensive testing guide for Open Sesame.

## Quick Start

```bash
# Run all tests
mise run test

# This runs:
# - cargo fmt --check (formatting)
# - cargo clippy (linter)
# - cargo test (unit and integration tests)
```

## Test Categories

### Unit Tests

Test individual functions and modules in isolation.

**Run unit tests:**

```bash
cargo test
```

**Run specific module tests:**

```bash
# Test config module
cargo test config::

# Test hint assignment
cargo test core::hint

# Test color parsing
cargo test config::schema::color
```

**Example unit test:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_hex_parse() {
        let c = Color::from_hex("#ff0000").unwrap();
        assert_eq!(c, Color::new(255, 0, 0, 255));
    }
}
```

### Integration Tests

Test multiple modules working together.

**Location:** `tests/` directory

**Run integration tests:**

```bash
cargo test --test '*'
```

**Example integration test:**

```rust
// tests/hint_assignment.rs
#[test]
fn test_hint_assignment_with_config() {
    let config = Config::load().unwrap();
    let windows = vec![/* ... */];
    let assignment = HintAssignment::assign(&windows, |app_id| {
        config.key_for_app(app_id)
    });
    assert_eq!(assignment.hints.len(), windows.len());
}
```

### Documentation Tests

Test code examples in documentation.

**Run doc tests:**

```bash
cargo test --doc
```

**Example doc test:**

```rust
/// Parse a color from hex.
///
/// # Examples
///
/// ```
/// use open_sesame::config::Color;
/// let color = Color::from_hex("#ff0000").unwrap();
/// assert_eq!(color.r, 255);
/// ```
pub fn from_hex(s: &str) -> Result<Color> {
    // ...
}
```

### Manual Tests

Interactive testing during development.

**Run development build:**

```bash
mise run dev
```

**Test specific functionality:**

```bash
# Test window enumeration
sesame --list-windows

# Test configuration validation
sesame --validate-config

# Test keybinding setup
sesame --setup-keybinding alt+space
```

## Running Tests

### All Tests

Run the full test suite:

```bash
# Via mise (recommended)
mise run test

# Or manually
cargo fmt --check && cargo clippy && cargo test
```

### Specific Tests

Run individual test functions:

```bash
# Run a specific test
cargo test test_color_hex_parse

# Run tests matching a pattern
cargo test color
```

### With Output

Show println! output from tests:

```bash
cargo test -- --nocapture
```

### With Logging

Enable logging during tests:

```bash
RUST_LOG=debug cargo test
```

### Parallel vs Sequential

```bash
# Run tests in parallel (default)
cargo test

# Run tests sequentially
cargo test -- --test-threads=1
```

## Code Quality

### Formatting

Check code formatting:

```bash
# Check formatting
cargo fmt --check

# Auto-format code
mise run fmt
```

**Configuration:** `.rustfmt.toml`

### Linting

Run Clippy linter:

```bash
# Check lints
cargo clippy

# Check with all features
cargo clippy --all-features

# Fail on warnings
cargo clippy -- -D warnings
```

**Clippy configuration:** `Cargo.toml`

```toml
[lints.clippy]
all = "warn"
pedantic = "warn"
```

### Dead Code Detection

Find unused code:

```bash
cargo clippy -- -W dead_code
```

## Test Coverage

### Measuring Coverage

Use `cargo-tarpaulin` for coverage reports:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html

# Open report
xdg-open tarpaulin-report.html
```

**Coverage goals:**

- Overall: > 70%
- Core modules: > 85%
- Utility modules: > 90%

### Current Coverage

Current test coverage by module:

| Module | Coverage |
|--------|----------|
| `config` | 92% |
| `core` | 88% |
| `util` | 95% |
| `input` | 85% |
| `platform` | 45% (hard to test Wayland) |
| `render` | 40% (hard to test rendering) |

## Continuous Integration

### GitHub Actions

Tests run automatically on every push:

```yaml
# .github/workflows/ci.yml
- name: Format check
  run: cargo fmt --check

- name: Clippy
  run: cargo clippy -- -D warnings

- name: Tests
  run: cargo test
```

**CI requirements:**

- All tests must pass
- No clippy warnings
- Code must be formatted

### Pre-commit Hooks

Set up pre-commit hooks to catch issues early:

```bash
# Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/sh
mise run test
EOF

chmod +x .git/hooks/pre-commit
```

## Writing Tests

### Unit Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_name() {
        // Arrange
        let input = /* setup */;

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Test Organization

Group related tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    mod color_parsing {
        use super::*;

        #[test]
        fn parses_rgb() { /* ... */ }

        #[test]
        fn parses_rgba() { /* ... */ }

        #[test]
        fn rejects_invalid() { /* ... */ }
    }
}
```

### Test Naming

Use descriptive names:

```rust
#[test]
fn test_hint_assignment_single_window() { /* ... */ }

#[test]
fn test_hint_assignment_multiple_windows_same_app() { /* ... */ }

#[test]
fn test_hint_assignment_with_config() { /* ... */ }
```

### Assertions

Common assertions:

```rust
// Equality
assert_eq!(actual, expected);

// Inequality
assert_ne!(actual, unexpected);

// Boolean
assert!(condition);
assert!(!condition);

// Result/Option
assert!(result.is_ok());
assert!(result.is_err());
assert!(option.is_some());
assert!(option.is_none());

// Custom message
assert_eq!(actual, expected, "Expected {}, got {}", expected, actual);
```

### Test Fixtures

Create reusable test data:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config {
            settings: Settings::default(),
            keys: HashMap::new(),
        }
    }

    fn sample_windows() -> Vec<Window> {
        vec![
            Window {
                id: WindowId::new("1"),
                app_id: AppId::new("firefox"),
                title: "Firefox".to_string(),
                is_focused: false,
            },
        ]
    }

    #[test]
    fn test_with_fixtures() {
        let config = sample_config();
        let windows = sample_windows();
        // ...
    }
}
```

## Benchmarking

### Criterion Benchmarks

Use Criterion for performance benchmarking:

```bash
# Add criterion to Cargo.toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "hint_assignment"
harness = false
```

**Example benchmark:**

```rust
// benches/hint_assignment.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use open_sesame::core::HintAssignment;

fn bench_hint_assignment(c: &mut Criterion) {
    let windows = /* create 100 windows */;

    c.bench_function("hint_assignment_100_windows", |b| {
        b.iter(|| {
            HintAssignment::assign(black_box(&windows), |_| None)
        })
    });
}

criterion_group!(benches, bench_hint_assignment);
criterion_main!(benches);
```

**Run benchmarks:**

```bash
cargo bench
```

### Performance Goals

Target performance metrics:

| Operation | Target |
|-----------|--------|
| Hint assignment (100 windows) | < 1ms |
| Configuration loading | < 5ms |
| Window enumeration | < 10ms |
| Render frame | < 16ms (60 FPS) |

## Testing Wayland Functionality

Testing Wayland interactions is challenging because it requires a running compositor.

### Manual Testing

```bash
# Test on real Wayland session
mise run dev

# Test window enumeration
sesame --list-windows

# Test window activation
sesame --launcher
```

### Integration Testing

Use a nested Wayland compositor for automated tests:

```bash
# Install weston (reference compositor)
sudo apt install weston

# Run tests in nested session
weston --backend=headless-backend.so &
WAYLAND_DISPLAY=wayland-1 cargo test platform::
```

### Mock Testing

For unit tests, mock Wayland interactions:

```rust
#[cfg(test)]
mod tests {
    struct MockWindowManager {
        windows: Vec<Window>,
    }

    impl MockWindowManager {
        fn enumerate(&self) -> Vec<Window> {
            self.windows.clone()
        }
    }

    #[test]
    fn test_with_mock() {
        let mock = MockWindowManager {
            windows: vec![/* ... */],
        };
        assert_eq!(mock.enumerate().len(), 1);
    }
}
```

## Debugging Tests

### Failed Test Output

When a test fails:

```bash
# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run specific failing test
cargo test test_name -- --nocapture

# Show detailed output
cargo test -- --show-output
```

### Test in Debug Mode

```bash
# Build and run tests in debug mode
cargo test --no-default-features
```

### GDB Debugging

Debug a test with GDB:

```bash
# Build test binary
cargo test --no-run

# Find test binary
find target/debug/deps -name 'open_sesame*' -type f

# Run with GDB
gdb target/debug/deps/open_sesame-<hash>

# In GDB:
(gdb) break test_function_name
(gdb) run
```

## Test Maintenance

### Keeping Tests Updated

- Update tests when changing functionality
- Add tests for new features
- Remove tests for removed features
- Refactor tests when refactoring code

### Test Documentation

Document complex test scenarios:

```rust
#[test]
/// Test that hint assignment works correctly when:
/// 1. Multiple windows of the same app exist
/// 2. Some apps have configured keys
/// 3. Some apps do not have configured keys
///
/// Expected behavior:
/// - Firefox instances get f, ff, fff
/// - Ghostty instances get g, gg
/// - Unconfigured apps get sequential letters
fn test_hint_assignment_complex_scenario() {
    // ...
}
```

## Troubleshooting

### Tests Fail on CI but Pass Locally

Possible causes:

- Different Rust version
- Missing system dependencies
- Environment variables

**Solution:**

```bash
# Match CI environment
rustup install 1.91
cargo +1.91 test
```

### Tests Hang

**Solution:**

```bash
# Run with timeout
timeout 60s cargo test

# Check for infinite loops
cargo test -- --test-threads=1
```

### Flaky Tests

Tests that sometimes pass and sometimes fail:

**Common causes:**

- Race conditions
- Timing dependencies
- File system state

**Solution:**

- Make tests deterministic
- Use mocks instead of real I/O
- Add retry logic for integration tests

## Next Steps

- [Contributing Guide](./contributing.md) - Contribute code and tests
- [Architecture](./architecture.md) - Understand the codebase
- [Building Guide](./building.md) - Build from source
