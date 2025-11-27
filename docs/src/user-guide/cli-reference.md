# CLI Reference

Complete command-line reference for the `sesame` binary.

## Synopsis

```text
sesame [OPTIONS]
```

## Options

### Configuration

#### `-c, --config <PATH>`

Use a custom configuration file instead of the default.

**Example:**

```bash
sesame -c ~/my-config.toml --list-windows
```

**Default:** XDG config paths (`~/.config/open-sesame/config.toml`)

#### `--print-config`

Print default configuration to stdout and exit.

Useful for generating a starter configuration file.

**Example:**

```bash
# View default config
sesame --print-config

# Create user config from defaults
sesame --print-config > ~/.config/open-sesame/config.toml
```

#### `--validate-config`

Validate configuration file and report any issues.

Checks for errors and warnings, exits with status code 0 if valid.

**Example:**

```bash
sesame --validate-config
```

**Output (valid):**

```text
Configuration is valid
```

**Output (invalid):**

```text
Configuration issues:
  - [ERROR] Invalid color format: "#xyz"
  - [WARNING] Key binding 'f' has no apps configured
```

### Window Management

#### `--list-windows`

List all current windows with assigned hints and exit.

Shows window IDs, app IDs, titles, and hint assignments. Useful for debugging and finding app IDs for configuration.

**Example:**

```bash
sesame --list-windows
```

**Output:**

```text
=== Window Enumeration ===
Found 3 windows:
(Focused window moved to end by Wayland enumeration)
  [0] wayland-1 - firefox - Mozilla Firefox
  [1] wayland-2 - code - Visual Studio Code
  [2] wayland-3 - ghostty - Terminal <-- FOCUSED (origin)

=== MRU State (persistence only, not used for ordering) ===
Previous window: Some("wayland-1")
Current window:  Some("wayland-3")

=== Hint Assignment ===
  [f] firefox - Mozilla Firefox (wayland-1)
  [v] code - Visual Studio Code (wayland-2)
  [g] ghostty - Terminal (wayland-3)

=== Quick Switch Target (index 0) ===
Quick Alt+Tab would activate: [f] firefox (Mozilla Firefox)
```

### Keybinding Management

#### `--setup-keybinding [KEY_COMBO]`

Setup COSMIC keybinding for Open Sesame.

Uses `activation_key` from config if no key combo is specified. Configures COSMIC desktop to launch
`sesame --launcher` when the key is pressed.

**Examples:**

```bash
# Use default from config (alt+space)
sesame --setup-keybinding

# Specify custom key combo
sesame --setup-keybinding alt+tab
sesame --setup-keybinding super+space
```

**Supported key combinations:**

- `alt+space`
- `alt+tab`
- `super+space`
- `ctrl+alt+space`
- Any combination supported by COSMIC

#### `--remove-keybinding`

Remove Open Sesame keybinding from COSMIC.

Cleans up any configured shortcuts. Use this before uninstalling.

**Example:**

```bash
sesame --remove-keybinding
```

#### `--keybinding-status`

Show current keybinding configuration status.

Displays what key combo is currently bound, if any.

**Example:**

```bash
sesame --keybinding-status
```

**Output:**

```text
Keybinding configured: alt+space → sesame --launcher
```

### Switcher Behavior

#### `-b, --backward`

Cycle backward through windows (for Alt+Shift+Tab).

Used with switcher mode for reverse cycling. Typically bound to `Alt+Shift+Tab` in COSMIC.

**Example:**

```bash
sesame --backward
```

**Usage pattern:**

```bash
# Configure COSMIC shortcuts:
# Alt+Tab → sesame
# Alt+Shift+Tab → sesame --backward
```

#### `-l, --launcher`

Launcher mode: show full overlay with hints immediately.

Without this flag, runs in switcher mode (Alt+Tab behavior). In switcher mode:

- Tap = quick switch to previous window
- Hold = show overlay after delay

**Example:**

```bash
sesame --launcher
```

**Comparison:**

| Mode | Command | Behavior |
|------|---------|----------|
| Switcher | `sesame` | Quick tap = instant switch, hold = delayed overlay |
| Launcher | `sesame --launcher` | Always shows overlay immediately |

### Help and Version

#### `-h, --help`

Print help message and exit.

Shows usage information and all available options.

**Example:**

```bash
sesame --help
```

#### `-V, --version`

Print version information and exit.

**Example:**

```bash
sesame --version
```

**Output:**

```text
sesame X.Y.Z
```

## Common Usage Patterns

### Setup as Alt+Space Launcher

```bash
# Configure keybinding
sesame --setup-keybinding alt+space

# COSMIC will run: sesame --launcher
```

### Setup as Alt+Tab Replacement

Manually configure COSMIC shortcuts:

1. Open COSMIC Settings → Keyboard → Custom Shortcuts
2. Add:
   - **Alt+Tab** → `sesame`
   - **Alt+Shift+Tab** → `sesame --backward`

### Debug Window Detection

Find app IDs for configuration:

```bash
sesame --list-windows
```

Look for the app ID in the output and add it to your config:

```toml
[keys.x]
apps = ["your-app-id-here"]
launch = "command-to-launch"
```

### Test Custom Config

Use a different configuration file temporarily:

```bash
sesame -c ~/test-config.toml --list-windows
```

### Validate Before Deployment

Always validate configuration after editing:

```bash
# Edit config
$EDITOR ~/.config/open-sesame/config.toml

# Validate
sesame --validate-config

# If valid, test it
sesame --launcher
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (configuration, runtime, etc.) |

## Environment Variables

### RUST_LOG

Enable debug logging:

```bash
RUST_LOG=debug sesame --launcher
```

**Log levels:**

- `error` - Errors only
- `warn` - Warnings and errors
- `info` - Informational messages
- `debug` - Detailed debug output
- `trace` - Very verbose tracing

**Log file location:**

```text
~/.cache/open-sesame/debug.log
```

**Example:**

```bash
# Enable debug logging
RUST_LOG=debug sesame --launcher

# View debug log
tail -f ~/.cache/open-sesame/debug.log
```

### XDG_CONFIG_HOME

Override default config directory:

```bash
XDG_CONFIG_HOME=~/my-configs sesame --launcher
```

**Default:** `~/.config`

**Config location:** `$XDG_CONFIG_HOME/open-sesame/config.toml`

### XDG_CACHE_HOME

Override cache directory (for logs and MRU state):

```bash
XDG_CACHE_HOME=~/my-cache sesame --launcher
```

**Default:** `~/.cache`

**Cache files:**

- `$XDG_CACHE_HOME/open-sesame/debug.log` - Debug log (when RUST_LOG is set)
- `$XDG_CACHE_HOME/open-sesame/mru.json` - MRU (Most Recently Used) state

## Examples

### Quick Setup

```bash
# Install and configure in 30 seconds
sudo apt install open-sesame
sesame --setup-keybinding
```

### Custom Configuration

```bash
# Generate starter config
sesame --print-config > ~/.config/open-sesame/config.toml

# Edit config
$EDITOR ~/.config/open-sesame/config.toml

# Validate config
sesame --validate-config

# Test it
sesame --launcher
```

### Debugging

```bash
# List windows and hints
sesame --list-windows

# Check keybinding status
sesame --keybinding-status

# Run with debug logging
RUST_LOG=debug sesame --launcher

# View debug log
tail -f ~/.cache/open-sesame/debug.log
```

### Multiple Configurations

```bash
# Work configuration
sesame -c ~/.config/open-sesame/work.toml --launcher

# Personal configuration
sesame -c ~/.config/open-sesame/personal.toml --launcher

# Test configuration
sesame -c ~/test.toml --list-windows
```

## Integration with COSMIC

Open Sesame integrates with COSMIC desktop through:

1. **Keybinding setup** - `--setup-keybinding` configures COSMIC shortcuts
2. **Wayland protocols** - Uses COSMIC-specific Wayland extensions
3. **Theme integration** - Respects COSMIC theme settings (future feature)

**Manual COSMIC setup:**

1. Open COSMIC Settings
2. Navigate to Keyboard → Custom Shortcuts
3. Add custom shortcuts:
   - Name: "Open Sesame Launcher"
   - Command: `sesame --launcher`
   - Keybinding: `Alt+Space`

## Troubleshooting Commands

### Configuration Issues

```bash
# Validate config
sesame --validate-config

# Print default config for reference
sesame --print-config

# Test with minimal config
echo '[settings]' > /tmp/minimal.toml
sesame -c /tmp/minimal.toml --list-windows
```

### Window Detection Issues

```bash
# List all windows with details
sesame --list-windows

# Run with debug logging
RUST_LOG=debug sesame --list-windows 2>&1 | grep -i "window"
```

### Keybinding Issues

```bash
# Check status
sesame --keybinding-status

# Remove and re-add
sesame --remove-keybinding
sesame --setup-keybinding

# Verify COSMIC shortcuts
# Open COSMIC Settings → Keyboard → View Shortcuts
```

## See Also

- [Configuration Guide](./configuration.md) - Detailed configuration reference
- [Troubleshooting](./troubleshooting.md) - Common issues and solutions
- [Basic Usage](./basic-usage.md) - How to use Open Sesame

## Man Page

After installation, view the manual page:

```bash
man sesame
```

The man page provides offline access to this reference documentation.
