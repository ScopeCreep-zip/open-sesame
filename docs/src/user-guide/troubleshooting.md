# Troubleshooting

Common issues and solutions for Open Sesame.

## No Windows Appear

**Problem:** The overlay shows "No windows found" or no windows are listed.

### Solution 1: Check Window Detection

```bash
sesame --list-windows
```

If no windows appear, ensure you're running on COSMIC desktop with Wayland (not X11).

**Verify COSMIC desktop:**

```bash
echo $XDG_CURRENT_DESKTOP
# Should output: COSMIC
```

**Verify Wayland:**

```bash
echo $WAYLAND_DISPLAY
# Should output: wayland-0 (or similar)
```

### Solution 2: Restart COSMIC Session

Sometimes the Wayland compositor needs a restart:

1. Log out of COSMIC
2. Log back in
3. Try again

### Solution 3: Check Debug Logs

Enable debug logging to see what's happening:

```bash
RUST_LOG=debug sesame --list-windows 2>&1 | grep -i "window"
```

Look for error messages about window enumeration.

## Wrong App IDs

**Problem:** App is not getting the correct hint letter.

### Solution: Find Correct App ID

Use `--list-windows` to find the exact app ID:

```bash
sesame --list-windows
```

**Output:**

```text
=== Window Enumeration ===
  [0] wayland-1 - org.mozilla.firefox - Mozilla Firefox
  [1] wayland-2 - code - Visual Studio Code
```

Copy the exact app ID (middle column) and use it in your configuration:

```toml
[keys.f]
apps = ["org.mozilla.firefox"]  # Use exact app ID
launch = "firefox"
```

### Common App ID Variations

Different apps may use different ID formats:

| App | Possible IDs |
|-----|-------------|
| Firefox | `firefox`, `org.mozilla.firefox`, `Firefox` |
| VS Code | `code`, `Code`, `visual-studio-code` |
| Ghostty | `ghostty`, `com.mitchellh.ghostty` |
| Chrome | `google-chrome`, `chromium`, `Google-chrome` |

Open Sesame matches all variations automatically (case-insensitive, last segment).

## Keybinding Not Working

**Problem:** Pressing Alt+Space (or configured key) doesn't launch Open Sesame.

### Solution 1: Check Keybinding Status

```bash
sesame --keybinding-status
```

Expected output:

```text
Keybinding configured: alt+space → sesame --launcher
```

### Solution 2: Re-setup Keybinding

Remove and re-add the keybinding:

```bash
sesame --remove-keybinding
sesame --setup-keybinding
```

### Solution 3: Check for Conflicts

Ensure the key combo doesn't conflict with other COSMIC shortcuts:

1. Open COSMIC Settings
2. Navigate to Keyboard → View Shortcuts
3. Search for the key combination
4. Remove any conflicting shortcuts

### Solution 4: Manual Setup

If `--setup-keybinding` doesn't work, configure manually:

1. Open COSMIC Settings
2. Navigate to Keyboard → Custom Shortcuts
3. Add:
   - Name: "Open Sesame"
   - Command: `sesame --launcher`
   - Keybinding: Press your desired key combo

### Solution 5: Verify Binary Path

Check that `sesame` is in your PATH:

```bash
which sesame
# Should output: /usr/bin/sesame
```

If not found:

```bash
# Install/reinstall package
sudo apt install --reinstall open-sesame
```

## Configuration Errors

**Problem:** Open Sesame reports configuration errors or doesn't behave as expected.

### Solution 1: Validate Configuration

```bash
sesame --validate-config
```

**Common errors:**

#### Invalid Color Format

```text
[ERROR] Invalid color format: "#xyz"
```

**Fix:** Use proper hex format:

```toml
border_color = "#ff0000"      # RGB
border_color = "#ff0000aa"    # RGBA
```

#### Missing Quotes

```text
[ERROR] TOML parse error: invalid string
```

**Fix:** Quote strings with spaces:

```toml
# Wrong:
launch = firefox --new-window

# Correct:
launch = "firefox --new-window"
```

#### Duplicate Key Bindings

```text
[WARNING] Duplicate key binding: 'g'
```

**Fix:** Each letter can only be used once. Remove or change duplicate:

```toml
# Only one [keys.g] section allowed
[keys.g]
apps = ["ghostty"]
```

### Solution 2: Start with Default Config

```bash
# Backup current config
mv ~/.config/open-sesame/config.toml ~/.config/open-sesame/config.toml.backup

# Generate default config
sesame --print-config > ~/.config/open-sesame/config.toml

# Test
sesame --launcher
```

### Solution 3: Test with Minimal Config

Create a minimal configuration to isolate the issue:

```bash
# Create minimal config
cat > /tmp/minimal.toml << 'EOF'
[settings]
activation_delay = 200
EOF

# Test with minimal config
sesame -c /tmp/minimal.toml --list-windows
```

If this works, gradually add back your customizations until you find the problem.

## Launch Commands Not Working

**Problem:** Pressing a letter doesn't launch the app when it's not running.

### Solution 1: Verify App is in PATH

```bash
# Test launch command directly
which firefox
firefox
```

If the command doesn't exist:

- Install the application
- Use the full path in configuration

### Solution 2: Use Full Path

```toml
[keys.f]
apps = ["firefox"]
[keys.f.launch]
command = "/usr/bin/firefox"  # Use absolute path
```

### Solution 3: Check Debug Logs

```bash
RUST_LOG=debug sesame --launcher
```

Look for launch errors:

```text
ERROR Failed to launch: No such file or directory
```

### Solution 4: Test Launch Command

Test the launch command manually:

```bash
# Verify command syntax
/bin/sh -c "firefox"
```

If it works manually but not from Open Sesame, check:

- Environment variables (PATH, etc.)
- Shell escaping issues
- Permissions

### Solution 5: Use Simple Launch First

Start with a simple string launch:

```toml
# Simple
[keys.f]
apps = ["firefox"]
launch = "firefox"

# Not this (yet):
[keys.f.launch]
command = "firefox"
args = ["--new-window"]
```

Once simple launch works, add complexity.

## Performance Issues

**Problem:** Overlay feels slow or laggy.

### Solution 1: Reduce Delays

```toml
[settings]
overlay_delay = 0           # Show immediately
activation_delay = 100      # Faster activation
```

### Solution 2: Check System Resources

```bash
# Check CPU usage
top

# Check memory
free -h
```

Open Sesame is lightweight, but performance issues may indicate system-wide problems.

### Solution 3: Verify Wayland Compositor

Ensure COSMIC compositor is running properly:

```bash
# Restart COSMIC session
# Log out and log back in
```

### Solution 4: Reduce Window Count

Fewer open windows = faster hint assignment:

```bash
# Check window count
sesame --list-windows | grep "Found"
# Output: Found 23 windows
```

If you have many windows, consider closing unused ones.

## Quick Switch Not Working

**Problem:** Tapping Alt+Space doesn't switch to the previous window.

### Solution 1: Check Quick Switch Threshold

You may be holding the key too long:

```toml
[settings]
quick_switch_threshold = 250  # Default: 250ms
```

Try increasing the threshold:

```toml
[settings]
quick_switch_threshold = 400  # More forgiving
```

### Solution 2: Verify Switcher Mode

Quick switch only works in switcher mode (NOT launcher mode):

```bash
# This works for quick switch:
sesame

# This doesn't (always shows overlay):
sesame --launcher
```

Check your keybinding:

```bash
sesame --keybinding-status
```

### Solution 3: Check MRU State

The MRU (Most Recently Used) state may be corrupted:

```bash
# View MRU state
sesame --list-windows | grep -A 2 "MRU State"

# Reset MRU state
rm ~/.cache/open-sesame/mru.json

# Try again
sesame
```

## Hints Not Appearing

**Problem:** Windows appear in the overlay but no letter hints are shown.

### Solution 1: Check Font Installation

Open Sesame requires fontconfig:

```bash
# Check fontconfig
fc-list | head

# If empty, install fonts
sudo apt install fonts-dejavu-core
```

### Solution 2: Check Debug Logs

```bash
RUST_LOG=debug sesame --launcher 2>&1 | grep -i "font"
```

Look for font loading errors.

### Solution 3: Verify Rendering

This is likely a rendering issue. Check:

```bash
# Verify Wayland display
echo $WAYLAND_DISPLAY

# Check for rendering errors
RUST_LOG=debug sesame --launcher 2>&1 | grep -i "render"
```

## App Launches But Doesn't Focus

**Problem:** Pressing a letter launches the app, but doesn't switch focus to it.

### Solution 1: Add Window Activation Delay

Some apps take time to create windows:

```bash
# Launch app
sesame --launcher  # Press 'f' for Firefox

# Wait a moment, then run again
sesame --launcher  # Should now show Firefox and focus it
```

This is a known limitation - Open Sesame can't focus a window that doesn't exist yet.

### Solution 2: Use Window Focus After Launch

After launching, manually activate Open Sesame again to focus the new window:

1. Press Alt+Space, type 'f' → launches Firefox
2. Wait 2 seconds for Firefox to start
3. Press Alt+Space, type 'f' → focuses Firefox

### Solution 3: Use Startup Notification

Some applications support startup notification. This is a future feature.

## Border Not Showing

**Problem:** No border appears around windows during quick switch.

### Solution 1: Check Border Settings

```toml
[settings]
border_width = 3.0          # Must be > 0
border_color = "#b4a0ffb4"  # Must have some opacity
```

### Solution 2: Increase Border Width

Make the border more visible:

```toml
[settings]
border_width = 5.0
border_color = "#ff0000ff"  # Bright red for testing
```

### Solution 3: Check Overlay Delay

If `overlay_delay = 0`, the border phase is skipped:

```toml
[settings]
overlay_delay = 720  # Allow border to show
```

## Environment Variables Not Loading

**Problem:** Environment variables in `env_files` aren't being set.

### Solution 1: Check File Exists

```bash
# Verify env file exists
cat ~/.config/open-sesame/global.env
```

### Solution 2: Check File Format

Environment files must use correct syntax:

```bash
# Correct:
KEY=value
KEY="value with spaces"
export KEY=value

# Incorrect:
KEY = value        # No spaces around =
KEY: value         # Not YAML
```

### Solution 3: Check Path Expansion

Paths must use `~/` for home directory:

```toml
# Correct:
env_files = ["~/.config/open-sesame/global.env"]

# Incorrect:
env_files = ["$HOME/.config/open-sesame/global.env"]  # $HOME not expanded
```

### Solution 4: Check Debug Logs

```bash
RUST_LOG=debug sesame --launcher 2>&1 | grep -i "env"
```

Look for:

```text
DEBUG Loading env file: /home/user/.config/open-sesame/global.env
```

## Wayland-Specific Issues

**Problem:** Open Sesame doesn't work or crashes on startup.

### Verify Wayland Session

```bash
# Check session type
echo $XDG_SESSION_TYPE
# Should output: wayland

# Check Wayland display
echo $WAYLAND_DISPLAY
# Should output: wayland-0 (or similar)
```

### X11 Not Supported

If you're on X11:

```bash
echo $XDG_SESSION_TYPE
# Output: x11
```

**Solution:** Log out and select a Wayland session at login, or switch to COSMIC desktop.

## Still Having Issues?

### Enable Full Debug Logging

```bash
# Run with maximum logging
RUST_LOG=trace sesame --launcher 2>&1 | tee sesame-debug.log

# Review the log
less sesame-debug.log
```

### Check System Logs

```bash
# Check system journal
journalctl --user -xe | grep -i sesame

# Check for COSMIC errors
journalctl --user -xe | grep -i cosmic
```

### Report an Issue

If none of these solutions work:

1. Gather information:

   ```bash
   # System info
   uname -a
   echo $XDG_CURRENT_DESKTOP
   echo $XDG_SESSION_TYPE

   # Open Sesame version
   sesame --version

   # Window list
   sesame --list-windows

   # Config validation
   sesame --validate-config

   # Debug log
   RUST_LOG=debug sesame --launcher 2>&1 > sesame-debug.log
   ```

2. Open an issue on GitHub: [https://github.com/ScopeCreep-zip/open-sesame/issues](https://github.com/ScopeCreep-zip/open-sesame/issues)

3. Include:
   - System information
   - Open Sesame version
   - Configuration file (redact any secrets)
   - Debug log
   - Steps to reproduce

## See Also

- [Configuration Guide](./configuration.md) - Detailed configuration reference
- [CLI Reference](./cli-reference.md) - Command-line options
- [Basic Usage](./basic-usage.md) - How to use Open Sesame
