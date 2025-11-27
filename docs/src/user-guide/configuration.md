# Configuration

Open Sesame uses TOML configuration files with XDG-compliant directory structure and layered inheritance.

## Configuration Files

Open Sesame loads configuration from multiple locations in order (later overrides earlier):

```text
/etc/open-sesame/config.toml              # System defaults
~/.config/open-sesame/config.toml         # User config (create this)
~/.config/open-sesame/config.d/*.toml     # Additional overrides (alphabetical)
```

### Generating Default Configuration

To get started with configuration:

```bash
# Print default config to stdout
sesame --print-config

# Create user config from defaults
sesame --print-config > ~/.config/open-sesame/config.toml

# Edit config
$EDITOR ~/.config/open-sesame/config.toml

# Validate config
sesame --validate-config
```

### Using a Custom Config File

You can specify a custom configuration file:

```bash
sesame -c ~/my-custom-config.toml --list-windows
```

## Settings Reference

The `[settings]` section controls global behavior:

```toml
[settings]
# Activation key combo (used by --setup-keybinding)
activation_key = "alt+space"

# Delay (ms) before activating a match when multiple hints exist
# Allows time for typing gg, ggg without 'g' firing immediately
activation_delay = 200

# Delay (ms) before showing full overlay (0 = immediate)
# During this time, only a border shows around focused window
overlay_delay = 720

# Quick switch threshold (ms) - tap within this time = instant MRU switch
quick_switch_threshold = 250

# Focus indicator border
border_width = 3.0
border_color = "#b4a0ffb4"  # Soft lavender with transparency

# Overlay colors (hex: #RRGGBB or #RRGGBBAA)
background_color = "#000000c8"  # Semi-transparent black
card_color = "#1e1e1ef0"        # Dark gray card
text_color = "#ffffffff"        # White text
hint_color = "#646464ff"        # Gray hint badge
hint_matched_color = "#4caf50ff" # Green for matched hints

# Global environment files (direnv .env style)
env_files = [
    # "~/.config/open-sesame/global.env"
]
```

### Settings Explained

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `activation_key` | string | `"alt+space"` | Default key combo for `--setup-keybinding` |
| `activation_delay` | integer | `200` | Delay (ms) before activating a match with multiple hints |
| `overlay_delay` | integer | `720` | Delay (ms) before showing full overlay in switcher mode |
| `quick_switch_threshold` | integer | `250` | Tap threshold (ms) for instant MRU switch |
| `border_width` | float | `3.0` | Border width (pixels) for focus indicator |
| `border_color` | color | `#b4a0ffb4` | Border color (hex with alpha) |
| `background_color` | color | `#000000c8` | Overlay background color |
| `card_color` | color | `#1e1e1ef0` | Window card background color |
| `text_color` | color | `#ffffffff` | Text color |
| `hint_color` | color | `#646464ff` | Hint badge color |
| `hint_matched_color` | color | `#4caf50ff` | Matched hint color |
| `env_files` | array | `[]` | Global environment files to load |

### Color Format

Colors are specified in hex format:

- `#RRGGBB` - RGB only (alpha defaults to 255 - fully opaque)
- `#RRGGBBAA` - RGB with alpha channel (00 = transparent, FF = opaque)

Examples:

```toml
border_color = "#ff0000"      # Red, fully opaque
border_color = "#ff0000aa"    # Red, semi-transparent
background_color = "#000000c8" # Black, 78% opaque
```

## Key Bindings

The `[keys.<letter>]` sections define per-app shortcuts for focus-or-launch functionality.

### Basic Key Binding

Each key binding section has:

- `apps` - List of app IDs that match this key
- `launch` - Command to run if no matching window exists

```toml
# Terminal
[keys.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"

# Browser
[keys.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"

# Editor
[keys.v]
apps = ["code", "Code", "cursor", "Cursor"]
launch = "code"

# File manager
[keys.n]
apps = ["nautilus", "org.gnome.Nautilus", "com.system76.CosmicFiles"]
launch = "nautilus"
```

### Focus-Only Binding

Omit the `launch` field to create a focus-only binding (won't launch if not running):

```toml
# Chromium - focus only, don't launch
[keys.c]
apps = ["chromium", "google-chrome"]
# No launch field
```

### Finding App IDs

To find the app ID for a window:

```bash
sesame --list-windows
```

Output example:

```text
=== Window Enumeration ===
Found 3 windows:
  [0] wayland-1 - firefox - Mozilla Firefox
  [1] wayland-2 - code - Visual Studio Code
  [2] wayland-3 - ghostty - Terminal
```

Use the app ID (second column) in your configuration.

### App ID Matching

Open Sesame matches app IDs flexibly:

1. **Exact match:** `"firefox"` matches app ID `"firefox"`
2. **Case-insensitive:** `"Firefox"` matches app ID `"firefox"`
3. **Last segment:** `"ghostty"` matches `"com.mitchellh.ghostty"`

This means you can use simple names instead of full reverse-domain IDs.

## Advanced Launch Configuration

For complex scenarios with command-line arguments and environment variables:

### Simple Launch

```toml
[keys.g]
apps = ["ghostty"]
launch = "ghostty"  # Just a command string
```

### Advanced Launch

```toml
[keys.g]
apps = ["ghostty"]
[keys.g.launch]
command = "ghostty"
args = ["--config-file=/path/to/config"]
env_files = ["~/.config/ghostty/.env"]  # Load env vars from file
env = { TERM = "xterm-256color" }       # Explicit env vars (override env_files)
```

### More Examples

**Chrome with specific profile:**

```toml
[keys.w]
apps = ["google-chrome"]
[keys.w.launch]
command = "google-chrome"
args = ["--profile-directory=Work"]
```

**App with custom environment:**

```toml
[keys.x]
apps = ["myapp"]
[keys.x.launch]
command = "/opt/myapp/bin/myapp"
args = ["--mode=production"]
env_files = [
    "~/.config/myapp/base.env",
    "~/.config/myapp/secrets.env",
]
env = { DEBUG = "false" }
```

## Environment Variables

### Environment Layering

Environment variables are applied in layers (later overrides earlier):

1. **Inherited process environment** (WAYLAND_DISPLAY, XDG_*, PATH, etc.)
2. **Global `env_files`** from `[settings]`
3. **Per-app `env_files`** from `[keys.x.launch]`
4. **Explicit `env`** from `[keys.x.launch]`

### Environment File Format

Environment files use direnv `.env` style syntax:

```bash
# ~/.config/open-sesame/global.env
KEY=value
KEY="value with spaces"
KEY='literal value'
export KEY=value
# comments
```

**Supported formats:**

- `KEY=value` - Simple assignment
- `KEY="value"` - Double-quoted (allows spaces)
- `KEY='value'` - Single-quoted (literal, no interpolation)
- `export KEY=value` - Export style (same as `KEY=value`)
- `# comment` - Comments

**Path expansion:**

- `~/` expands to home directory
- Environment variables in values are NOT expanded

### Global Environment Files

To load environment variables for all launched apps:

```toml
[settings]
env_files = [
    "~/.config/open-sesame/global.env",
    "/etc/open-sesame/env.d/system.env",
]
```

## Adding New Key Bindings

Step-by-step process:

1. **Find your app ID:**

   ```bash
   sesame --list-windows
   ```

2. **Add configuration section:**

   ```toml
   [keys.x]
   apps = ["your-app-id"]
   launch = "your-app-command"
   ```

3. **Verify configuration:**

   ```bash
   sesame --validate-config
   ```

4. **Test it:**

   ```bash
   # Press Alt+Space, type 'x'
   ```

## Configuration Validation

Always validate your configuration after making changes:

```bash
sesame --validate-config
```

Output if valid:

```text
Configuration is valid
```

Output if invalid:

```text
Configuration issues:
  - [ERROR] Invalid color format: "#xyz"
  - [WARNING] Key binding 'f' has no apps configured
```

**Severity levels:**

- **ERROR** - Critical issues that will prevent Open Sesame from working
- **WARNING** - Non-critical issues that may cause unexpected behavior

## Example Configuration

Complete example configuration file:

```toml
[settings]
activation_key = "alt+space"
activation_delay = 200
overlay_delay = 720
quick_switch_threshold = 250
border_width = 3.0
border_color = "#b4a0ffb4"
background_color = "#000000c8"
card_color = "#1e1e1ef0"
text_color = "#ffffffff"
hint_color = "#646464ff"
hint_matched_color = "#4caf50ff"

# Terminal
[keys.g]
apps = ["ghostty", "com.mitchellh.ghostty"]
launch = "ghostty"

# Browser
[keys.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"

# Editor
[keys.v]
apps = ["code", "Code", "cursor", "Cursor"]
launch = "code"

# File manager
[keys.n]
apps = ["nautilus", "org.gnome.Nautilus", "com.system76.CosmicFiles"]
launch = "nautilus"

# Communication
[keys.s]
apps = ["slack", "Slack"]
launch = "slack"

[keys.d]
apps = ["discord", "Discord"]
launch = "discord"
```

## Configuration Tips

### Performance Tuning

For faster response times:

```toml
[settings]
activation_delay = 100      # Faster activation (may skip gg, ggg)
overlay_delay = 0           # Show immediately (launcher mode)
quick_switch_threshold = 150  # Faster tap threshold
```

### Minimal UI

For minimal visual distraction:

```toml
[settings]
overlay_delay = 1000        # Longer delay before overlay
border_width = 2.0          # Thinner border
background_color = "#00000080"  # More transparent background
```

### Theme Customization

Match your desktop theme:

```toml
[settings]
# Cosmic purple theme
border_color = "#a56de2ff"
card_color = "#2a2a2eff"
hint_matched_color = "#a56de2ff"
```

## Configuration Directory Structure

Recommended structure for complex setups:

```text
~/.config/open-sesame/
├── config.toml                 # Main configuration
├── config.d/
│   ├── 10-theme.toml          # Theme overrides
│   ├── 20-work.toml           # Work-specific apps
│   └── 30-personal.toml       # Personal apps
├── env.d/
│   ├── global.env             # Global environment
│   └── work.env               # Work environment
└── scripts/
    └── custom-launcher.sh     # Custom launch scripts
```

Files in `config.d/` are loaded in alphabetical order, allowing modular configuration.

## Next Steps

- [CLI Reference](./cli-reference.md) - Explore all command-line options
- [Troubleshooting](./troubleshooting.md) - Fix configuration issues
- [Developer Guide](../developer-guide/architecture.md) - Understand the configuration system internals
