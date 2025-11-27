# Quick Start

Get Open Sesame running in 30 seconds.

## Installation (Pop!_OS 24.04+)

```bash
# Add repository
curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | \
  sudo gpg --dearmor -o /etc/apt/keyrings/open-sesame.gpg

echo "deb [signed-by=/etc/apt/keyrings/open-sesame.gpg] \
  https://scopecreep-zip.github.io/open-sesame noble main" | \
  sudo tee /etc/apt/sources.list.d/open-sesame.list

# Install
sudo apt update && sudo apt install open-sesame

# Setup keybinding
sesame --setup-keybinding
```

## First Launch

Press **Alt+Space** (or your configured key) to see all windows with letter hints.

Type a letter to switch to that window instantly.

## Quick Tips

- **Tap Alt+Space** - Instantly switch to the previous window (MRU - Most Recently Used)
- **Hold Alt+Space** - Show the full overlay with all windows
- **Type a letter** - Jump directly to that window
- **Use arrow keys** - Navigate through windows if you prefer
- **Press Escape** - Cancel and return to the origin window

## Next Steps

- Learn about [Basic Usage](./basic-usage.md) and keyboard shortcuts
- Configure [Key Bindings](./configuration.md#key-bindings) for your favorite apps
- Read the full [CLI Reference](./cli-reference.md)
- Troubleshoot any issues in [Troubleshooting](./troubleshooting.md)

## What Makes Open Sesame Different?

Unlike traditional Alt+Tab switchers, Open Sesame:

- Shows ALL windows at once, not just sequential cycling
- Assigns predictable letter hints based on app names
- Allows instant switching with a single keystroke
- Supports focus-or-launch: if an app isn't running, it launches it
- Works with both keyboard shortcuts (letters) and arrow navigation
