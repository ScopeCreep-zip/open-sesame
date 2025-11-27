# Basic Usage

Learn how to use Open Sesame for efficient window management.

## Launching Open Sesame

After setting up a keybinding, simply press your configured key (default: `Alt+Space`):

```bash
# The keybinding triggers this command
sesame --launcher
```

You can also run Open Sesame manually:

```bash
# Show window switcher
sesame

# Launcher mode (immediate overlay)
sesame --launcher

# List all windows with hints
sesame --list-windows

# Backward cycling (for Alt+Shift+Tab)
sesame --backward
```

## Keyboard Shortcuts

Once the overlay appears, you have several ways to interact:

| Key | Action |
|-----|--------|
| **Letter keys** (a-z) | Instantly switch to window with that hint |
| **Repeated letters** (gg, ggg) | Select multiple windows with same letter |
| **Arrow keys** (↑↓) | Navigate through window list |
| **Enter** | Activate currently selected window |
| **Escape** | Cancel and return to origin window |

## Two Modes Explained

Open Sesame has two distinct operating modes:

### Launcher Mode (`--launcher` flag)

**Best for:** Alt+Space style launchers

**Behavior:**

- Shows the full overlay immediately
- Displays all windows with letter hints from the start
- No delay before showing the UI
- Used for quick access to any window

**Setup:**

```bash
# Configure Alt+Space to use launcher mode
sesame --setup-keybinding alt+space

# COSMIC will run: sesame --launcher
```

### Switcher Mode (default)

**Best for:** Alt+Tab replacement

**Behavior:**

- Quick tap (< 250ms): Instantly switch to the previous window (MRU)
- Hold longer: Shows overlay after a delay (default: 720ms)
- During the delay, a subtle border highlights the target window
- Designed to mimic traditional Alt+Tab behavior

**Setup:**

```bash
# Manually configure COSMIC shortcuts:
# Alt+Tab → sesame
# Alt+Shift+Tab → sesame --backward
```

## Quick Switch Behavior

The "quick switch" feature allows you to toggle between windows with a quick tap:

**Tap Alt+Space** (release within 250ms):

- Instantly switches to the previous window
- No overlay shown
- Perfect for bouncing between two windows

**Hold Alt+Space** (hold longer than 250ms):

- Shows the full overlay after a delay
- Allows you to select any window

> **Note:** The quick switch threshold can be configured in your config file with the `quick_switch_threshold`
> setting (default: 250ms).

## Focus-or-Launch

One of Open Sesame's most powerful features is focus-or-launch functionality. When you've configured a key binding
for an application:

**If the app is running:** Open Sesame focuses the window
**If the app is NOT running:** Open Sesame launches it

### Example

Configure Firefox with the `f` key:

```toml
# In ~/.config/open-sesame/config.toml
[keys.f]
apps = ["firefox", "org.mozilla.firefox"]
launch = "firefox"
```

Now:

- Press `Alt+Space`, then `f` → switches to Firefox if it's open
- Press `Alt+Space`, then `f` → launches Firefox if it's not running

This eliminates the need for separate application launchers.

## Hint Assignment

Open Sesame assigns letter hints to windows intelligently:

1. **Configured apps** get their configured key (e.g., Firefox gets `f`)
2. **Multiple windows** of the same app get repeated letters:
   - First instance: `g`
   - Second instance: `gg`
   - Third instance: `ggg`
3. **Unconfigured apps** get sequential letters (a-z, excluding used keys)

### Alternative Input

You can also type hints with numbers:

- `g1` is equivalent to `g`
- `g2` is equivalent to `gg`
- `g3` is equivalent to `ggg`

## Using Arrow Navigation

If you prefer not to type letters, arrow keys work too:

1. Press `Alt+Space` to show the overlay
2. Use `↑` and `↓` to navigate through windows
3. Press `Enter` to activate the selected window
4. Or press `Escape` to cancel

The selected window is highlighted in the overlay.

## Activation Delay

When multiple windows share the same hint prefix (e.g., `g`, `gg`, `ggg`), Open Sesame waits a short time before activating:

**Default delay:** 200ms

This gives you time to type the full hint without the first letter firing immediately.

**To skip the delay:** Press `Enter` after typing the hint

You can configure this delay in your config file:

```toml
[settings]
activation_delay = 200  # milliseconds
```

## Overlay Delay

In switcher mode, there's a delay before the full overlay appears:

**Default delay:** 720ms

During this time, only a subtle border is shown around the target window. This keeps the UI minimal for quick switches.

**To show the overlay immediately:** Set `overlay_delay = 0` in your config, or use `--launcher` flag

```toml
[settings]
overlay_delay = 0  # Show immediately (launcher mode behavior)
```

## Common Workflows

### Quick Toggle Between Two Apps

Press `Alt+Space` quickly (tap and release):

- Switches to the previous window instantly
- No overlay shown
- Works like traditional Alt+Tab quick toggle

### Jump to Specific App

1. Press `Alt+Space` (hold until overlay appears)
2. Type the letter hint for your app (e.g., `f` for Firefox)
3. Window activates immediately

### Launch an App That's Not Running

1. Press `Alt+Space`
2. Type the configured letter (e.g., `g` for Ghostty)
3. If Ghostty isn't running, it launches automatically

### Browse All Windows

1. Press `Alt+Space` (hold until overlay appears)
2. Use arrow keys to scroll through windows
3. Press `Enter` to activate the selected one

## Tips and Tricks

### Speed Over Accuracy

Open Sesame is designed for speed. Don't wait for the overlay—start typing immediately:

1. Press `Alt+Space` and immediately type `f` → switches to Firefox
2. The overlay may not even appear if you're fast enough

### Consistent Key Bindings

Configure your most-used apps with memorable keys:

- `f` for Firefox (web browser)
- `g` for Ghostty (terminal)
- `v` for VS Code (editor)
- `n` for Nautilus (file manager)

### Customize Delays

If the default delays feel too slow or too fast, adjust them:

```toml
[settings]
activation_delay = 100      # Faster activation (may skip gg, ggg)
overlay_delay = 0           # Show overlay immediately
quick_switch_threshold = 150  # Faster tap threshold
```

## Next Steps

- [Configuration](./configuration.md) - Set up key bindings and customize behavior
- [CLI Reference](./cli-reference.md) - Explore all command-line options
- [Troubleshooting](./troubleshooting.md) - Fix common issues
