//! Keyboard capture via evdev.
//!
//! Provides:
//! - `DeviceInfo`: metadata about an evdev input device.
//! - `enumerate_devices()`: discover keyboard and pointer devices under `/dev/input/`.
//! - `open_keyboard_stream()`: open an evdev device as an async `EventStream` for
//!   tokio-native keyboard event reading.
//!
//! Requires `input` group membership (never root). Nothing is injected:
//! there is no uinput device.

use evdev::{Device, EventStream, KeyCode};
use std::path::{Path, PathBuf};

/// Discovered evdev device metadata.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: PathBuf,
    pub name: String,
    pub is_keyboard: bool,
    pub is_pointer: bool,
}

/// The evdev devices under `/dev/input/` this process can open.
///
/// Uses the evdev crate's `enumerate()`, which reads `/dev/input/event*`
/// and skips devices that fail to open (EACCES, etc.): a process outside
/// the `input` group sees none.
///
/// A device is classified as a keyboard if it supports `KEY_A`, `KEY_Z`, and
/// `KEY_ENTER`. This heuristic excludes power buttons, media controllers, and
/// other devices that report KEY events but are not full keyboards.
#[must_use]
pub fn enumerate_devices() -> Vec<DeviceInfo> {
    evdev::enumerate()
        .map(|(path, device)| {
            let keys = device.supported_keys();
            DeviceInfo {
                name: device.name().unwrap_or("Unknown").to_owned(),
                is_keyboard: keys.is_some_and(|keys| {
                    keys.contains(KeyCode::KEY_A)
                        && keys.contains(KeyCode::KEY_Z)
                        && keys.contains(KeyCode::KEY_ENTER)
                }),
                is_pointer: keys.is_some_and(|keys| keys.contains(KeyCode::BTN_LEFT)),
                path,
            }
        })
        .collect()
}

/// Open an evdev device as an async `EventStream` for tokio-native reading.
///
/// The returned `EventStream` uses `AsyncFd<Device>` internally — fully
/// async, no `spawn_blocking` needed. Call `stream.next_event().await` to
/// read events.
///
/// Does NOT grab the device (EVIOCGRAB). Events are read passively — they
/// also reach the compositor. This is intentional: we observe and forward
/// copies, not steal events.
///
/// # Errors
///
/// Returns an error if the device cannot be opened or the async fd setup fails.
pub fn open_keyboard_stream(path: &Path) -> core_types::Result<EventStream> {
    let device = Device::open(path).map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to open evdev device {}: {e}",
            path.display()
        ))
    })?;

    device.into_event_stream().map_err(|e| {
        core_types::Error::Platform(format!(
            "failed to create event stream for {}: {e}",
            path.display()
        ))
    })
}
