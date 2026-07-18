//! Keyboard and seat handler implementations for the overlay.

use smithay_client_toolkit::{
    delegate_keyboard, delegate_seat,
    seat::{
        Capability, SeatHandler, SeatState,
        keyboard::{KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers},
    },
};
use wayland_client::{
    Connection, QueueHandle,
    protocol::{wl_keyboard, wl_seat, wl_surface},
};

use super::OverlayEvent;
use super::app::OverlayApp;

impl SeatHandler for OverlayApp {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }

    fn new_seat(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _seat: wl_seat::WlSeat) {}

    fn new_capability(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        seat: wl_seat::WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard {
            let _ = self.seat_state.get_keyboard(qh, &seat, None);
        }
    }

    fn remove_capability(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: wl_seat::WlSeat,
        _: Capability,
    ) {
    }
    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
}

impl KeyboardHandler for OverlayApp {
    fn enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
        _: &[u32],
        _: &[Keysym],
    ) {
        self.received_key_event = true;
        self.alt_held = true;
    }

    fn leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: &wl_surface::WlSurface,
        _: u32,
    ) {
    }

    fn press_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.received_key_event = true;
        let ev = match event.keysym {
            Keysym::Escape => Some(OverlayEvent::Escape),
            Keysym::Return | Keysym::KP_Enter => Some(OverlayEvent::Confirm),
            Keysym::Tab | Keysym::ISO_Left_Tab => None,
            Keysym::Down => Some(OverlayEvent::SelectionDown),
            Keysym::Up => Some(OverlayEvent::SelectionUp),
            Keysym::BackSpace => Some(OverlayEvent::Backspace),
            Keysym::space => Some(OverlayEvent::KeyChar(' ')),
            _ => event
                .utf8
                .as_ref()
                .and_then(|s| {
                    let mut chars = s.chars();
                    let c = chars.next()?;
                    if chars.next().is_none() && c.is_ascii_graphic() {
                        Some(c)
                    } else {
                        None
                    }
                })
                .map(OverlayEvent::KeyChar),
        };
        if let Some(ev) = ev {
            self.send_event(ev);
        }
    }

    fn release_key(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        event: KeyEvent,
    ) {
        self.received_key_event = true;
        if matches!(
            event.keysym,
            Keysym::Alt_L | Keysym::Alt_R | Keysym::Meta_L | Keysym::Meta_R
        ) {
            self.send_event(OverlayEvent::ModifierReleased);
        }
    }

    fn update_modifiers(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_keyboard::WlKeyboard,
        _: u32,
        modifiers: Modifiers,
        _: RawModifiers,
        _: u32,
    ) {
        self.alt_held = modifiers.alt;
    }

    fn repeat_key(
        &mut self,
        conn: &Connection,
        qh: &QueueHandle<Self>,
        keyboard: &wl_keyboard::WlKeyboard,
        serial: u32,
        event: KeyEvent,
    ) {
        self.press_key(conn, qh, keyboard, serial, event);
    }
}

delegate_seat!(OverlayApp);
delegate_keyboard!(OverlayApp);
