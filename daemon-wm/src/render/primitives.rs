//! tiny-skia drawing primitives: filled and stroked rounded rectangles.

use super::Color;
use super::layout::Rect;

/// The outline of `rect` with corners of `radius` (at most half its
/// shorter side); `None` for an empty or non-finite rectangle.
fn rounded_rect_path(rect: Rect, radius: f32) -> Option<tiny_skia::Path> {
    let Rect {
        x: left,
        y: top,
        width,
        height,
    } = rect;
    let (right, bottom) = (left + width, top + height);
    let radius = radius.min(width / 2.0).min(height / 2.0);
    let mut path = tiny_skia::PathBuilder::new();
    path.move_to(left + radius, top);
    path.line_to(right - radius, top);
    path.quad_to(right, top, right, top + radius);
    path.line_to(right, bottom - radius);
    path.quad_to(right, bottom, right - radius, bottom);
    path.line_to(left + radius, bottom);
    path.quad_to(left, bottom, left, bottom - radius);
    path.line_to(left, top + radius);
    path.quad_to(left, top, left + radius, top);
    path.close();
    path.finish()
}

/// An anti-aliased paint of `color`.
fn paint(color: Color) -> tiny_skia::Paint<'static> {
    let mut paint = tiny_skia::Paint::default();
    paint.set_color(color.to_tiny_skia());
    paint.anti_alias = true;
    paint
}

/// Fill `rect`, its corners rounded by `radius`, with `color`.
pub fn fill_rounded_rect(pixmap: &mut tiny_skia::Pixmap, rect: Rect, radius: f32, color: Color) {
    if let Some(path) = rounded_rect_path(rect, radius) {
        pixmap.fill_path(
            &path,
            &paint(color),
            tiny_skia::FillRule::Winding,
            tiny_skia::Transform::identity(),
            None,
        );
    }
}

/// Stroke the outline of `rect`, its corners rounded by `radius`, with
/// `color` at `width` pixels.
pub fn stroke_rounded_rect(
    pixmap: &mut tiny_skia::Pixmap,
    rect: Rect,
    radius: f32,
    color: Color,
    width: f32,
) {
    if let Some(path) = rounded_rect_path(rect, radius) {
        let stroke = tiny_skia::Stroke {
            width,
            line_cap: tiny_skia::LineCap::Round,
            line_join: tiny_skia::LineJoin::Round,
            ..Default::default()
        };
        pixmap.stroke_path(
            &path,
            &paint(color),
            &stroke,
            tiny_skia::Transform::identity(),
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQUARE: Rect = Rect {
        x: 2.0,
        y: 2.0,
        width: 6.0,
        height: 6.0,
    };

    #[test]
    fn fills_paint_inside_the_rect_only() {
        let mut pixmap = tiny_skia::Pixmap::new(10, 10).unwrap();
        fill_rounded_rect(&mut pixmap, SQUARE, 1.0, Color::rgb(255, 0, 0));
        assert_eq!(pixmap.pixel(5, 5).unwrap().red(), 255);
        assert_eq!(pixmap.pixel(0, 0).unwrap().alpha(), 0);
    }

    #[test]
    fn an_empty_rect_draws_nothing() {
        let mut pixmap = tiny_skia::Pixmap::new(10, 10).unwrap();
        let empty = Rect {
            width: 0.0,
            height: 0.0,
            ..SQUARE
        };
        fill_rounded_rect(&mut pixmap, empty, 1.0, Color::rgb(255, 0, 0));
        assert!(pixmap.data().iter().all(|&byte| byte == 0));
    }
}
