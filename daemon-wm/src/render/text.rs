//! cosmic-text shaping, measurement, and glyph compositing.

use super::{Color, whole};
use cosmic_text::{
    Attrs, Buffer, Ellipsize, EllipsizeHeightLimit, FontSystem, Metrics, Shaping, SwashCache, Wrap,
};

/// Line height as a multiple of the font size.
const LINE_HEIGHT: f32 = 1.3;

/// How text fits the horizontal space it is given.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fit {
    /// One line per paragraph, as wide as the text.
    Natural,
    /// Wrapped to this width.
    Wrap(f32),
    /// One line, ending in `…` when wider than this width.
    Ellipsize(f32),
}

/// A run of text to lay out: its content, size, attributes, and fit.
#[derive(Debug, Clone)]
pub struct Text<'t> {
    pub content: &'t str,
    pub size: f32,
    pub attrs: Attrs<'t>,
    pub fit: Fit,
}

impl Text<'_> {
    /// The text shaped and laid out.
    fn shape(&self, fonts: &mut FontSystem) -> Buffer {
        let mut buffer = Buffer::new(fonts, Metrics::new(self.size, self.size * LINE_HEIGHT));
        match self.fit {
            Fit::Natural => {}
            Fit::Wrap(width) => buffer.set_size(Some(width), None),
            Fit::Ellipsize(width) => {
                buffer.set_wrap(Wrap::None);
                buffer.set_ellipsize(Ellipsize::End(EllipsizeHeightLimit::Lines(1)));
                buffer.set_size(Some(width), None);
            }
        }
        buffer.set_text(self.content, &self.attrs, Shaping::Advanced, None);
        buffer.shape_until_scroll(fonts, false);
        buffer
    }

    /// Width of the widest line and the bottom of the last.
    pub fn extent(&self, fonts: &mut FontSystem) -> (f32, f32) {
        extent(&self.shape(fonts))
    }

    /// Composite the text in `color` onto `pixmap` with its top-left at
    /// `origin`; its extent, as [`Text::extent`].
    pub fn draw(
        &self,
        pixmap: &mut tiny_skia::Pixmap,
        fonts: &mut FontSystem,
        glyphs: &mut SwashCache,
        origin: (f32, f32),
        color: Color,
    ) -> (f32, f32) {
        let mut buffer = self.shape(fonts);
        let (ox, oy) = (whole(origin.0), whole(origin.1));
        let (width, height) = (pixmap.width(), pixmap.height());
        let data = pixmap.data_mut();
        // The callback reports glyph coverage pixels (1x1) and decoration
        // rectangles; each covers its whole w x h area.
        buffer.draw(
            fonts,
            glyphs,
            color.to_cosmic_text(),
            |x, y, w, h, pixel| {
                let (Ok(w), Ok(h)) = (i32::try_from(w), i32::try_from(h)) else {
                    return;
                };
                for py in y..y.saturating_add(h) {
                    for px in x..x.saturating_add(w) {
                        let at =
                            offset(ox.saturating_add(px), oy.saturating_add(py), width, height);
                        if let Some(at) = at {
                            blend(&mut data[at..at + 4], pixel);
                        }
                    }
                }
            },
        );
        extent(&buffer)
    }
}

/// Width of the widest laid-out line, and the baseline of the last line
/// plus one line height.
fn extent(buffer: &Buffer) -> (f32, f32) {
    buffer
        .layout_runs()
        .fold((0.0_f32, 0.0_f32), |(w, _), run| {
            (w.max(run.line_w), run.line_y + run.line_height)
        })
}

/// The byte offset of pixel (`x`, `y`) in a `width` x `height` RGBA
/// pixmap; `None` outside it.
fn offset(x: i32, y: i32, width: u32, height: u32) -> Option<usize> {
    let x = u32::try_from(x).ok().filter(|&x| x < width)?;
    let y = u32::try_from(y).ok().filter(|&y| y < height)?;
    let index =
        usize::try_from(y).ok()? * usize::try_from(width).ok()? + usize::try_from(x).ok()?;
    index.checked_mul(4)
}

/// Composite straight-alpha `color` over the premultiplied RGBA `pixel`
/// (source-over).
fn blend(pixel: &mut [u8], color: cosmic_text::Color) {
    let alpha = u32::from(color.a());
    if alpha == 0 {
        return;
    }
    let inverse = 255 - alpha;
    // Each term is at most 255 * 255; the sum over 255 is at most 255.
    let mix = |source: u32, destination: u8| {
        u8::try_from((source + u32::from(destination) * inverse) / 255).unwrap_or(u8::MAX)
    };
    for (destination, source) in pixel[..3].iter_mut().zip([color.r(), color.g(), color.b()]) {
        *destination = mix(u32::from(source) * alpha, *destination);
    }
    pixel[3] = mix(alpha * 255, pixel[3]);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TITLE: &str = "A window title far too long for the column it is drawn in";

    /// The fonts of the host; text tests need at least one face.
    fn font_system() -> FontSystem {
        let font_system = FontSystem::new();
        assert!(
            font_system.db().faces().next().is_some(),
            "no system fonts: install a font (fontconfig) to run the text tests"
        );
        font_system
    }

    fn text(content: &str, fit: Fit) -> Text<'_> {
        Text {
            content,
            size: 14.0,
            attrs: Attrs::new(),
            fit,
        }
    }

    #[test]
    fn ellipsized_text_fits_its_width() {
        let mut fonts = font_system();
        let (natural, one_line) = text(TITLE, Fit::Natural).extent(&mut fonts);
        let width = natural / 2.0;
        let (ellipsized, height) = text(TITLE, Fit::Ellipsize(width)).extent(&mut fonts);
        assert!(ellipsized <= width, "{ellipsized} > {width}");
        assert!(ellipsized > 0.0);
        assert!(
            (height - one_line).abs() < f32::EPSILON,
            "ellipsized text stays one line: {height} vs {one_line}"
        );
    }

    #[test]
    fn text_that_fits_is_not_ellipsized() {
        let mut fonts = font_system();
        let (natural, _) = text("Files", Fit::Natural).extent(&mut fonts);
        let (fitted, _) = text("Files", Fit::Ellipsize(natural + 10.0)).extent(&mut fonts);
        assert!((fitted - natural).abs() < f32::EPSILON);
    }

    #[test]
    fn wrapped_text_is_taller_than_one_line() {
        let mut fonts = font_system();
        let (natural, one_line) = text(TITLE, Fit::Natural).extent(&mut fonts);
        let (wrapped_w, wrapped_h) = text(TITLE, Fit::Wrap(natural / 3.0)).extent(&mut fonts);
        assert!(wrapped_w <= natural / 3.0 + 1.0);
        assert!(wrapped_h > one_line);
    }

    #[test]
    fn drawn_text_marks_the_pixmap_inside_its_extent() {
        let mut fonts = font_system();
        let mut pixmap = tiny_skia::Pixmap::new(200, 40).unwrap();
        let (w, h) = text("Files", Fit::Natural).draw(
            &mut pixmap,
            &mut fonts,
            &mut SwashCache::new(),
            (4.0, 4.0),
            Color::rgb(255, 255, 255),
        );
        assert!(w > 0.0 && h > 0.0);
        assert!(pixmap.data().chunks_exact(4).any(|px| px[3] > 0));
        assert_eq!(
            pixmap.pixel(199, 39).unwrap().alpha(),
            0,
            "nothing past the text"
        );
    }

    #[test]
    fn blending_is_source_over_on_premultiplied_pixels() {
        let mut pixel = [0, 0, 0, 0];
        blend(&mut pixel, cosmic_text::Color::rgba(255, 0, 0, 255));
        assert_eq!(pixel, [255, 0, 0, 255], "opaque replaces");
        let mut pixel = [0, 0, 255, 255];
        blend(&mut pixel, cosmic_text::Color::rgba(255, 0, 0, 0));
        assert_eq!(pixel, [0, 0, 255, 255], "transparent leaves it");
        let mut pixel = [0, 0, 0, 0];
        blend(&mut pixel, cosmic_text::Color::rgba(255, 255, 255, 51));
        assert_eq!(pixel, [51, 51, 51, 51], "partial coverage premultiplies");
    }

    #[test]
    fn offsets_reject_pixels_outside_the_pixmap() {
        assert_eq!(offset(0, 0, 4, 4), Some(0));
        assert_eq!(offset(3, 1, 4, 4), Some(28));
        assert_eq!(offset(-1, 0, 4, 4), None);
        assert_eq!(offset(4, 0, 4, 4), None);
        assert_eq!(offset(0, 4, 4, 4), None);
    }
}
