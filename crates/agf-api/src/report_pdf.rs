//! A4 report layout with headings, wrapped paragraphs, and repeating table headers.
//! User text is hex encoded; it can never become a PDF operator.
use agf_core::error::DomainResult;
use std::fmt::Write;
#[path = "report_pdf_font.rs"]
mod font;

const LEFT: f32 = 44.0;
const WIDTH: f32 = 507.0;
const TOP: f32 = 782.0;
const BOTTOM: f32 = 60.0;

#[derive(Default)]
struct Layout {
    pages: Vec<String>,
    current: String,
    y: f32,
    codes: font::CodeMap,
}

impl Layout {
    fn new(codes: font::CodeMap) -> Self {
        let mut out = Self { codes, ..Self::default() };
        out.new_page();
        out
    }

    fn new_page(&mut self) {
        if !self.current.is_empty() {
            self.pages.push(std::mem::take(&mut self.current));
        }
        self.y = TOP;
        self.current.push_str("0.12 0.25 0.42 rg 44 808 507 3 re f\n");
        text(&mut self.current, &self.codes, "AIGuardFabric", (LEFT, 819.0), 9.0, true);
    }

    fn room(&mut self, height: f32) -> bool {
        if self.y - height < BOTTOM {
            self.new_page();
            return true;
        }
        false
    }

    fn paragraph(&mut self, source: &str, size: f32, heading: bool) {
        let lines = wrap(source, WIDTH, size);
        if heading {
            self.room(size * 3.0);
            self.y -= 8.0;
        }
        for line in lines {
            self.room(size + 6.0);
            text(&mut self.current, &self.codes, &line, (LEFT, self.y), size, heading);
            self.y -= size + 6.0;
        }
        if heading {
            self.y -= 3.0;
        }
    }

    fn row(&mut self, cells: &[String], widths: &[f32], header: bool) {
        let wrapped: Vec<_> = widths
            .iter()
            .enumerate()
            .map(|(i, w)| wrap(cells.get(i).map_or("", String::as_str), *w - 12.0, 9.0))
            .collect();
        let count = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        // Long source cells are already bounded by report rendering. Split at page boundaries.
        for start in (0..count).step_by(40) {
            let end = (start + 40).min(count);
            let height = (end - start) as f32 * 13.0 + 10.0;
            self.room(height);
            let bottom = self.y - height + 6.0;
            let color = if header { "0.90 0.94 0.98" } else { "1 1 1" };
            let _ = writeln!(self.current, "{color} rg {LEFT} {bottom} {WIDTH} {height} re f");
            self.current.push_str("0.80 0.84 0.89 RG 0.4 w\n");
            let mut x = LEFT;
            for (lines, width) in wrapped.iter().zip(widths) {
                let _ = writeln!(self.current, "{x} {bottom} {width} {height} re S");
                for (offset, line) in lines.iter().skip(start).take(end - start).enumerate() {
                    text(
                        &mut self.current,
                        &self.codes,
                        line,
                        (x + 6.0, self.y - 6.0 - offset as f32 * 13.0),
                        9.0,
                        header,
                    );
                }
                x += width;
            }
            self.y -= height;
        }
    }

    fn table(&mut self, rows: &[Vec<String>]) {
        if rows.is_empty() {
            return;
        }
        let columns = rows.iter().map(Vec::len).max().unwrap_or(1);
        let weights: Vec<f32> = (0..columns)
            .map(|i| {
                rows.iter().filter_map(|row| row.get(i)).map(|s| measure(s, 1.0)).fold(6.0, f32::max).clamp(6.0, 35.0)
            })
            .collect();
        let total: f32 = weights.iter().sum();
        let widths: Vec<_> = weights.iter().map(|w| WIDTH * w / total).collect();
        for (index, row) in rows.iter().enumerate() {
            let height = widths
                .iter()
                .enumerate()
                .map(|(i, w)| wrap(row.get(i).map_or("", String::as_str), *w - 12.0, 9.0).len())
                .max()
                .unwrap_or(1) as f32
                * 13.0
                + 10.0;
            if self.room(height.min(530.0) + 26.0) && index > 0 {
                self.row(&rows[0], &widths, true);
            }
            self.row(row, &widths, index == 0);
        }
        self.y -= 14.0;
    }
}

fn char_width(c: char, size: f32) -> f32 {
    font::advance(c) * size
}
fn measure(s: &str, size: f32) -> f32 {
    s.chars().map(|c| char_width(c, size)).sum()
}

fn wrap(source: &str, width: f32, size: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0.0;
    for c in source.chars().filter(|c| !c.is_control()) {
        let advance = char_width(c, size);
        if used + advance > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            used = 0.0;
        }
        line.push(c);
        used += advance;
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

fn text(out: &mut String, codes: &font::CodeMap, value: &str, position: (f32, f32), size: f32, accent: bool) {
    let (mut x, y) = position;
    let color = if accent { "0.12 0.25 0.42" } else { "0.16 0.19 0.23" };
    // Explicit positioning avoids relying on different viewer substitute-font widths.
    for c in value.chars().filter(|c| !c.is_control()) {
        let hex = format!("{:04X}", codes.get(&c).copied().unwrap_or_default());
        // ActualText preserves distinct Unicode values that share a glyph (including missing glyphs).
        let actual = font::unicode_hex(c);
        let _ = writeln!(out, "/Span << /ActualText <FEFF{actual}> >> BDC");
        let _ = writeln!(out, "BT {color} rg /F1 {size} Tf 1 0 0 1 {x:.2} {y:.2} Tm <{hex}> Tj ET");
        out.push_str("EMC\n");
        x += char_width(c, size);
    }
}

fn cells(line: &str) -> Vec<String> {
    line.trim().trim_matches('|').split('|').map(|s| s.trim().replace("&#124;", "|")).collect()
}
fn separator(line: &str) -> bool {
    line.chars().all(|c| c.is_whitespace() || "|:-".contains(c))
}

pub(super) fn render(source: &str) -> DomainResult<Vec<u8>> {
    let mut layout = Layout::new(font::codes(source)?);
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.starts_with('|') {
            let mut rows = vec![cells(line)];
            while let Some(next) = lines.peek().copied().filter(|s| s.trim().starts_with('|')) {
                if !separator(next) {
                    rows.push(cells(next));
                }
                lines.next();
            }
            layout.table(&rows);
        } else if line.starts_with('#') {
            let level = line.chars().take_while(|c| *c == '#').count();
            layout.paragraph(line.trim_start_matches('#').trim(), if level == 1 { 19.0 } else { 12.0 }, true);
        } else if !line.is_empty() {
            layout.paragraph(line, 9.5, false);
        } else {
            layout.y -= 6.0;
        }
    }
    layout.pages.push(layout.current);
    assemble(layout.pages, &layout.codes)
}

fn assemble(pages: Vec<String>, codes: &font::CodeMap) -> DomainResult<Vec<u8>> {
    let mut objects = vec![Vec::new(), Vec::new()];
    objects.extend(font::objects(codes)?);
    let mut refs = Vec::new();
    let total = pages.len();
    for (index, mut stream) in pages.into_iter().enumerate() {
        let id = objects.len() + 1;
        refs.push(format!("{id} 0 R"));
        objects.push(format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>", id + 1).into_bytes());
        text(&mut stream, codes, &format!("AIGuardFabric | {} / {total}", index + 1), (LEFT, 32.0), 8.0, true);
        objects.push(font::stream(stream.as_bytes(), ""));
    }
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();
    objects[1] = format!("<< /Type /Pages /Count {total} /Kids [{}] >>", refs.join(" ")).into_bytes();
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        bytes.extend_from_slice(object);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes(),
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_cannot_inject_pdf_operators_and_long_tables_paginate() {
        let source = format!("# 中文报告\n|名称|数值|\n|---|---|\n{}", "| ) ET /JavaScript ( | 中文 |\n".repeat(100));
        let bytes = render(&source).unwrap();
        let pdf = String::from_utf8_lossy(&bytes);
        assert!(!pdf.contains("/JavaScript"));
        assert!(pdf.matches("/Type /Page ").count() >= 3);
        let offset = pdf.split("startxref\n").nth(1).unwrap().lines().next().unwrap().parse::<usize>().unwrap();
        assert!(bytes[offset..].starts_with(b"xref"));
        assert!(pdf.contains("/FontFile3"));
        assert!(pdf.contains("/ToUnicode"));
        assert!(!pdf.contains("STSong-Light"));
        assert!(wrap("混合abc中文", 20.0, 10.0).iter().all(|line| measure(line, 10.0) <= 20.0));
    }
}
