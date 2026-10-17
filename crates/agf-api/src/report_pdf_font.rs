//! Font subsetting and explicit PDF character maps, including non-BMP Unicode.
use agf_core::error::{DomainError, DomainResult};
use skrifa::{
    FontRef, GlyphId, MetadataProvider,
    instance::{LocationRef, Size},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};
use subsetter::GlyphRemapper;

const DATA: &[u8] = include_bytes!("../resources/fonts/NotoSansCJKsc-Regular.otf");

fn face() -> Option<FontRef<'static>> {
    let font = FontRef::new(DATA).ok()?;
    let metrics = font.metrics(Size::unscaled(), LocationRef::default());
    (metrics.units_per_em > 0 && metrics.bounds.is_some()).then_some(font)
}

fn glyph(font: &FontRef<'_>, c: char) -> GlyphId {
    font.charmap().map(c as u32).unwrap_or(GlyphId::new(0))
}

fn subset_glyph(font: &FontRef<'_>, c: char) -> u16 {
    u16::try_from(glyph(font, c).to_u32()).unwrap_or(0)
}

pub(super) fn advance(c: char) -> f32 {
    let Some(font) = face() else { return 1.0 };
    let metrics = font.metrics(Size::unscaled(), LocationRef::default());
    font.glyph_metrics(Size::unscaled(), LocationRef::default())
        .advance_width(glyph(&font, c))
        .unwrap_or(f32::from(metrics.units_per_em))
        / f32::from(metrics.units_per_em)
}

pub(super) fn stream(data: &[u8], attributes: &str) -> Vec<u8> {
    let mut out = format!("<< /Length {} {attributes} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

pub(super) type CodeMap = BTreeMap<char, u16>;

pub(super) fn codes(source: &str) -> DomainResult<CodeMap> {
    let chars: BTreeSet<char> =
        source.chars().chain("AIGuardFabric | 0123456789 /".chars()).filter(|c| !c.is_control()).collect();
    if chars.len() > 65_534 {
        return Err(DomainError::Validation("单份 PDF 字符种类超过 65534，请缩小报表范围".into()));
    }
    let font = face().ok_or_else(|| DomainError::Internal("报表字体资源损坏".into()))?;
    let mut mapper = GlyphRemapper::new();
    Ok(chars.into_iter().map(|c| (c, mapper.remap(subset_glyph(&font, c)))).collect())
}

/// Objects 3..7: Type0 font, CID font, descriptor, font program, ToUnicode.
pub(super) fn objects(codes: &CodeMap) -> DomainResult<Vec<Vec<u8>>> {
    let font = face().ok_or_else(|| DomainError::Internal("报表字体资源损坏".into()))?;
    let mut mapper = GlyphRemapper::new();
    let mut mapping = Vec::new();
    let mut widths = BTreeMap::new();
    for (&c, &code) in codes {
        let cid = mapper.remap(subset_glyph(&font, c));
        mapping.push((c, code, cid));
        widths.insert(cid, (advance(c) * 1000.0).round() as i32);
    }
    let subset = subsetter::subset(DATA, 0, &mapper)
        .map_err(|error| DomainError::Internal(format!("报表字体嵌入失败：{error:?}")))?;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&subset);
    let tag: String = digest[..6].iter().map(|v| char::from(b'A' + v % 26)).collect();
    let name = format!("{tag}+NotoSansCJKsc-Regular");
    let metrics = font.metrics(Size::unscaled(), LocationRef::default());
    let box_ = metrics.bounds.ok_or_else(|| DomainError::Internal("报表字体缺少边界数据".into()))?;
    let scale = |v: f32| (v * 1000.0 / f32::from(metrics.units_per_em)).round() as i32;
    let widths = widths.iter().map(|(cid, width)| format!("{cid} [{width}]")).collect::<Vec<_>>().join(" ");
    let type0 = format!(
        "<< /Type /Font /Subtype /Type0 /BaseFont /{name} /Encoding /Identity-H /DescendantFonts [4 0 R] /ToUnicode 7 0 R >>"
    );
    let cid = format!(
        "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /{name} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 5 0 R /DW 1000 /W [{widths}] >>"
    );
    let descriptor = format!(
        "<< /Type /FontDescriptor /FontName /{name} /Flags 4 /FontBBox [{} {} {} {}] /ItalicAngle 0 /Ascent {} /Descent {} /CapHeight {} /StemV 80 /FontFile3 6 0 R >>",
        scale(box_.x_min),
        scale(box_.y_min),
        scale(box_.x_max),
        scale(box_.y_max),
        scale(metrics.ascent),
        scale(metrics.descent),
        scale(metrics.cap_height.unwrap_or(metrics.ascent))
    );
    Ok(vec![
        type0.into_bytes(),
        cid.into_bytes(),
        descriptor.into_bytes(),
        stream(&subset, "/Subtype /OpenType"),
        stream(cmap(&mapping).as_bytes(), ""),
    ])
}

pub(super) fn unicode_hex(c: char) -> String {
    let mut utf16 = [0u16; 2];
    let mut hex = String::new();
    for v in c.encode_utf16(&mut utf16) {
        let _ = write!(hex, "{v:04X}");
    }
    hex
}

fn cmap(mapping: &[(char, u16, u16)]) -> String {
    let mut unique = BTreeMap::new();
    for &(c, code, _) in mapping {
        unique.entry(code).or_insert(c);
    }
    let entries: Vec<_> = unique.into_iter().collect();
    let mut out = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /AGFUnicode def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    for chunk in entries.chunks(100) {
        let _ = writeln!(out, "{} beginbfchar", chunk.len());
        for &(code, c) in chunk {
            let _ = writeln!(out, "<{code:04X}> <{}>", unicode_hex(c));
        }
        out.push_str("endbfchar\n");
    }
    out.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_font_subsets_and_unicode_maps_preserve_surrogate_pairs() {
        assert!(face().unwrap().charmap().map('御' as u32).is_some());
        assert!(face().unwrap().charmap().map('𠮷' as u32).is_some());
        let objects = objects(&codes("中文𠮷").unwrap()).unwrap();
        let cmap = String::from_utf8_lossy(&objects[4]);
        assert!(cmap.contains("<D842DFB7>"));
        assert!(objects[3].len() < DATA.len() / 10);
        assert!(advance('i') < advance('W'));
    }
}
