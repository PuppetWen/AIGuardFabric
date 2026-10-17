/**
 * Colour maths for the accessibility checks.
 *
 * The dark theme is the default, so every foreground/background pair the console
 * actually renders must clear WCAG AA (4.5:1 for body text, 3:1 for large text
 * and non-text UI). `colors.test.ts` asserts those pairs.
 */

export interface Rgb {
  r: number;
  g: number;
  b: number;
}

/** Parse `#rgb`, `#rrggbb` or `#rrggbbaa` into 0-255 channels. */
export function hexToRgb(hex: string): Rgb {
  const value = hex.trim().replace(/^#/, '');
  const expanded =
    value.length === 3
      ? value
          .split('')
          .map((char) => char + char)
          .join('')
      : value.slice(0, 6);
  if (expanded.length !== 6 || !/^[0-9a-f]{6}$/i.test(expanded)) {
    throw new Error(`Unsupported hex colour: ${hex}`);
  }
  return {
    r: Number.parseInt(expanded.slice(0, 2), 16),
    g: Number.parseInt(expanded.slice(2, 4), 16),
    b: Number.parseInt(expanded.slice(4, 6), 16),
  };
}

/** Parse `rgb(r, g, b)` / `rgba(r, g, b, a)` into channels plus alpha. */
export function parseRgbString(value: string): Rgb & { a: number } {
  const match = /rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/i.exec(value);
  if (!match) {
    throw new Error(`Unsupported rgb colour: ${value}`);
  }
  return {
    r: Number.parseFloat(match[1] as string),
    g: Number.parseFloat(match[2] as string),
    b: Number.parseFloat(match[3] as string),
    a: match[4] === undefined ? 1 : Number.parseFloat(match[4]),
  };
}

function channelLuminance(channel: number): number {
  const srgb = channel / 255;
  return srgb <= 0.03928 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
}

/** Relative luminance per WCAG 2.1. */
export function relativeLuminance(color: string | Rgb): number {
  const rgb = typeof color === 'string' ? parseAnyColor(color) : color;
  return (
    0.2126 * channelLuminance(rgb.r) + 0.7152 * channelLuminance(rgb.g) + 0.0722 * channelLuminance(rgb.b)
  );
}

/** Accepts `#rrggbb` and `rgb()/rgba()` strings. */
export function parseAnyColor(value: string): Rgb {
  return value.trim().startsWith('#') ? hexToRgb(value) : parseRgbString(value);
}

/** WCAG contrast ratio between two opaque colours (1..21). */
export function contrastRatio(foreground: string, background: string): number {
  const a = relativeLuminance(foreground);
  const b = relativeLuminance(background);
  const lighter = Math.max(a, b);
  const darker = Math.min(a, b);
  return (lighter + 0.05) / (darker + 0.05);
}

/** Composite a translucent foreground over an opaque background. */
export function compositeOver(foreground: string, background: string): Rgb {
  const fg = parseRgbString(foreground);
  const bg = parseAnyColor(background);
  return {
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a),
  };
}

/** Contrast ratio for a translucent chip colour over an opaque surface colour. */
export function contrastOverTranslucent(
  textColor: string,
  chipBackground: string,
  surface: string,
): number {
  const composited = compositeOver(chipBackground, surface);
  return contrastRatio(textColor, `#${toHex(composited)}`);
}

function toHex(rgb: Rgb): string {
  const part = (value: number): string =>
    Math.round(Math.min(255, Math.max(0, value)))
      .toString(16)
      .padStart(2, '0');
  return `${part(rgb.r)}${part(rgb.g)}${part(rgb.b)}`;
}

/** Round a ratio for readable test output. */
export function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
