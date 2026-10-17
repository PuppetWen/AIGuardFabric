/**
 * Minimal, dependency-free Markdown → HTML renderer.
 *
 * The console only needs to preview trusted server-generated report bodies
 * (red-team reports, report previews), so a small subset is enough: headings,
 * fenced code, blockquotes, tables, ordered/unordered lists, bold/italic/code
 * spans and paragraphs. Everything is HTML-escaped before any markup is added,
 * so a report body cannot inject tags — `markdown.test.ts` asserts that.
 */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Inline formatting applied to already-escaped text. */
function renderInline(value: string): string {
  return value
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|\W)\*([^*]+)\*/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
}

function renderTable(rows: string[]): string {
  const cells = rows.map((row) =>
    row
      .replace(/^\||\|$/g, '')
      .split('|')
      .map((cell) => cell.trim()),
  );
  const [header, ...body] = cells;
  if (!header) {
    return '';
  }
  const head = `<thead><tr>${header.map((cell) => `<th>${renderInline(cell)}</th>`).join('')}</tr></thead>`;
  const rest = body
    .filter((row) => !row.every((cell) => /^-{2,}$/.test(cell) || cell === ''))
    .map((row) => `<tr>${row.map((cell) => `<td>${renderInline(cell)}</td>`).join('')}</tr>`)
    .join('');
  return `<table>${head}<tbody>${rest}</tbody></table>`;
}

/** Convert a Markdown document to an HTML string. */
export function renderMarkdown(markdown: string): string {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const output: string[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? '';

    // fenced code block
    if (line.trimStart().startsWith('```')) {
      const buffer: string[] = [];
      index += 1;
      while (index < lines.length && !(lines[index] ?? '').trimStart().startsWith('```')) {
        buffer.push(lines[index] ?? '');
        index += 1;
      }
      index += 1;
      output.push(`<pre class="agf-code">${escapeHtml(buffer.join('\n'))}</pre>`);
      continue;
    }

    // table
    if (/^\s*\|.*\|\s*$/.test(line) && /^\s*\|[-:\s|]+\|\s*$/.test(lines[index + 1] ?? '')) {
      const rows: string[] = [];
      while (index < lines.length && /^\s*\|.*\|\s*$/.test(lines[index] ?? '')) {
        rows.push(lines[index] ?? '');
        index += 1;
      }
      output.push(renderTable(rows));
      continue;
    }

    // heading
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const level = (heading[1] ?? '#').length;
      output.push(`<h${level}>${renderInline(escapeHtml(heading[2] ?? ''))}</h${level}>`);
      index += 1;
      continue;
    }

    // blockquote
    if (/^>\s?/.test(line)) {
      const buffer: string[] = [];
      while (index < lines.length && /^>\s?/.test(lines[index] ?? '')) {
        buffer.push((lines[index] ?? '').replace(/^>\s?/, ''));
        index += 1;
      }
      output.push(`<blockquote>${renderInline(escapeHtml(buffer.join(' ')))}</blockquote>`);
      continue;
    }

    // unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const buffer: string[] = [];
      while (index < lines.length && /^\s*[-*+]\s+/.test(lines[index] ?? '')) {
        buffer.push((lines[index] ?? '').replace(/^\s*[-*+]\s+/, ''));
        index += 1;
      }
      output.push(
        `<ul>${buffer.map((item) => `<li>${renderInline(escapeHtml(item))}</li>`).join('')}</ul>`,
      );
      continue;
    }

    // ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const buffer: string[] = [];
      while (index < lines.length && /^\s*\d+\.\s+/.test(lines[index] ?? '')) {
        buffer.push((lines[index] ?? '').replace(/^\s*\d+\.\s+/, ''));
        index += 1;
      }
      output.push(
        `<ol>${buffer.map((item) => `<li>${renderInline(escapeHtml(item))}</li>`).join('')}</ol>`,
      );
      continue;
    }

    // blank line
    if (line.trim() === '') {
      index += 1;
      continue;
    }

    // paragraph
    const buffer: string[] = [];
    while (
      index < lines.length &&
      (lines[index] ?? '').trim() !== '' &&
      !/^(#{1,6})\s+/.test(lines[index] ?? '') &&
      !/^\s*[-*+]\s+/.test(lines[index] ?? '') &&
      !/^\s*\d+\.\s+/.test(lines[index] ?? '') &&
      !(lines[index] ?? '').trimStart().startsWith('```') &&
      !/^>\s?/.test(lines[index] ?? '')
    ) {
      buffer.push(lines[index] ?? '');
      index += 1;
    }
    output.push(`<p>${renderInline(escapeHtml(buffer.join(' ')))}</p>`);
  }

  return output.join('\n');
}

export default renderMarkdown;
