// Re-render the README animation from its recorded transcript: node tools/render-terminal.cjs
// Requires macOS (AppKit emoji and Menlo), Swift, sharp, and ffmpeg.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const sharp = require('sharp');
const root = path.resolve(__dirname, '..');
const events = fs.readFileSync(path.join(root, 'assets/try-prodigy.cast'), 'utf8')
  .trim().split('\n').slice(1).map(JSON.parse);
const scenes = [];
for (const [, type, text] of events) {
  if (type !== 'o') continue;
  if (text.startsWith('$ ') || text.startsWith('^C')) scenes.push([]);
  if (scenes.length) scenes.at(-1).push(text);
}
const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const titles = ['RUN YOUR FIRST SERVICE', 'INSPECT IT', 'DEPLOY AN UPDATE', 'MAKE A REQUEST', 'CLEAN UP'];
// One terminal grid controls the prompt, emoji, commands, output, and cursor.
const grid = { left: 30, baseline: 89, font: 20, cell: 12.05, row: 30, columns: 94 };
const terminalText = (text, column, row, color) => text ?
  `<text x="${grid.left + column * grid.cell}" y="${grid.baseline + row * grid.row}" fill="${color}" textLength="${[...text].length * grid.cell}" lengthAdjust="spacingAndGlyphs">${escape(text)}</text>` : '';
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'prodigy-terminal-'));
(async () => {
  try {
    // AppKit preserves the emoji's color artwork; SVG font rendering flattens it.
    const emojiPath = path.join(scratch, 'skull.png');
    execFileSync('swift', ['-e', `
      import AppKit
      let image = NSImage(size: NSSize(width: 96, height: 96))
      image.lockFocus()
      ("☠️" as NSString).draw(at: NSPoint(x: 4, y: 6), withAttributes: [.font: NSFont(name: "Apple Color Emoji", size: 76)!])
      image.unlockFocus()
      let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
      try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
    `, emojiPath]);
    const emoji = (await sharp(emojiPath).trim().png().toBuffer()).toString('base64');
    for (const [index, chunks] of scenes.entries()) {
      const lines = chunks.join('').trimEnd().replace('--noproxy *', '--noproxy "*"').split('\n');
      const command = lines.shift().replace(/^\$ /, '');
      let row = 0;
      const output = [];
      // The emoji occupies two character cells, followed by one space.
      let rest = command;
      let column = 18;
      while (rest.length) {
        const count = grid.columns - column;
        output.push(terminalText(rest.slice(0, count), column, row, '#f1f1f1'));
        rest = rest.slice(count);
        row += 1;
        column = 0;
      }
      for (const line of lines) {
        const color = line.startsWith('hello from') || line === 'Demo removed.' ? '#ff962f'
          : line.startsWith('Service:') ? '#65b5ec' : '#c6c6c6';
        const wrapped = line.match(new RegExp(`.{1,${grid.columns}}`, 'g')) || [''];
        for (const part of wrapped) {
          output.push(terminalText(part, 0, row, color));
          row += 1;
        }
      }
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="460">
        <rect width="1200" height="460" rx="12" fill="#000000"/>
        <path d="M12 0H1188Q1200 0 1200 12V47H0V12Q0 0 12 0" fill="#191919"/>
        <g font-family="Menlo, DejaVu Sans Mono, monospace">
          <text x="30" y="30" fill="#a5a5a5" font-size="12">PRODIGY</text>
          <text x="1170" y="30" text-anchor="end" fill="#9a9a9a" font-size="12">0${index + 1} / 05 · ${titles[index]}</text>
          <g font-size="${grid.font}">
            ${terminalText('root', 0, 0, '#d94c2b')}
            ${terminalText('@', 4, 0, '#eeeeee')}
            ${terminalText('prodigy', 5, 0, '#ff962f')}
            ${terminalText(':', 12, 0, '#eeeeee')}
            ${terminalText('~', 13, 0, '#65b5ec')}
            <image x="${grid.left + 15 * grid.cell + (2 * grid.cell - grid.font) / 2}" y="${grid.baseline - 17}" width="${grid.font}" height="${grid.font}" href="data:image/png;base64,${emoji}"/>
            ${output.join('')}
          </g>
          <rect x="${grid.left}" y="${grid.baseline + row * grid.row - 17}" width="${grid.cell}" height="${grid.font}" fill="#818181"/>
          <path d="M30 421H1170" stroke="#242424"/>
          <text x="30" y="444" font-size="12" fill="#919191">Prepared Linux guest · Verified output excerpts · Playback paced for readability</text>
        </g>
      </svg>`;
      await sharp(Buffer.from(svg)).png().toFile(path.join(scratch, `${index}.png`));
    }
    const list = scenes.map((_, i) => `file '${i}.png'\nduration ${i < 2 ? 5 : 4}`).join('\n');
    fs.writeFileSync(path.join(scratch, 'frames.txt'), `${list}\nfile '${scenes.length - 1}.png'\n`);
    execFileSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0',
      '-i', path.join(scratch, 'frames.txt'), '-vf',
      'split[a][b];[a]palettegen=max_colors=256[p];[b][p]paletteuse=dither=none',
      '-loop', '0', path.join(root, 'assets/try-prodigy.gif')]);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
