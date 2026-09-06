#!/usr/bin/env python3
"""Generate the README's small, theme-aware SVG graphics; no dependencies."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "assets/readme"
ICONS = {
    "application": '<rect x="3" y="3" width="26" height="26" rx="4"/><path d="m12 11-5 5 5 5m8-10 5 5-5 5m-3-12-2 14"/>',
    "machines": '<rect x="3" y="3" width="26" height="10" rx="3"/><rect x="3" y="19" width="26" height="10" rx="3"/><path d="M8 8h1m4 0h1m6 0h4M8 24h1m4 0h1m6 0h4"/>',
    "cloud": '<path d="M8 26a6 6 0 0 1-1-12 9 9 0 0 1 17-3 7.5 7.5 0 0 1 0 15Z"/>',
    "runtime": '<rect x="3" y="3" width="26" height="26" rx="4"/><path d="m7 22 6-7 5 3 7-10m-6 0h6v6"/>',
    "lifecycle": '<circle cx="7" cy="16" r="4"/><circle cx="25" cy="6" r="4"/><circle cx="25" cy="26" r="4"/><path d="m11 14 10-6M11 18l10 6"/>',
}


def svg(width, height, content):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">{content}</svg>\n')


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for theme, accent, ink, button_ink in (
        ("light", "#a34400", "#1f2328", "#ffffff"),
        ("dark", "#ff962f", "#e6edf3", "#111111"),
    ):
        stroke = f'fill="none" stroke="{accent}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
        for name, paths in ICONS.items():
            (ROOT / f"{name}-{theme}.svg").write_text(svg(32, 32, f'<g {stroke}>{paths}</g>'))
        button = (f'<rect width="166" height="42" rx="6" fill="{accent}"/>'
                  f'<text x="83" y="27" text-anchor="middle" fill="{button_ink}" '
                  'font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="16" font-weight="650">Try Prodigy →</text>')
        (ROOT / f"try-{theme}.svg").write_text(svg(166, 42, button))
        diagram = f'''<g {stroke}>
          <g transform="translate(35 54) scale(1.7)">{ICONS['application']}</g>
          <rect x="257" y="57" width="54" height="54" rx="7"/>
          <path d="M277 95V73h8a6 6 0 0 1 0 12h-8"/>
          <path d="M111 84h111m-7-6 7 6-7 6M334 84h67M401 40v88M401 40h43m-7-6 7 6-7 6M401 128h43m-7-6 7 6-7 6"/>
          <g transform="translate(465 13) scale(1.7)">{ICONS['machines']}</g>
          <g transform="translate(465 101) scale(1.7)">{ICONS['cloud']}</g>
        </g>
        <g fill="{ink}" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="18">
          <text x="62" y="144" text-anchor="middle">Your application</text>
          <text x="284" y="144" text-anchor="middle">Prodigy</text>
          <text x="543" y="47">Your machines</text>
          <text x="543" y="135">Cloud capacity</text>
        </g>'''
        # A little extra inset keeps the first label clear of the SVG edge.
        (ROOT / f"flow-{theme}.svg").write_text(svg(760, 184, f'<g transform="translate(20 8)">{diagram}</g>'))
        mobile = f'''<g {stroke}>
          <g transform="translate(44 10) scale(1.3)">{ICONS['application']}</g>
          <rect x="235" y="12" width="40" height="40" rx="6"/>
          <path d="M248.75 42.5V21.5h7a5.5 5.5 0 0 1 0 11h-7"/>
          <path d="M105 32h107m-6-5 6 5-6 5"/>
          <path d="M255 88v20H85m0 0v24m-5-6 5 6 5-6m165-18v24m-5-6 5 6 5-6"/>
          <g transform="translate(64 144) scale(1.3)">{ICONS['machines']}</g>
          <g transform="translate(234 144) scale(1.3)">{ICONS['cloud']}</g>
        </g>
        <g fill="{ink}" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="16" text-anchor="middle">
          <text x="65" y="76">Your application</text><text x="255" y="76">Prodigy</text>
          <text x="85" y="210">Your machines</text><text x="255" y="210">Cloud capacity</text>
        </g>'''
        (ROOT / f"flow-mobile-{theme}.svg").write_text(svg(340, 230, mobile))


if __name__ == "__main__":
    main()
