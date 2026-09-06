#!/usr/bin/env python3
"""Check the GitHub documentation's local links, anchors, snippets and entrypoints."""

import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = [ROOT / name for name in ("README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md")]
PUBLIC += sorted(p for p in (ROOT / "prodigy/docs").rglob("*.md") if "archive" not in p.parts)
PUBLIC += sorted((ROOT / "examples").rglob("README.md"))
PUBLIC += [ROOT / "prodigy/sdk/README.md"]


def anchors(text):
    result, counts = set(), {}
    for title in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", text, re.M):
        title = re.sub(r"<[^>]+>", "", title).lower()
        slug = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        number = counts.get(slug, 0)
        counts[slug] = number + 1
        result.add(slug + ("-" + str(number) if number else ""))
    for title in re.findall(r"<h1\b[^>]*>(.*?)</h1>", text, re.I | re.S):
        title = re.sub(r"<[^>]+>", "", title).strip().lower()
        slug = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        number = counts.get(slug, 0)
        counts[slug] = number + 1
        result.add(slug + ("-" + str(number) if number else ""))
    result.update(re.findall(r'\bid=["\']([^"\']+)', text))
    return result


def main():
    failures = []
    for path in PUBLIC:
        text = path.read_text()
        if not re.search(r"^#\s+\S|<h1\b[^>]*>\s*\S", text, re.I | re.M):
            failures.append(f"{path.relative_to(ROOT)}: missing page title")
        prose = re.sub(r"```[^\n]*\n.*?```", "", text, flags=re.S)
        targets = re.findall(r"\]\(([^)]+)\)", prose)
        targets += re.findall(r'<(?:img|a)\b[^>]*(?:src|href)="([^"]+)"', prose)
        targets += re.findall(r'<source\b[^>]*\bsrcset="([^"]+)"', prose)
        for raw in targets:
            raw = raw.strip().split(' "', 1)[0].strip("<>")
            url = urlsplit(raw)
            if url.scheme or raw.startswith("//"):
                continue
            target = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not target.exists():
                failures.append(f"{path.relative_to(ROOT)}: missing link {raw}")
            elif url.fragment and target.suffix.lower() == ".md":
                if unquote(url.fragment) not in anchors(target.read_text()):
                    failures.append(f"{path.relative_to(ROOT)}: missing anchor {raw}")
        for language, code in re.findall(r"```([^\n]*)\n(.*?)```", text, re.S):
            language = language.strip()
            if language == "json":
                try:
                    json.loads(code)
                except ValueError as error:
                    failures.append(f"{path.relative_to(ROOT)}: invalid JSON example: {error}")
            elif language in ("bash", "sh"):
                result = subprocess.run(["bash", "-n"], input=code, text=True, capture_output=True)
                if result.returncode:
                    failures.append(f"{path.relative_to(ROOT)}: invalid shell example: {result.stderr.strip()}")
    words = len((ROOT / "README.md").read_text().split())
    if words > 650:
        failures.append(f"README: {words} words, maximum 650")
    for script in ("try-prodigy", "tools/build-evaluation.sh", "tools/package-evaluation.sh"):
        if not (ROOT / script).is_file():
            failures.append("missing documented entrypoint: " + script)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"PASS: {len(PUBLIC)} documentation pages; local links, anchors, JSON and shell examples; README {words} words")
    return 0


if __name__ == "__main__":
    sys.exit(main())
