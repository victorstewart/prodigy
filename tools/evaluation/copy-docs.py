#!/usr/bin/env python3
"""Include the local files referenced by the bundle's Markdown documentation."""

from pathlib import Path
import re
import shutil
import sys
from urllib.parse import unquote, urlsplit

source, destination = (Path(value).resolve(strict=True) for value in sys.argv[1:])
pending = list(destination.rglob("*.md"))
seen = set()
while pending:
    page = pending.pop()
    if page in seen:
        continue
    seen.add(page)
    text = re.sub(r"```[^\n]*\n.*?```", "", page.read_text(), flags=re.S)
    links = re.findall(r"\]\(([^)]+)\)", text)
    links += re.findall(r'<(?:img|a)\b[^>]*(?:src|href)="([^"]+)"', text)
    for link in links:
        url = urlsplit(link.strip().split(' "', 1)[0].strip("<>"))
        if url.scheme or not url.path or link.startswith("//"):
            continue
        target = (page.parent / unquote(url.path)).resolve()
        if not target.is_relative_to(destination):
            raise ValueError(f"Documentation link escapes bundle: {page}: {link}")
        original = source / target.relative_to(destination)
        if not original.exists():
            raise ValueError(f"Documentation link is missing: {page}: {link}")
        originals = list(original.rglob("*.md")) if original.is_dir() else [original]
        target.mkdir(parents=True, exist_ok=True) if original.is_dir() else None
        for item in originals:
            copied = destination / item.relative_to(source)
            copied.parent.mkdir(parents=True, exist_ok=True)
            if not copied.exists():
                shutil.copy2(item, copied)
            if copied.suffix == ".md":
                pending.append(copied)
