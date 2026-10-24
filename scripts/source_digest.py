#!/usr/bin/env python3
"""Print the canonical source-tree digest used by sources.toml."""

import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
paths: list[Path] = []
for path in root.rglob("*"):
    relative = path.relative_to(root)
    if relative.parts[0] in {".git", "target"}:
        continue
    if path.is_symlink():
        raise SystemExit(f"unsupported symlink: {relative}")
    if path.is_file() and relative != Path("sources.toml"):
        paths.append(relative)
    elif not path.is_dir() and not path.is_file():
        raise SystemExit(f"unsupported file type: {relative}")

digest = hashlib.sha256(b"peritus-module-source-tree-v1\0exclude:sources.toml\0")
for relative in sorted(paths):
    name = relative.as_posix().encode()
    data = (root / relative).read_bytes()
    digest.update(len(name).to_bytes(8, "big"))
    digest.update(name)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
print(digest.hexdigest())
