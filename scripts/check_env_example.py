#!/usr/bin/env python3
"""Fail when config or compose reads a variable that .env.example does not list."""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def settings_fields() -> list[str]:
    tree = ast.parse((ROOT / "app/core/config.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Settings":
            names = []
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    names.append(stmt.target.id)
            if not names:
                raise SystemExit("Settings has no fields")
            return names
    raise SystemExit("Settings class not found")


def example_keys() -> set[str]:
    keys = set()
    for raw in (ROOT / ".env.example").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0].strip())
    return keys


def referenced(path: Path, pattern: str) -> set[str]:
    return set(re.findall(pattern, path.read_text()))


def main() -> int:
    needed = set(settings_fields())
    needed |= referenced(ROOT / "docker-compose.yml", r"\$\{([A-Z][A-Z0-9_]*)")
    needed |= referenced(ROOT / "Caddyfile", r"\{\$([A-Z][A-Z0-9_]*)")
    missing = sorted(needed - example_keys())
    if missing:
        print("Missing from .env.example:")
        for name in missing:
            print(f"  {name}")
        return 1
    print(f".env.example documents {len(needed)} variables")
    return 0


if __name__ == "__main__":
    sys.exit(main())
