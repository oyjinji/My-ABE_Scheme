#!/usr/bin/env python3
"""Write SHA-256 checksums for every artifact in one run."""

import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir")
    args = parser.parse_args()
    root = Path(args.run_dir).resolve()
    target = root / "MANIFEST.sha256"
    lines = []
    for path in sorted(x for x in root.rglob("*") if x.is_file() and x != target):
        lines.append("%s  %s" % (
            hashlib.sha256(path.read_bytes()).hexdigest(), path.relative_to(root)
        ))
    target.write_text("\n".join(lines) + "\n")
    print("MANIFEST_PASS", len(lines))


if __name__ == "__main__":
    main()
