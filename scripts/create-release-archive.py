#!/usr/bin/env python3
"""Create a byte-stable tar.gz around one prepared release directory."""

from __future__ import annotations

import argparse
import gzip
import pathlib
import tarfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    return parser.parse_args()


def members(root: pathlib.Path) -> list[pathlib.Path]:
    values = [root]
    values.extend(sorted(root.rglob("*"), key=lambda path: path.as_posix()))
    return values


def main() -> None:
    args = parse_args()
    root = args.source.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise SystemExit(f"release source must be a regular directory: {root}")

    output = args.output.resolve()
    if output == root or root in output.parents:
        raise SystemExit("release archive must be outside its source directory")
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("wb") as raw_stream:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=raw_stream,
            mtime=1,
        ) as gzip_stream:
            with tarfile.open(
                fileobj=gzip_stream,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive:
                for path in members(root):
                    if path.is_symlink() or not (path.is_dir() or path.is_file()):
                        raise SystemExit(f"release source has an unsupported entry: {path}")
                    arcname = path.relative_to(root.parent).as_posix()
                    info = archive.gettarinfo(str(path), arcname)
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 1
                    info.pax_headers = {}
                    if path.is_dir():
                        info.mode = 0o755
                        archive.addfile(info)
                    else:
                        info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                        with path.open("rb") as file_stream:
                            archive.addfile(info, file_stream)


if __name__ == "__main__":
    main()
