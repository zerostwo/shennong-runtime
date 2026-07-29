#!/usr/bin/env python3
"""Stream one previously scanned artifact through bounded helper stdout.

The helper runs networkless with /workspace mounted read-only. Every path
component is opened relative to an already-open directory with O_NOFOLLOW, so a
workspace symlink or rename race cannot redirect the read into the image root.
"""

import hashlib
import json
import os
import pathlib
import stat


CHUNK_BYTES = 1024 * 1024
def request() -> tuple[list[str], int, str, int]:
    value = json.loads(os.environ["SHENNONG_ARTIFACT_READ_JSON"])
    if not isinstance(value, dict) or set(value) != {
        "path",
        "size_bytes",
        "sha256",
        "max_bytes",
    }:
        raise ValueError("artifact read request has unexpected fields")
    path = value["path"]
    expected_size = value["size_bytes"]
    expected_sha256 = value["sha256"]
    max_bytes = value["max_bytes"]
    if not isinstance(path, str) or not path or len(path) > 512 or "\\" in path:
        raise ValueError("artifact read path is invalid")
    pure = pathlib.PurePosixPath(path)
    parts = list(pure.parts)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("artifact read path must remain below /workspace")
    if (
        not isinstance(expected_size, int)
        or not isinstance(max_bytes, int)
        or expected_size < 0
        or max_bytes < 0
        or expected_size > max_bytes
    ):
        raise ValueError("artifact read byte bounds are invalid")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError("artifact read sha256 is invalid")
    return parts, expected_size, expected_sha256, max_bytes


def open_artifact(parts: list[str], workspace: str = "/workspace") -> int:
    directory = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def stream_artifact(
    source: int,
    expected_size: int,
    expected_sha256: str,
    max_bytes: int,
    output: int = 1,
) -> None:
    digest = hashlib.sha256()
    copied = 0
    while chunk := os.read(source, CHUNK_BYTES):
        copied += len(chunk)
        if copied > max_bytes:
            raise ValueError("artifact exceeded the bounded read limit")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(output, view)
            view = view[written:]
    if copied != expected_size or digest.hexdigest() != expected_sha256:
        raise ValueError("artifact bytes no longer match the validated manifest")


def main() -> None:
    parts, expected_size, expected_sha256, max_bytes = request()
    source = open_artifact(parts)
    try:
        metadata = os.fstat(source)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("artifact read source must be a regular file")
        if metadata.st_size != expected_size or metadata.st_size > max_bytes:
            raise ValueError("artifact size changed after manifest validation")
        stream_artifact(source, expected_size, expected_sha256, max_bytes)
    finally:
        os.close(source)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error)) from error
