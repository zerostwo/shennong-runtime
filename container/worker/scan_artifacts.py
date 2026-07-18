#!/usr/bin/env python3
"""Read-only, networkless scanner run by the daemon after a Job exits."""

import glob
import hashlib
import json
import mimetypes
import os
import pathlib
import stat
import sys
import uuid


ALLOWED_KINDS = {
    "figure",
    "image",
    "table",
    "report",
    "notebook",
    "script",
    "dataset_subset",
    "archive",
    "other",
}


def validate_rule(rule: object) -> tuple[str, str]:
    if not isinstance(rule, dict) or set(rule) != {"path", "kind"}:
        raise ValueError("artifact rule has unexpected fields")
    pattern = rule["path"]
    kind = rule["kind"]
    if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
        raise ValueError("artifact path pattern is invalid")
    path = pathlib.PurePosixPath(pattern)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact path must remain under /workspace")
    if kind not in ALLOWED_KINDS:
        raise ValueError("artifact kind is invalid")
    return pattern, kind


def reject_symlink_path(workspace: pathlib.Path, relative: pathlib.Path) -> None:
    current = workspace
    for part in relative.parts:
        current = current / part
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise ValueError(f"symlink artifacts are forbidden: {relative}")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    workspace = pathlib.Path("/workspace").resolve(strict=True)
    raw_rules = json.loads(os.environ.get("SHENNONG_ARTIFACT_RULES_JSON", "[]"))
    if not isinstance(raw_rules, list) or len(raw_rules) > 64:
        raise ValueError("artifact rules must be a bounded list")
    max_bytes = int(os.environ["SHENNONG_MAX_ARTIFACT_BYTES"])
    if max_bytes < 1024:
        raise ValueError("artifact byte limit is invalid")

    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    total = 0
    visited = 0
    for raw_rule in raw_rules:
        pattern, kind = validate_rule(raw_rule)
        for value in glob.iglob(pattern, root_dir=workspace, recursive=True, include_hidden=True):
            visited += 1
            if visited > 4096:
                raise ValueError("artifact scan matched more than 4096 paths")
            relative = pathlib.Path(value)
            if str(relative) in seen:
                continue
            reject_symlink_path(workspace, relative)
            candidate = (workspace / relative).resolve(strict=True)
            candidate.relative_to(workspace)
            if not candidate.is_file():
                continue
            size = candidate.stat().st_size
            total += size
            if total > max_bytes:
                raise ValueError("artifact manifest exceeds max_artifact_bytes")
            seen.add(str(relative))
            entries.append(
                {
                    "id": str(uuid.uuid4()),
                    "relative_path": relative.as_posix(),
                    "kind": kind,
                    "size_bytes": size,
                    "sha256": sha256(candidate),
                    "media_type": mimetypes.guess_type(candidate.name)[0],
                }
            )
            if len(entries) > 256:
                raise ValueError("artifact manifest contains more than 256 files")
    json.dump(entries, sys.stdout, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # scanner errors must fail the Job finalization
        print(str(error), file=sys.stderr)
        raise SystemExit(70) from error
