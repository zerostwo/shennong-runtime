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


def validate_rule(rule: object) -> tuple[str, str, str | None]:
    if not isinstance(rule, dict) or not {"path", "kind"} <= set(rule):
        raise ValueError("artifact rule has unexpected fields")
    if set(rule) - {"path", "kind", "role", "required"}:
        raise ValueError("artifact rule has unexpected fields")
    pattern = rule["path"]
    kind = rule["kind"]
    role = rule.get("role")
    required = rule.get("required", False)
    if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
        raise ValueError("artifact path pattern is invalid")
    path = pathlib.PurePosixPath(pattern)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact path must remain under /workspace")
    if kind not in ALLOWED_KINDS:
        raise ValueError("artifact kind is invalid")
    if role is not None and (
        not isinstance(role, str)
        or not role
        or len(role) > 64
        or any(not (character.isalnum() or character in "-_.") for character in role)
    ):
        raise ValueError("artifact role is invalid")
    if not isinstance(required, bool):
        raise ValueError("artifact required flag is invalid")
    return pattern, kind, role


def open_regular(workspace: int, relative: pathlib.Path) -> tuple[int, os.stat_result]:
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"artifact path must remain below /workspace: {relative}")
    directory = os.dup(workspace)
    artifact = None
    try:
        for part in relative.parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        artifact = os.open(
            relative.parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory,
        )
        metadata = os.fstat(artifact)
        if not stat.S_ISREG(metadata.st_mode):
            if stat.S_ISDIR(metadata.st_mode):
                raise IsADirectoryError(f"artifact match is a directory: {relative}")
            raise ValueError(f"artifact must be a regular file: {relative}")
        return artifact, metadata
    except Exception:
        if artifact is not None:
            os.close(artifact)
        raise
    finally:
        os.close(directory)


def sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    with os.fdopen(os.dup(descriptor), "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    workspace_path = pathlib.Path("/workspace")
    workspace = os.open(workspace_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
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
    try:
        for raw_rule in raw_rules:
            pattern, kind, role = validate_rule(raw_rule)
            for value in glob.iglob(
                pattern,
                root_dir=workspace_path,
                recursive=True,
                include_hidden=True,
            ):
                visited += 1
                if visited > 4096:
                    raise ValueError("artifact scan matched more than 4096 paths")
                relative = pathlib.Path(value)
                if str(relative) in seen:
                    continue
                descriptor = None
                try:
                    descriptor, metadata = open_regular(workspace, relative)
                except IsADirectoryError:
                    continue
                try:
                    size = metadata.st_size
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
                            "sha256": sha256(descriptor),
                            "media_type": mimetypes.guess_type(relative.name)[0],
                            "role": role,
                        }
                    )
                    if len(entries) > 256:
                        raise ValueError("artifact manifest contains more than 256 files")
                finally:
                    os.close(descriptor)
    finally:
        os.close(workspace)
    json.dump(entries, sys.stdout, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # scanner errors must fail the Job finalization
        print(str(error), file=sys.stderr)
        raise SystemExit(70) from error
