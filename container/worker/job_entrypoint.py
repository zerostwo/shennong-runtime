#!/usr/bin/env python3
"""Trusted argv entrypoint. It never invokes a command shell."""

import os
import pathlib
import sys


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("a direct executable argv is required")
    workspace = pathlib.Path("/workspace")
    home = workspace / ".shennong" / "home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chdir(workspace)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
