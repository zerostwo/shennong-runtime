import base64
import errno
import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("read_artifact.py")
SPEC = importlib.util.spec_from_file_location("read_artifact", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class ArtifactReaderTests(unittest.TestCase):
    def test_opens_a_regular_file_relative_to_the_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "results").mkdir()
            (root / "results" / "table.csv").write_bytes(b"feature,value\n")
            descriptor = reader.open_artifact(
                ["results", "table.csv"],
                workspace=directory,
            )
            try:
                self.assertEqual(os.read(descriptor, 1024), b"feature,value\n")
            finally:
                os.close(descriptor)

    def test_rejects_final_and_intermediate_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            outside = root / "outside.txt"
            outside.write_text("outside")
            (root / "final-link").symlink_to(outside)
            with self.assertRaises(OSError) as final_error:
                reader.open_artifact(["final-link"], workspace=directory)
            self.assertIn(final_error.exception.errno, {errno.ELOOP, errno.ENOTDIR})

            real = root / "real"
            real.mkdir()
            (real / "value.txt").write_text("value")
            (root / "directory-link").symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError) as directory_error:
                reader.open_artifact(
                    ["directory-link", "value.txt"],
                    workspace=directory,
                )
            self.assertIn(directory_error.exception.errno, {errno.ELOOP, errno.ENOTDIR})

    def test_request_rejects_parent_paths_and_oversized_reads(self) -> None:
        base = {
            "path": "../outside",
            "size_bytes": 1,
            "sha256": "a" * 64,
            "max_bytes": 1,
        }
        with mock.patch.dict(
            os.environ,
            {"SHENNONG_ARTIFACT_READ_JSON": __import__("json").dumps(base)},
        ):
            with self.assertRaisesRegex(ValueError, "remain below"):
                reader.request()

        base["path"] = "results/value"
        base["size_bytes"] = 2
        with mock.patch.dict(
            os.environ,
            {"SHENNONG_ARTIFACT_READ_JSON": __import__("json").dumps(base)},
        ):
            with self.assertRaisesRegex(ValueError, "byte bounds"):
                reader.request()

    def test_streams_exact_bytes_and_rejects_digest_mismatch(self) -> None:
        payload = b"\x00binary artifact\n"
        with tempfile.TemporaryDirectory() as directory:
            source_path = pathlib.Path(directory) / "source"
            output_path = pathlib.Path(directory) / "output"
            source_path.write_bytes(payload)
            source = os.open(source_path, os.O_RDONLY)
            output = os.open(output_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                reader.stream_artifact(
                    source,
                    len(payload),
                    hashlib.sha256(payload).hexdigest(),
                    len(payload),
                    output,
                )
            finally:
                os.close(output)
                os.close(source)
            self.assertEqual(base64.b64decode(output_path.read_bytes()), payload)

            source = os.open(source_path, os.O_RDONLY)
            output = os.open(output_path, os.O_WRONLY | os.O_TRUNC)
            try:
                with self.assertRaisesRegex(ValueError, "no longer match"):
                    reader.stream_artifact(
                        source,
                        len(payload),
                        "0" * 64,
                        len(payload),
                        output,
                    )
            finally:
                os.close(output)
                os.close(source)


if __name__ == "__main__":
    unittest.main()
