import os
import pathlib
import tempfile
import unittest

import scan_artifacts


class ScannerOpenTests(unittest.TestCase):
    def test_regular_file_is_opened_relative_to_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            (workspace / "results").mkdir()
            payload = b"feature,value\ngene1,1\n"
            (workspace / "results" / "table.csv").write_bytes(payload)
            root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
            try:
                descriptor, metadata = scan_artifacts.open_regular(
                    root, pathlib.Path("results/table.csv")
                )
                try:
                    self.assertEqual(metadata.st_size, len(payload))
                    self.assertEqual(
                        scan_artifacts.sha256(descriptor),
                        "d70dcfa7a2460fd238af27d9f81f9bf77c8bf756136b2d3e4bf9053394820e09",
                    )
                finally:
                    os.close(descriptor)
            finally:
                os.close(root)

    def test_symlink_components_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            target = workspace / "target"
            target.mkdir()
            (target / "artifact.txt").write_text("not allowed", encoding="utf-8")
            (workspace / "link").symlink_to(target, target_is_directory=True)
            (workspace / "final-link").symlink_to(target / "artifact.txt")
            root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(OSError):
                    scan_artifacts.open_regular(
                        root, pathlib.Path("link/artifact.txt")
                    )
                with self.assertRaises(OSError):
                    scan_artifacts.open_regular(root, pathlib.Path("final-link"))
            finally:
                os.close(root)

    def test_directory_matches_are_identified_for_the_scanner_to_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            (workspace / "results").mkdir()
            root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(IsADirectoryError):
                    scan_artifacts.open_regular(root, pathlib.Path("results"))
            finally:
                os.close(root)

    def test_parent_components_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(ValueError):
                    scan_artifacts.open_regular(root, pathlib.Path("../outside"))
            finally:
                os.close(root)


if __name__ == "__main__":
    unittest.main()
