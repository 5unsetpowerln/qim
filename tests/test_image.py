import datetime
import os
import tempfile
import unittest
from pathlib import Path

from qim import image


class PacmanConfTest(unittest.TestCase):
    def test_servers_point_to_the_archive_of_the_date(self):
        conf = image.pacman_conf(datetime.date(2026, 11, 8))
        server = "Server = https://archive.archlinux.org/repos/2026/11/08/$repo/os/$arch"
        self.assertIn(f"[core]\n{server}\n", conf)
        self.assertIn(f"[extra]\n{server}\n", conf)

    def test_has_no_extraction_exclusions(self):
        self.assertNotIn("NoExtract", image.pacman_conf(datetime.date(2026, 11, 8)))

    def test_cache_dir_only_when_given(self):
        self.assertNotIn("CacheDir", image.pacman_conf(datetime.date(2026, 11, 8)))
        self.assertIn("CacheDir = /var/cache/qim\n",
                      image.pacman_conf(datetime.date(2026, 11, 8), Path("/var/cache/qim")))


class DefaultDateTest(unittest.TestCase):
    def test_is_the_previous_day(self):
        self.assertEqual(image.default_date(datetime.date(2026, 11, 9)), datetime.date(2026, 11, 8))
        self.assertEqual(image.default_date(datetime.date(2026, 3, 1)), datetime.date(2026, 2, 28))


class ManifestTest(unittest.TestCase):
    def test_lists_files_directories_and_symlinks_sorted_by_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "d").mkdir()
            (root / "d").chmod(0o755)
            (root / "d/f").write_bytes(b"hello\n")
            (root / "d/f").chmod(0o644)
            os.symlink("d/f", root / "l")
            entries = image.manifest(root)
        uid, gid = os.getuid(), os.getgid()
        self.assertEqual(entries, [
            {"path": "/d", "type": "dir", "mode": "0755", "uid": uid, "gid": gid},
            {"path": "/d/f", "type": "file", "mode": "0644", "uid": uid, "gid": gid, "size": 6,
             "sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"},
            {"path": "/l", "type": "symlink", "mode": "0777", "uid": uid, "gid": gid, "target": "d/f"},
        ])


if __name__ == "__main__":
    unittest.main()
