import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from qim import run


def tar_bytes(members):
    """members: (TarInfo, data or None)"""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, data in members:
            if data is not None:
                member.size = len(data)
            archive.addfile(member, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def entry(name, kind=tarfile.REGTYPE, **attributes):
    member = tarfile.TarInfo(name)
    member.type = kind
    for key, value in attributes.items():
        setattr(member, key, value)
    return member


class InputTarTest(unittest.TestCase):
    def test_contains_init_config_and_nul_separated_argv(self):
        data = run.input_tar(["sh", "-c", "echo 'a b'"], "qim", 60)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive}
            modes = {member.name: member.mode for member in archive.getmembers()}
        self.assertEqual(set(files), {"init", "config", "argv"})
        self.assertEqual(files["argv"], b"sh\0-c\0echo 'a b'\0")
        self.assertIn(b"QIM_USER=qim\n", files["config"])
        self.assertIn(b"QIM_TIMEOUT=60\n", files["config"])
        self.assertEqual(modes["init"], 0o755)

    def test_root_user_is_an_empty_value(self):
        data = run.input_tar(["true"], None, 60)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            config = archive.extractfile("config").read()
        self.assertIn(b"QIM_USER=''\n", config)


class ReadOutputTest(unittest.TestCase):
    def read(self, members):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "raw").write_bytes(tar_bytes(members) + b"\0" * 4096)
        output = root / "out"
        output.mkdir()
        run.read_output(root / "raw", output)
        return output

    def test_known_meta_files_are_extracted_and_upper_is_kept_as_a_tar(self):
        output = self.read([
            (entry("meta", tarfile.DIRTYPE), None),
            (entry("meta/exit_code"), b"3\n"),
            (entry("meta/command.log"), b"hello\n"),
            (entry("upper", tarfile.DIRTYPE), None),
            (entry("upper/etc/new"), b"x"),
            (entry("upper/etc/gone", tarfile.CHRTYPE, devmajor=0, devminor=0), None),
        ])
        self.assertEqual((output / "meta/exit_code").read_bytes(), b"3\n")
        self.assertEqual((output / "meta/command.log").read_bytes(), b"hello\n")
        with tarfile.open(output / "upper.tar") as upper:
            members = {member.name: member for member in upper.getmembers()}
            self.assertEqual(upper.extractfile("upper/etc/new").read(), b"x")
        self.assertEqual(set(members), {"upper", "upper/etc/new", "upper/etc/gone"})
        self.assertTrue(members["upper/etc/gone"].ischr())

    def test_nothing_else_reaches_the_host_filesystem(self):
        output = self.read([
            (entry("meta/exit_code", tarfile.SYMTYPE, linkname="/etc/passwd"), None),
            (entry("meta/other"), b"x"),
            (entry("../escape"), b"x"),
            (entry("/abs"), b"x"),
            (entry("upperfoo/x"), b"x"),
        ])
        self.assertEqual(sorted(path.name for path in output.rglob("*")), ["meta", "upper.tar"])
        self.assertEqual(list((output / "meta").iterdir()), [])
        with tarfile.open(output / "upper.tar") as upper:
            self.assertEqual(upper.getmembers(), [])


if __name__ == "__main__":
    unittest.main()
