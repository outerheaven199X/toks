"""Mutation-based tests of the stdlib Windows wheel audit.

Requires TOKS_WHEEL_SAMPLE pointing to a real Windows wheel built from this tree.
"""
import base64
import csv
import hashlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.ci.audit_windows_wheel import AuditError, audit


class WheelAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get("TOKS_WHEEL_SAMPLE"):
            raise RuntimeError("TOKS_WHEEL_SAMPLE must point to a real win_amd64 wheel")
        cls.source = Path(os.environ["TOKS_WHEEL_SAMPLE"]).resolve()
        cls.name = cls.source.name
        with zipfile.ZipFile(cls.source) as z:
            cls.original = {n: z.read(n) for n in z.namelist()}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def mutated(self, changes=None, *, add=None, omit=(), regenerate_record=True):
        contents = {k: v for k, v in self.original.items() if k not in omit}
        contents.update(changes or {})
        contents.update(add or {})
        record = next(k for k in contents if k.endswith(".dist-info/RECORD"))
        if regenerate_record:
            rows = []
            for n, data in contents.items():
                if n == record:
                    rows.append((n, "", ""))
                else:
                    sig = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                    rows.append((n, "sha256=" + sig, str(len(data))))
            stream = io.StringIO()
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerows(rows)
            contents[record] = stream.getvalue().encode()
        target = Path(self.tmp.name) / self.name
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for n, data in contents.items():
                z.writestr(n, data)
        return target

    def test_valid_built_wheel(self):
        report = audit(self.source)
        self.assertGreater(report["files_checked"], 9)
        self.assertTrue(any(x.lower().startswith("python3") for x in report["imports"]))
        self.assertTrue(report["extension_sha256"])

    def test_record_digest_tamper(self):
        pyd = next(n for n in self.original if n.endswith(".pyd"))
        changed = self.original[pyd][:-1] + bytes([self.original[pyd][-1] ^ 1])
        with self.assertRaisesRegex(AuditError, "RECORD hash"):
            audit(self.mutated({pyd: changed}, regenerate_record=False))

    def test_unexpected_native_dependency_even_with_valid_record(self):
        pyd = next(n for n in self.original if n.endswith(".pyd"))
        b = self.original[pyd]
        self.assertIn(b"KERNEL32.dll", b)
        evil = b.replace(b"KERNEL32.dll", b"MALWARE1.dll", 1)
        with self.assertRaisesRegex(AuditError, "unexpected PE import"):
            audit(self.mutated({pyd: evil}))

    def test_extension_cannot_be_replaced_by_arbitrary_bytes(self):
        pyd = next(n for n in self.original if n.endswith(".pyd"))
        with self.assertRaisesRegex(AuditError, "missing DOS header"):
            audit(self.mutated({pyd: b"not a Windows DLL"}))

    def test_hidden_library_and_pth_are_rejected(self):
        for n in ("toks/toks.dll", "toks/trampoline.pth"):
            with self.subTest(name=n), self.assertRaises(AuditError):
                audit(self.mutated(add={n: b"bad"}))

    def test_required_license_cannot_be_removed(self):
        n = next(n for n in self.original if n.endswith("/licenses/LICENSE"))
        with self.assertRaisesRegex(AuditError, "missing license"):
            audit(self.mutated(omit={n}))

    def test_wrong_abi_filename_rejected(self):
        p = Path(self.tmp.name) / self.name.replace("win_amd64", "win32")
        p.write_bytes(self.source.read_bytes())
        with self.assertRaisesRegex(AuditError, "unexpected wheel name"):
            audit(p)

    def test_extra_archive_file_rejected(self):
        with self.assertRaisesRegex(AuditError, "unexpected wheel member"):
            audit(self.mutated(add={"thirdparty/hello.py": b"x"}))


if __name__ == "__main__":
    unittest.main()
