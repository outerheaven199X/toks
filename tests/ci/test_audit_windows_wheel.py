"""Mutation-based tests of the no-dependencies Windows wheel audit.

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
from tools.ci.audit_windows_wheel import AuditError, audit, source_pins, verify_source_git


class WheelAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('TOKS_WHEEL_SAMPLE'):
            raise RuntimeError('TOKS_WHEEL_SAMPLE must point to a real win_amd64 wheel')
        cls.source = Path(os.environ['TOKS_WHEEL_SAMPLE']).resolve()
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
        record = next(k for k in contents if k.endswith('.dist-info/RECORD'))
        if regenerate_record:
            rows = []
            for n, data in contents.items():
                if n == record:
                    rows.append((n, '', ''))
                else:
                    sig = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                    rows.append((n, 'sha256=' + sig, str(len(data))))
            stream = io.StringIO()
            writer = csv.writer(stream, lineterminator='\n')
            writer.writerows(rows)
            contents[record] = stream.getvalue().encode()
        target = Path(self.tmp.name) / self.name
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for n, data in contents.items():
                z.writestr(n, data)
        return target

    def _write_deflate_slack_case(self, suffix: bytes):
        """Construct a CRC-valid ZIP whose top_level.txt stream ends before its local data ends."""
        import struct
        import zlib
        items = zipfile.ZipFile(self.source).infolist()
        output, directory = bytearray(), bytearray()
        for info in items:
            contents = self.original[info.filename]
            name = info.filename.encode("utf-8")
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            compressed = compressor.compress(contents) + compressor.flush()
            if info.filename.endswith("top_level.txt"):
                compressed += suffix
            crc = zlib.crc32(contents)
            offset = len(output)
            output += (struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 8, 0,
                                   0x21, crc, len(compressed), len(contents),
                                   len(name), 0) + name + compressed)
            directory += (struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 20,
                                      20, 0, 8, 0, 0x21, crc, len(compressed),
                                      len(contents), len(name), 0, 0, 0, 0,
                                      info.external_attr, offset) + name)
        cd_off = len(output)
        output += directory
        output += struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(items),
                              len(items), len(directory), cd_off, 0)
        target = Path(self.tmp.name) / self.name
        target.write_bytes(output)
        return target

    def test_reviewer_deflate_slack_pth_rejected_with_valid_crc_and_record(self):
        import struct
        import zlib
        hidden_name = b"zz_slack.pth"
        hidden_data = b"import sys; sys.stderr.write('SLACK PTH EXECUTED\\n')\n"
        hidden = (struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0,
                              0x21, zlib.crc32(hidden_data), len(hidden_data),
                              len(hidden_data), len(hidden_name), 0)
                  + hidden_name + hidden_data)
        target = self._write_deflate_slack_case(hidden)
        with zipfile.ZipFile(target) as archive:
            self.assertIsNone(archive.testzip())
            self.assertNotIn("zz_slack.pth", archive.namelist())
        with self.assertRaisesRegex(AuditError, "ZIP deflate stream has trailing compressed bytes"):
            audit(target)

    def test_even_nonexecutable_deflate_slack_bytes_are_rejected(self):
        target = self._write_deflate_slack_case(b"unaccounted-trailing-bytes")
        with self.assertRaisesRegex(AuditError, "ZIP deflate stream has trailing compressed bytes"):
            audit(target)

    def test_reviewer_orphan_local_pth_rejected_even_when_zipfile_cannot_list_it(self):
        import struct
        import zlib
        raw = self.source.read_bytes()
        eocd = raw.rfind(b"PK\x05\x06")
        cd_off = struct.unpack_from("<I", raw, eocd + 16)[0]
        name = b"zz_smuggled.pth"
        payload = b"import sys; sys.stderr.write('unexpected\\n')\n"
        crc = zlib.crc32(payload)
        orphan = struct.pack("<IHHHHHIIIHH", 0x04034b50, 20, 0, 0, 0, 0x21,
                             crc, len(payload), len(payload), len(name), 0) + name + payload
        mutated = bytearray(raw[:cd_off] + orphan + raw[cd_off:])
        later = mutated.rfind(b"PK\x05\x06")
        struct.pack_into("<I", mutated, later + 16, cd_off + len(orphan))
        target = Path(self.tmp.name) / self.name
        target.write_bytes(mutated)
        with zipfile.ZipFile(target) as z:
            self.assertNotIn(name.decode(), z.namelist())
        with self.assertRaisesRegex(AuditError, "ZIP has an unindexed local member"):
            audit(target)

    def test_reviewer_nonempty_zip_comment_rejected(self):
        target = self.mutated()
        with zipfile.ZipFile(target, "a") as z:
            z.comment = b"#" * 65535
        with self.assertRaisesRegex(AuditError, "ZIP has unaccounted trailer"):
            audit(target)

    def test_archive_prefix_trailer_and_junk_rejected(self):
        raw = self.source.read_bytes()
        for payload in (b"not-a-wheel-prefix" + raw, raw + b"trailer-ignored-by-zipfile"):
            target = Path(self.tmp.name) / self.name
            target.write_bytes(payload)
            with self.assertRaises(AuditError):
                audit(target)

    def test_reordered_uncompressed_zip_keeps_exact_members_valid(self):
        target = Path(self.tmp.name) / self.name
        with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as z:
            for name in reversed(list(self.original)):
                z.writestr(name, self.original[name])
        self.assertEqual(audit(target)['native_normalized_sha256'],
                         audit(self.source)['native_normalized_sha256'])

    def test_reviewer_alternate_record_csv_quoting_keeps_semantics(self):
        record = next(k for k in self.original if k.endswith('/RECORD'))
        s = io.StringIO()
        writer = csv.writer(s, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
        for name, data in self.original.items():
            if name == record:
                writer.writerow((name, "", ""))
            else:
                digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                writer.writerow((name, "sha256=" + digest, len(data)))
        target = self.mutated({record: s.getvalue().encode("utf-8")}, regenerate_record=False)
        self.assertEqual(audit(target)['git_blob_members_checked'], 8)

    def test_valid_built_wheel(self):
        report = audit(self.source)
        self.assertGreater(report['files_checked'], 9)
        self.assertTrue(any(x.lower().startswith('python3') for x in report['imports']))
        self.assertTrue(report['extension_sha256'])

    def test_record_digest_tamper(self):
        pyd = next(n for n in self.original if n.endswith('.pyd'))
        changed = self.original[pyd][:-1] + bytes([self.original[pyd][-1] ^ 1])
        with self.assertRaisesRegex(AuditError, 'RECORD hash'):
            audit(self.mutated({pyd: changed}, regenerate_record=False))

    def test_unexpected_native_dependency_even_with_valid_record(self):
        pyd = next(n for n in self.original if n.endswith('.pyd'))
        b = self.original[pyd]
        self.assertIn(b'KERNEL32.dll', b)
        evil = b.replace(b'KERNEL32.dll', b'MALWARE1.dll', 1)
        with self.assertRaisesRegex(AuditError, 'unexpected PE import'):
            audit(self.mutated({pyd: evil}))

    def test_non_python_export_rejected_with_updated_record(self):
        pyd = next(n for n in self.original if n.endswith(".pyd"))
        self.assertIn(b"PyInit__toks", self.original[pyd])
        evil = self.original[pyd].replace(b"PyInit__toks", b"PyInit__evil", 1)
        with self.assertRaisesRegex(AuditError, "wrong or leaked PE export"):
            audit(self.mutated({pyd: evil}))

    def test_delay_import_directory_is_refused(self):
        import struct
        pyd = next(n for n in self.original if n.endswith(".pyd"))
        binary = bytearray(self.original[pyd])
        pe = struct.unpack_from("<I", binary, 0x3C)[0]
        opt = pe + 24
        struct.pack_into("<II", binary, opt + 112 + 8 * 13, 1, 32)
        with self.assertRaisesRegex(AuditError, "delay-import"):
            audit(self.mutated({pyd: bytes(binary)}))

    def test_forged_metadata_header_is_rejected(self):
        meta = next(n for n in self.original if n.endswith(".dist-info/METADATA"))
        evil = self.original[meta].replace(b"Name: toks\r\n", b"Name: malicious\r\n", 1)
        with self.assertRaisesRegex(AuditError, "invalid METADATA Name"):
            audit(self.mutated({meta: evil}))

    def test_unreviewed_python_module_not_in_allowlist(self):
        with self.assertRaisesRegex(AuditError, "unexpected wheel member"):
            audit(self.mutated(add={"toks/sidecar.py": b"print(1)"}))

    def test_review_c1_injected_init_code_rejected_with_regenerated_record(self):
        name = 'toks/__init__.py'
        payload = (b'import ctypes, os\n'
                   b'try: ctypes.WinDLL(os.path.join(os.path.dirname(__file__), "..", "evil.dll"))\n'
                   b'except Exception: pass\n')
        with self.assertRaisesRegex(AuditError, "source-pinned file differs from Git"):
            audit(self.mutated({name: payload + self.original[name]}))

    def test_review_c1_altered_vocab_code_rejected(self):
        name = 'toks/_vocab.py'
        with self.assertRaisesRegex(AuditError, "source-pinned file differs from Git"):
            audit(self.mutated({name: self.original[name] + b"\nexec('pass')\n"}))

    def test_review_c2_requires_dist_rejected_with_regenerated_record(self):
        name = next(n for n in self.original if n.endswith('/METADATA'))
        raw = self.original[name]
        for dependency in (b'Requires-Dist: totally-not-malware>=0\n',
                           b'requires-dist: utterly-fake-package; python_version>="3.10"\n'):
            with self.subTest(dependency=dependency):
                changed = raw.replace(b'License-Expression:', dependency + b'License-Expression:', 1)
                with self.assertRaisesRegex(AuditError, "disallowed METADATA field"):
                    audit(self.mutated({name: changed}))

    def test_review_c3_c4_duplicate_wheel_fields_rejected(self):
        name = next(n for n in self.original if n.endswith('/WHEEL'))
        for injected in (b'Tag: py3-none-any\n', b'Root-Is-Purelib: true\n'):
            with self.subTest(injected=injected):
                with self.assertRaisesRegex(AuditError, "duplicate WHEEL field"):
                    audit(self.mutated({name: self.original[name].rstrip() + b"\n" + injected}))

    def test_review_c5_invalid_purelib_substring_rejected(self):
        name = next(n for n in self.original if n.endswith('/WHEEL'))
        changed = self.original[name].replace(b'Root-Is-Purelib: false', b'Root-Is-Purelib: falsey')
        self.assertNotEqual(changed, self.original[name])
        with self.assertRaisesRegex(AuditError, 'invalid WHEEL Root-Is-Purelib'):
            audit(self.mutated({name: changed}))

    def test_nonstandard_metadata_fields_rejected(self):
        name = next(n for n in self.original if n.endswith('/METADATA'))
        for field in (b'Provides-Extra: fake\n', b'Requires-External: malware\n',
                      b'Obsoletes-Dist: innocent-package\n', b'Project-URL: Fake, https://example.com\n'):
            with self.subTest(field=field):
                with self.assertRaisesRegex(AuditError, 'disallowed METADATA field'):
                    audit(self.mutated({name: self.original[name].replace(b'License-Expression:', field + b'License-Expression:', 1)}))

    def test_unknown_wheel_field_rejected(self):
        name = next(n for n in self.original if n.endswith('/WHEEL'))
        with self.assertRaisesRegex(AuditError, 'disallowed WHEEL field'):
            audit(self.mutated({name: self.original[name].rstrip() + b"\nUnreviewed: yes\n"}))

    def test_pe_unaligned_pointer_to_raw_data_rejected(self):
        import struct
        name = next(n for n in self.original if n.endswith('.pyd'))
        binary = bytearray(self.original[name])
        pe = struct.unpack_from('<I', binary, 0x3C)[0]
        opt = pe + 24
        sections_start = opt + struct.unpack_from('<H', binary, pe + 20)[0]
        raw = struct.unpack_from('<I', binary, sections_start + 20)[0]
        self.assertEqual(raw % struct.unpack_from('<I', binary, opt + 36)[0], 0)
        struct.pack_into('<I', binary, sections_start + 20, raw + 1)
        with self.assertRaisesRegex(AuditError, 'misaligned PE section'):
            audit(self.mutated({name: bytes(binary)}))

    def test_local_pins_cover_expected_contents(self):
        pins = source_pins()
        self.assertEqual(pins['source_commit'], 'ca80a3ed4a45fdabd934f5b5ff818ac3efc0f3e9')
        self.assertEqual(pins['repository'], 'outerheaven199X/toks')
        self.assertEqual(pins['upstream_repository'], 'actual-computer/toks')
        self.assertEqual(len(pins['files']), 8)
        self.assertIn('toks/__init__.py', pins['files'])
        report = audit(self.source)
        self.assertEqual(report['git_blob_members_checked'], 8)
        self.assertEqual(report['source_commit'], pins['source_commit'])

    @unittest.skipUnless(os.environ.get('TOKS_SOURCE_REPO'), 'TOKS_SOURCE_REPO not supplied for Git verification')
    def test_source_pins_match_actual_git_commit(self):
        verify_source_git(Path(os.environ['TOKS_SOURCE_REPO']), source_pins())

    def test_native_text_tamper_rejected_even_with_matching_import_export_and_record(self):
        import struct
        name = next(n for n in self.original if n.endswith('.pyd'))
        binary = bytearray(self.original[name])
        pe = struct.unpack_from('<I', binary, 0x3C)[0]
        opt = pe + 24
        first_section = opt + struct.unpack_from('<H', binary, pe + 20)[0]
        raw = struct.unpack_from('<I', binary, first_section + 20)[0]
        self.assertEqual(binary[first_section:first_section + 5], b'.text')
        binary[raw + 256] ^= 1
        with self.assertRaisesRegex(AuditError, 'native extension fingerprint differs'):
            audit(self.mutated({name: bytes(binary)}))

    def test_identical_compiled_code_with_new_linker_timestamps_is_accepted(self):
        import struct
        name = next(n for n in self.original if n.endswith('.pyd'))
        binary = bytearray(self.original[name])
        pe = struct.unpack_from('<I', binary, 0x3C)[0]
        opt = pe + 24
        sections = struct.unpack_from('<H', binary, pe + 6)[0]
        table = opt + struct.unpack_from('<H', binary, pe + 20)[0]
        debug_rva = struct.unpack_from('<I', binary, opt + 112 + 6 * 8)[0]
        debug_raw = None
        for i in range(sections):
            off = table + 40 * i
            vs, va, sz, raw = struct.unpack_from('<IIII', binary, off + 8)
            if va <= debug_rva < va + max(vs, sz):
                self.assertIsNone(debug_raw)
                debug_raw = raw + debug_rva - va
        self.assertIsNotNone(debug_raw)
        old = struct.unpack_from('<I', binary, pe + 8)[0]
        stamp = (old + 873) & 0xffffffff
        struct.pack_into('<I', binary, pe + 8, stamp)
        struct.pack_into('<I', binary, debug_raw + 4, stamp)
        report = audit(self.mutated({name: bytes(binary)}))
        self.assertEqual(report['native_normalized_sha256'],
                         audit(self.source)['native_normalized_sha256'])

    def test_metadata_body_mutation_rejected_without_new_headers(self):
        name = next(n for n in self.original if n.endswith('/METADATA'))
        original = self.original[name]
        with self.assertRaisesRegex(AuditError, 'unreviewed dist-info bytes: METADATA'):
            audit(self.mutated({name: original + b"\nHarmless-looking new package description\n"}))

    def test_generator_change_and_top_level_mutation_rejected(self):
        name = next(n for n in self.original if n.endswith('/WHEEL'))
        original = self.original[name]
        import re
        self.assertIn(b'setuptools (', original)
        changed = re.sub(rb'Generator: setuptools \(\d+\.\d+\.\d+\)',
                         b'Generator: setuptools (999.1.0)', original)
        self.assertNotEqual(changed, original)
        with self.assertRaisesRegex(AuditError, 'unreviewed dist-info bytes: WHEEL'):
            audit(self.mutated({name: changed}))
        name = next(n for n in self.original if n.endswith('/top_level.txt'))
        with self.assertRaisesRegex(AuditError, 'unreviewed dist-info bytes: top_level.txt'):
            audit(self.mutated({name: b'toks\nother\n'}))

    def test_inconsistent_linker_timestamps_rejected(self):
        import struct
        name = next(n for n in self.original if n.endswith('.pyd'))
        binary = bytearray(self.original[name])
        pe = struct.unpack_from('<I', binary, 0x3C)[0]
        struct.pack_into('<I', binary, pe + 8, 1)
        with self.assertRaisesRegex(AuditError, 'linker timestamps do not agree'):
            audit(self.mutated({name: bytes(binary)}))

    def test_extension_cannot_be_replaced_by_arbitrary_bytes(self):
        pyd = next(n for n in self.original if n.endswith('.pyd'))
        with self.assertRaisesRegex(AuditError, 'missing DOS header'):
            audit(self.mutated({pyd: b'not a Windows DLL'}))

    def test_hidden_library_and_pth_are_rejected(self):
        for n in ('toks/toks.dll', 'toks/trampoline.pth'):
            with self.subTest(name=n), self.assertRaises(AuditError):
                audit(self.mutated(add={n: b'bad'}))

    def test_required_license_cannot_be_removed(self):
        n = next(n for n in self.original if n.endswith('/licenses/LICENSE'))
        with self.assertRaisesRegex(AuditError, 'missing license'):
            audit(self.mutated(omit={n}))

    def test_wrong_abi_filename_rejected(self):
        p = Path(self.tmp.name) / self.name.replace('win_amd64', 'win32')
        p.write_bytes(self.source.read_bytes())
        with self.assertRaisesRegex(AuditError, 'unexpected wheel name'):
            audit(p)

    def test_extra_archive_file_rejected(self):
        with self.assertRaisesRegex(AuditError, 'unexpected wheel member'):
            audit(self.mutated(add={'thirdparty/hello.py': b'x'}))


if __name__ == '__main__':
    unittest.main()
