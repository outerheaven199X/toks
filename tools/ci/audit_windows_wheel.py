#!/usr/bin/env python3
"""Fail-closed, stdlib-only audit of toks CPython win_amd64 release candidates.

Checks RECORD integrity, wheel metadata, file layout, PE/x64 import dependencies.
Not a substitute for installing and exercising the wheel on Windows.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import subprocess
from email.parser import Parser
import stat
import struct
import sys
import zlib
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile


class AuditError(ValueError):
    pass


# This is a version-pinned research auditor, not an upstream release workflow or a generic PyPI wheel validator.
# The GitHub source ref is not supplied by the untrusted wheel.
PINNED_SOURCE_COMMIT = "ca80a3ed4a45fdabd934f5b5ff818ac3efc0f3e9"
PINS_FILE = Path(__file__).with_name("windows_wheel_source_pins.json")


def source_pins() -> dict:
    try:
        obj = json.loads(PINS_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"missing/malformed source pin manifest: {exc}") from exc
    need(obj.get("schema") == 1 and obj.get("source_commit") == PINNED_SOURCE_COMMIT,
         "source pin manifest has an unexpected source commit/schema")
    need(obj.get("repository") == "outerheaven199X/toks" and
         obj.get("upstream_repository") == "actual-computer/toks" and
         obj.get("package_version") == "0.3.2",
         "source pin manifest has unexpected fork/upstream/version")
    native = obj.get("native_extension_normalized_sha256")
    need(isinstance(native, dict) and set(native) == {"310", "311", "312", "313", "314"},
         "source pin manifest lacks the five native extension fingerprints")
    need(all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for v in native.values()),
         "malformed native extension fingerprints")
    need(obj.get("native_reference_run_id") == 39089648806,
         "unknown reference build for native extension fingerprints")
    dist = obj.get("dist_info_sha256")
    need(isinstance(dist, dict) and set(dist) == {"METADATA", "WHEEL", "top_level.txt"},
         "missing pinned dist-info hashes")
    need(all(isinstance(dist.get(n), str) and re.fullmatch(r"[a-f0-9]{64}", dist[n])
             for n in ("METADATA", "top_level.txt")), "malformed dist-info hashes")
    need(isinstance(dist["WHEEL"], dict) and set(dist["WHEEL"]) == set(native)
         and all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
                 for v in dist["WHEEL"].values()), "malformed WHEEL hashes")
    files = obj.get("files")
    need(isinstance(files, dict), "source pin manifest has no file list")
    expected = {"toks/__init__.py", "toks/_vocab.py", "toks/_toks.pyi", "toks/py.typed",
                *(f"licenses/{name}" for name in ("LICENSE", "NOTICE", "LICENSING.md", "THIRD_PARTY_NOTICES.md"))}
    need(set(files) == expected, "source pin manifest does not cover the exact source/notice files")
    for name, record in files.items():
        need(isinstance(record, dict) and set(record) == {"sha256", "git_blob_sha1", "git_path"},
             f"invalid source pin entry: {name}")
        need(re.fullmatch(r"[a-f0-9]{64}", record["sha256"]) is not None
             and re.fullmatch(r"[a-f0-9]{40}", record["git_blob_sha1"]) is not None,
             f"invalid source pin hashes: {name}")
        need(record["git_path"] == ("python/" + name if name.startswith("toks/")
                                   else name.removeprefix("licenses/")),
             f"unreviewed pin source path: {name}")
    return obj


def git_blob_id(data: bytes) -> str:
    """Git SHA-1 blob ID (repository's object format), independent of RECORD."""
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\x00" + data).hexdigest()


def verify_source_git(source_root: Path, manifest: dict) -> None:
    """Prove the pinned bytes are actually the immutable named source Git blobs.

    Fails if the checkout lacks the commit; no network fetch or fallback.
    """
    try:
        check = subprocess.run(["git", "-C", str(source_root), "cat-file", "-t", PINNED_SOURCE_COMMIT],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        need(check.stdout.strip() == b"commit", "pinned source object is not a Git commit")
        for name, entry in manifest["files"].items():
            show = subprocess.run(["git", "-C", str(source_root), "show",
                                   f"{PINNED_SOURCE_COMMIT}:{entry['git_path']}"],
                                  check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            raw = show.stdout
            need(hashlib.sha256(raw).hexdigest() == entry["sha256"] and
                 git_blob_id(raw) == entry["git_blob_sha1"],
                 f"source pin differs from Git commit/blob: {name}")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError(f"pinned Git source could not be verified offline: {exc}") from exc


def strict_headers(raw: bytes, required: dict, allowed: set[str], multi: set[str], context: str):
    """Exact parsed metadata headers, no unknown or duplicate security-relevant keys."""
    try:
        decoded = raw.decode("utf-8")
        obj = Parser().parsestr(decoded, headersonly=True)
    except UnicodeError as exc:
        raise AuditError(f"invalid UTF-8 {context}") from exc
    if context == "WHEEL":
        # PEP 427 WHEEL contains headers, not a message body. Metadata, in
        # contrast, has a Markdown body, so this check is deliberately scoped.
        normalized = decoded.replace("\r\n", "\n")
        tail = normalized.partition("\n\n")[2]
        need(not tail.strip(), "WHEEL has unexpected body content after headers")
    keys = [k.lower() for k in obj.keys()]
    unexpected = sorted(set(keys) - {k.lower() for k in allowed})
    need(not unexpected, f"disallowed {context} field(s): {unexpected}")
    for key in keys:
        need(key in {k.lower() for k in multi} or keys.count(key) == 1,
             f"duplicate {context} field: {key}")
    for key, val in required.items():
        need(obj.get_all(key) == [val], f"invalid {context} {key}")
    return obj


def need(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def u16(b: bytes, off: int) -> int:
    need(0 <= off and off + 2 <= len(b), "truncated PE u16")
    return struct.unpack_from("<H", b, off)[0]


def u32(b: bytes, off: int) -> int:
    need(0 <= off and off + 4 <= len(b), "truncated PE u32")
    return struct.unpack_from("<I", b, off)[0]


def pe_imports(b: bytes) -> list[str]:
    """Read PE32+ imports from the binary itself, not external DLL tools."""
    need(len(b) >= 64 and b[:2] == b"MZ", "missing DOS header")
    pe = u32(b, 0x3c)
    need(pe >= 64 and pe + 24 <= len(b) and b[pe:pe + 4] == b"PE\0\0", "bad PE signature")
    machine, sections = u16(b, pe + 4), u16(b, pe + 6)
    need(machine == 0x8664, f"PE machine is not AMD64: {machine:#x}")
    need(0 < sections <= 96, "invalid PE section count")
    need(u16(b, pe + 22) & 0x2000, "PE image is not marked DLL")
    opt_len = u16(b, pe + 20)
    opt = pe + 24
    need(opt_len >= 128 and opt + opt_len <= len(b), "truncated optional header")
    need(u16(b, opt) == 0x20b, "expected PE32+ optional header")
    dirs = u32(b, opt + 108)
    need(dirs >= 2 and opt_len >= 112 + 8 * 2, "no PE import directory")
    imp_rva, imp_size = u32(b, opt + 120), u32(b, opt + 124)
    need(imp_rva > 0 and imp_size >= 20, "empty or malformed PE import directory")
    section_alignment, file_alignment = u32(b, opt + 32), u32(b, opt + 36)
    headers_size = u32(b, opt + 60)
    need(file_alignment >= 512 and file_alignment <= 65536 and (file_alignment & (file_alignment - 1)) == 0,
         "invalid PE FileAlignment")
    need(section_alignment >= file_alignment and section_alignment % file_alignment == 0,
         "invalid PE SectionAlignment")
    need(headers_size >= opt + opt_len - pe and headers_size % file_alignment == 0,
         "invalid PE headers size/alignment")
    section_start = opt + opt_len
    need(section_start + sections * 40 <= len(b), "truncated section table")
    parts = []
    for i in range(sections):
        off = section_start + 40 * i
        vsize, va, rsize, raw = (u32(b, off + k) for k in (8, 12, 16, 20))
        need(va % section_alignment == 0 and (not rsize or (raw % file_alignment == 0 and raw >= headers_size)),
             "misaligned PE section raw pointer / virtual address")
        need(raw + rsize <= len(b), "section exceeds file bounds")
        parts.append((va, max(vsize, rsize), raw, rsize))

    def rva_offset(rva: int) -> int:
        for va, virtual_size, raw, rsize in parts:
            if va <= rva < va + virtual_size:
                delta = rva - va
                need(delta < rsize, f"PE RVA {rva:#x} lands in unbacked virtual memory")
                return raw + delta
        raise AuditError(f"PE RVA {rva:#x} is outside mapped sections")

    def cstring(rva: int) -> str:
        p = rva_offset(rva)
        end = b.find(b"\0", p, min(len(b), p + 261))
        need(end > p, "missing/empty NUL-terminated import name")
        try:
            return b[p:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuditError("import DLL name is not ASCII") from exc

    import_off = rva_offset(imp_rva)
    need(import_off + imp_size <= len(b), "import descriptors exceed file")
    found = []
    count = min(imp_size // 20, 128)
    for i in range(count):
        off = import_off + i * 20
        desc = struct.unpack_from("<IIIII", b, off)
        if desc == (0, 0, 0, 0, 0):
            break
        need(desc[3] > 0, "import descriptor missing DLL name")
        found.append(cstring(desc[3]))
    else:
        raise AuditError("unterminated PE import descriptor array")
    # A delay-load dependency would bypass the ordinary import table; refuse
    # it rather than suggesting all dependencies were inspected.
    if dirs > 13 and opt_len >= 112 + 14 * 8:
        need(u32(b, opt + 112 + 8 * 13) == 0 and u32(b, opt + 116 + 8 * 13) == 0,
             "PE has a delay-import directory that this auditor cannot inspect")
    export_rva, export_size = u32(b, opt + 112), u32(b, opt + 116)
    need(export_rva and export_size >= 40, "missing PE export directory")
    export_off = rva_offset(export_rva)
    need(export_off + 40 <= len(b), "truncated PE export directory")
    funcs, names = u32(b, export_off + 20), u32(b, export_off + 24)
    need(funcs == 1 and names == 1, "extension must export exactly one function")
    export_name_table = rva_offset(u32(b, export_off + 32))
    export_name = cstring(u32(b, export_name_table))
    need(export_name == "PyInit__toks", f"wrong or leaked PE export: {export_name}")
    need(len(found) > 0, "PE import table has no DLLs")
    need(len({s.lower() for s in found}) == len(found), "duplicate PE DLL imports")
    return found


def normalized_pe_sha256(binary: bytes) -> str:
    """Fingerprint the full .pyd, ignoring ONLY two linker timestamps.

    Clang/LLD 21 on the pinned Windows runners changes the COFF header timestamp
    and the IMAGE_DEBUG_DIRECTORY timestamp on every rebuild. Both fields are
    identified from the PE tables and must agree. Every other byte, including
    code, import data, resource data and debug records, is hashed unchanged.
    This is reproducibility against one pinned *binary build*, not a proof of
    provenance or of the absence of malicious source code in that reference.
    """
    pe = u32(binary, 0x3c)
    need(binary[:2] == b"MZ" and binary[pe:pe + 4] == b"PE\x00\x00",
         "bad PE image for normalized fingerprint")
    opt = pe + 24
    nsec, opt_len = u16(binary, pe + 6), u16(binary, pe + 20)
    need(0 < nsec <= 96 and u16(binary, opt) == 0x20b,
         "unsupported PE architecture for normalized fingerprint")
    dirs = u32(binary, opt + 108)
    need(dirs >= 7 and opt_len >= 112 + 7 * 8,
         "missing PE debug directory for normalized fingerprint")
    drva, dsize = u32(binary, opt + 112 + 6 * 8), u32(binary, opt + 116 + 6 * 8)
    need(drva != 0 and dsize == 28, "unsupported debug directory count/size")
    section_start = opt + opt_len
    need(section_start + nsec * 40 <= len(binary), "truncated PE section table")
    matches = []
    for i in range(nsec):
        o = section_start + 40 * i
        virtual_size, va, raw_size, raw_start = [u32(binary, o + k) for k in (8, 12, 16, 20)]
        if va <= drva and drva + dsize <= va + max(virtual_size, raw_size):
            delta = drva - va
            need(delta + dsize <= raw_size and raw_start + delta + dsize <= len(binary),
                 "PE debug directory has no matching raw bytes")
            matches.append(raw_start + delta)
    need(len(matches) == 1, "PE debug directory has ambiguous or missing section mapping")
    debug = matches[0]
    need(u32(binary, debug) == 0 and u32(binary, debug + 12) == 13,
         "unexpected PE debug directory shape (expected single POGO entry)")
    stamp_a, stamp_b = u32(binary, pe + 8), u32(binary, debug + 4)
    need(stamp_a == stamp_b, "PE linker timestamps do not agree")
    copy = bytearray(binary)
    copy[pe + 8:pe + 12] = b"\x00" * 4
    copy[debug + 4:debug + 8] = b"\x00" * 4
    return hashlib.sha256(copy).hexdigest()


def verify_zip_member_stream(fragment: bytes, method: int, expanded: int, crc: int, name: str) -> None:
    """Require one complete compression stream to consume every declared byte.

    ZIP local/central sizes can agree even when a deflate stream ends early,
    leaving another local record hidden in its unconsumed tail. Do not use
    ZipFile.read() or testzip() alone as a complete stream-consumption check.
    """
    need(0 <= expanded <= 16 * 1024 * 1024 and len(fragment) <= 16 * 1024 * 1024,
         f"ZIP member exceeds audit bounds: {name}")
    if method == 0:
        need(len(fragment) == expanded, f"ZIP stored member size mismatch: {name}")
        output = fragment
    elif method == 8:
        try:
            inflater = zlib.decompressobj(-15)
            output = inflater.decompress(fragment, expanded + 1)
        except zlib.error as exc:
            raise AuditError(f"malformed ZIP raw deflate stream: {name}: {exc}") from exc
        need(inflater.eof,
             f"ZIP deflate stream is incomplete or expands past declared size: {name}")
        need(not inflater.unused_data and not inflater.unconsumed_tail,
             f"ZIP deflate stream has trailing compressed bytes: {name}")
        need(len(output) == expanded, f"ZIP deflate output size mismatch: {name}")
    else:
        raise AuditError(f"unsupported ZIP compression method {method}: {name}")
    need((zlib.crc32(output) & 0xFFFFFFFF) == crc,
         f"ZIP decompressed CRC mismatch: {name}")


def verify_zip_layout(raw: bytes, infos: list) -> None:
    """Require every ZIP byte to belong to exactly one declared member or directory.

    ZIP readers usually trust the central directory. A crafted archive can place
    *unlisted* local file records before it; those bytes are invisible to
    ZipFile.namelist(), and behavior may differ across installers. For this
    version-pinned wheel profile, reject ZIP64, split archives, archive/member
    comments, extras, encryption, data descriptors and all unexplained bytes.

    This validates ZIP layout, not the authenticity of the publisher.
    """
    need(len(raw) >= 22 and raw[-22:-18] == b"PK\x05\x06",
         "ZIP has unaccounted trailer bytes, comment, or ambiguous end record")
    eocd = len(raw) - 22
    sig, disk, cd_disk, disk_entries, entries, cd_size, cd_off, comment_len = struct.unpack_from(
        "<4s4H2IH", raw, eocd)
    need(sig == b"PK\x05\x06" and disk == cd_disk == 0 and
         disk_entries == entries == len(infos) and comment_len == 0,
         "ZIP has a comment, multiple disks, or an inconsistent entry count")
    need(0 < entries <= 64 and 0 < cd_off < eocd and cd_size == eocd - cd_off,
         "ZIP central-directory boundary is inconsistent")
    # This research build ships ordinary ZIP32 archives with zero extra fields.
    # Reject all alternate encodings until specifically reviewed. zipfile's
    # permissive fallback must not become the security policy here.
    central = {}
    off = cd_off
    while off < eocd:
        need(off + 46 <= eocd and raw[off:off + 4] == b"PK\x01\x02",
             "unknown bytes or truncated ZIP central-directory record")
        fields = struct.unpack_from("<4s6H3I5H2I", raw, off)
        (_, made, needed, flags, method, mtime, mdate, crc, compressed,
         expanded, name_len, extra_len, member_comment, disk_start, internal,
         external, local_off) = fields
        end = off + 46 + name_len + extra_len + member_comment
        need(0 < name_len <= 255 and end <= eocd, "invalid ZIP central-directory length")
        need(extra_len == 0 and member_comment == 0 and disk_start == 0,
             "ZIP contains unreviewed extra fields, member comment, or disk")
        need(flags & (1 | 8 | 64) == 0 and flags & ~0x800 == 0,
             "encrypted, descriptor-backed, or otherwise unsupported ZIP flags")
        name = raw[off + 46:off + 46 + name_len]
        need(name not in central, "duplicate ZIP member in central directory")
        central[name] = (local_off, needed, flags, method, mtime, mdate, crc,
                         compressed, expanded)
        off = end
    need(off == eocd and len(central) == entries,
         "unaccounted ZIP central-directory bytes or duplicate entries")

    local_ranges = []
    for info in infos:
        name = info.filename.encode("utf-8")
        need(name in central, f"ZIP member absent from central directory: {info.filename}")
        local, needed, flags, method, mtime, mdate, crc, compressed, expanded = central[name]
        need(local == info.header_offset and flags == info.flag_bits and
             method == info.compress_type and compressed == info.compress_size and
             expanded == info.file_size and crc == info.CRC,
             f"ZIP parser and central directory disagree: {info.filename}")
        need(0 <= local < cd_off and local + 30 <= cd_off and
             raw[local:local + 4] == b"PK\x03\x04",
             f"missing ZIP local header: {info.filename}")
        (_, lneeded, lflags, lmethod, ltime, ldate, lcrc,
         lcsize, lusize, lname, lextra) = struct.unpack_from(
            "<4s5H3I2H", raw, local)
        need((lneeded, lflags, lmethod, ltime, ldate, lcrc, lcsize, lusize) ==
             (needed, flags, method, mtime, mdate, crc, compressed, expanded),
             f"ZIP local/central metadata differs: {info.filename}")
        need(lname == len(name) and lextra == 0 and
             raw[local + 30:local + 30 + lname] == name,
             f"ZIP local filename or extra fields differ: {info.filename}")
        payload_start = local + 30 + lname
        end = payload_start + compressed
        need(end <= cd_off, f"ZIP local member extends beyond data region: {info.filename}")
        verify_zip_member_stream(raw[payload_start:end], method, expanded, crc, info.filename)
        local_ranges.append((local, end))

    cursor = 0
    for start, end in sorted(local_ranges):
        need(start == cursor, "ZIP contains unreferenced local bytes or overlapping entries")
        cursor = end
    need(cursor == cd_off, "ZIP has an unindexed local member or other hidden bytes")


def audit(path: Path, *, source_root: Path | None = None) -> dict:
    match = re.fullmatch(r"toks-(\d+\.\d+\.\d+)-cp(3\d{2})-cp\2-win_amd64\.whl", path.name)
    need(match is not None, "unexpected wheel name or unsupported Python/ABI tag")
    version, pyver = match.group(1), match.group(2)
    pins = source_pins()
    need(version == pins["package_version"], "wheel is not the pinned version of toks")
    if source_root is not None:
        verify_source_git(source_root, pins)
    need(pyver in ("310", "311", "312", "313", "314"), "Python version outside validated support")
    base = f"toks-{version}.dist-info/"
    tag = f"cp{pyver}-cp{pyver}-win_amd64"
    with ZipFile(path) as z:
        infos = z.infolist()
        need(0 < len(infos) <= 64 and sum(i.file_size for i in infos) <= 32 * 1024 * 1024,
             "wheel exceeds bounded audit budget")
        need(all(i.file_size <= 16 * 1024 * 1024 for i in infos), "oversized wheel member")
        need(path.stat().st_size <= 32 * 1024 * 1024, "ZIP raw archive exceeds audit budget")
        verify_zip_layout(path.read_bytes(), infos)
        need(all(stat.S_IFMT(i.external_attr >> 16) != stat.S_IFLNK for i in infos),
             "wheel contains symlink")
        files = z.namelist()
        need(len({n.lower() for n in files}) == len(files), "case-colliding archive entries")
        need(len(files) > 5 and len(files) == len(set(files)), "missing files or duplicate archive path")
        for name in files:
            p = PurePosixPath(name)
            need(name and not name.endswith("/") and not name.startswith("/") and "\\" not in name
                 and ".." not in p.parts and p.parts[0] not in (".", ""), f"unsafe archive member: {name}")
            permitted_package = {"toks/__init__.py", "toks/_vocab.py", "toks/_toks.pyi", "toks/py.typed",
                                 f"toks/_toks.cp{pyver}-win_amd64.pyd"}
            permitted_dist = {base + x for x in ("METADATA", "WHEEL", "RECORD", "top_level.txt")}
            permitted_dist.update(base + "licenses/" + x for x in
                                  ("LICENSE", "NOTICE", "LICENSING.md", "THIRD_PARTY_NOTICES.md"))
            need(name in permitted_package or name in permitted_dist, f"unexpected wheel member: {name}")
            need(not name.lower().endswith((".pth", ".dll", ".exe", ".so", ".dylib")),
                 f"unexpected extra native executable: {name}")
        records = base + "RECORD"
        need(records in files and base + "WHEEL" in files and base + "METADATA" in files,
             "missing required .dist-info metadata")
        pydb = [n for n in files if n.endswith(".pyd")]
        need(pydb == [f"toks/_toks.cp{pyver}-win_amd64.pyd"], "wrong/multiple CPython extension module(s)")
        license_files = ("LICENSE", "NOTICE", "LICENSING.md", "THIRD_PARTY_NOTICES.md")
        for name in license_files:
            need(base + "licenses/" + name in files, f"missing license material: {name}")
        wheel_hdr = strict_headers(
            z.read(base + "WHEEL"),
            {"Wheel-Version": "1.0", "Root-Is-Purelib": "false", "Tag": tag},
            {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"}, set(), "WHEEL")
        need(len(wheel_hdr.get_all("Generator") or []) == 1 and
             re.fullmatch(r"setuptools \(\d+\.\d+\.\d+\)", wheel_hdr["Generator"]) is not None,
             "unexpected WHEEL generator")
        meta_hdr = strict_headers(
            z.read(base + "METADATA"),
            {"Metadata-Version": "2.4", "Name": "toks", "Version": version,
             "License-Expression": "Apache-2.0", "Requires-Python": ">=3.10",
             "Description-Content-Type": "text/markdown",
             "Summary": "Actual Computer's tokenizer: exactly hf tokenizers 0.23.2's ids, as fast as the hardware allows"},
            {"Metadata-Version", "Name", "Version", "Summary", "License-Expression",
             "Classifier", "Requires-Python", "Description-Content-Type", "License-File", "Dynamic"},
            {"Classifier", "License-File"}, "METADATA")
        need(meta_hdr.get_all("License-File") == ["LICENSE", "NOTICE", "LICENSING.md",
                                                   "THIRD_PARTY_NOTICES.md"],
             "METADATA license files differ from pinned list")
        need(meta_hdr.get_all("Dynamic") == ["license-file"], "unexpected METADATA Dynamic header")
        classifiers = ["Programming Language :: C", "Programming Language :: Python :: 3",
                       "Programming Language :: Python :: Implementation :: CPython",
                       "Operating System :: MacOS", "Operating System :: POSIX :: Linux",
                       "Operating System :: Microsoft :: Windows"]
        need(meta_hdr.get_all("Classifier") == classifiers, "unexpected METADATA classifiers")
        for name, expected in (("METADATA", pins["dist_info_sha256"]["METADATA"]),
                               ("WHEEL", pins["dist_info_sha256"]["WHEEL"][pyver]),
                               ("top_level.txt", pins["dist_info_sha256"]["top_level.txt"])):
            need(base + name in files, f"missing pinned metadata member: {name}")
            need(hashlib.sha256(z.read(base + name)).hexdigest() == expected,
                 f"unreviewed dist-info bytes: {name}")
        listed = {}
        with z.open(records) as f:
            lines = io.TextIOWrapper(f, encoding="utf-8", newline="")
            for line in csv.reader(lines):
                need(len(line) == 3, "invalid RECORD row shape")
                name, sig, size = line
                need(name in files and name not in listed, f"RECORD missing/multiple entry: {name}")
                listed[name] = (sig, size)
        need(set(listed) == set(files), "RECORD does not name every wheel member")
        for name, (sig, size) in listed.items():
            if name == records:
                need(not sig and not size, "RECORD must not hash itself")
                continue
            need(sig.startswith("sha256="), f"RECORD lacks SHA-256 for {name}")
            binary = z.read(name)
            actual = base64.urlsafe_b64encode(hashlib.sha256(binary).digest()).rstrip(b"=").decode("ascii")
            need(actual == sig[7:] and str(len(binary)) == size, f"RECORD hash/size mismatch: {name}")
        for relative, pin in pins["files"].items():
            member = relative if relative.startswith("toks/") else base + relative
            need(member in files, f"missing source-pinned member: {member}")
            raw = z.read(member)
            need(hashlib.sha256(raw).hexdigest() == pin["sha256"]
                 and git_blob_id(raw) == pin["git_blob_sha1"],
                 f"source-pinned file differs from Git {PINNED_SOURCE_COMMIT[:12]}: {relative}")
        pe = z.read(pydb[0])
        imported = pe_imports(pe)
        allowed = {f"python{pyver}.dll", "kernel32.dll", "vcruntime140.dll",
                   "vcruntime140_1.dll", "ucrtbase.dll"}
        unexpected = [d for d in imported if d.lower() not in allowed and
                      not re.fullmatch(r"api-ms-win-crt-[a-z0-9-]+\.dll", d.lower())]
        need(not unexpected, f"unexpected PE import dependencies: {unexpected}")
        need(f"python{pyver}.dll" in [x.lower() for x in imported], "wrong/missing CPython DLL import")
        native_digest = normalized_pe_sha256(pe)
        need(native_digest == pins["native_extension_normalized_sha256"][pyver],
             "native extension fingerprint differs from the pinned reference build")
        return {"wheel": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "source_commit": PINNED_SOURCE_COMMIT, "git_blob_members_checked": len(pins["files"]),
                "git_source_independently_checked": source_root is not None,
                "bytes": path.stat().st_size, "python": f"3.{pyver[1:]}", "tag": tag,
                "extension": pydb[0], "extension_sha256": hashlib.sha256(pe).hexdigest(),
                "native_normalized_sha256": native_digest,
                "native_reference_run_id": pins["native_reference_run_id"],
                "imports": sorted(imported, key=str.lower), "files_checked": len(files) - 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-source-root", type=Path,
                        help="Require every pin to match its blob in the offline pinned Git commit")
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args()
    status = 0
    for path in args.wheels:
        try:
            print(json.dumps(audit(path, source_root=args.verify_source_root), sort_keys=True))
        except (AuditError, FileNotFoundError, PermissionError, BadZipFile, OSError, UnicodeDecodeError) as exc:
            print(f"INVALID {path}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
