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
import stat
import struct
import sys
from pathlib import Path, PurePosixPath
from email.parser import Parser
from zipfile import BadZipFile, ZipFile


class AuditError(ValueError):
    pass


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
    section_start = opt + opt_len
    need(section_start + sections * 40 <= len(b), "truncated section table")
    parts = []
    for i in range(sections):
        off = section_start + 40 * i
        vsize, va, rsize, raw = (u32(b, off + k) for k in (8, 12, 16, 20))
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
    # Delay-load imports bypass the normal dependency list: refuse them.
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


def audit(path: Path) -> dict:
    match = re.fullmatch(r"toks-(\d+\.\d+\.\d+)-cp(3\d{2})-cp\2-win_amd64\.whl", path.name)
    need(match is not None, "unexpected wheel name or unsupported Python/ABI tag")
    version, pyver = match.group(1), match.group(2)
    need(pyver in ("310", "311", "312", "313", "314"), "Python version outside validated support")
    base = f"toks-{version}.dist-info/"
    tag = f"cp{pyver}-cp{pyver}-win_amd64"
    with ZipFile(path) as z:
        infos = z.infolist()
        need(0 < len(infos) <= 64 and sum(i.file_size for i in infos) <= 32 * 1024 * 1024,
             "wheel exceeds bounded audit budget")
        need(all(i.file_size <= 16 * 1024 * 1024 for i in infos), "oversized wheel member")
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
        with z.open(base + "WHEEL") as f:
            wheel_text = f.read().decode("utf-8")
        need("Root-Is-Purelib: false" in wheel_text and f"Tag: {tag}" in wheel_text,
             "wrong wheel platform tag or purelib flag")
        with z.open(base + "METADATA") as f:
            metadata = f.read().decode("utf-8")
        headers = Parser().parsestr(metadata, headersonly=True)
        for key, value in (("Version", version), ("Name", "toks"),
                           ("License-Expression", "Apache-2.0")):
            need(headers.get_all(key) == [value], f"invalid {key} metadata")
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
        pe = z.read(pydb[0])
        imported = pe_imports(pe)
        allowed = {f"python{pyver}.dll", "kernel32.dll", "vcruntime140.dll",
                   "vcruntime140_1.dll", "ucrtbase.dll"}
        unexpected = [d for d in imported if d.lower() not in allowed and
                      not re.fullmatch(r"api-ms-win-crt-[a-z0-9-]+\.dll", d.lower())]
        need(not unexpected, f"unexpected PE import dependencies: {unexpected}")
        need(f"python{pyver}.dll" in [x.lower() for x in imported], "wrong/missing CPython DLL import")
        return {"wheel": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size, "python": f"3.{pyver[1:]}", "tag": tag,
                "extension": pydb[0], "extension_sha256": hashlib.sha256(pe).hexdigest(),
                "imports": sorted(imported, key=str.lower), "files_checked": len(files) - 1}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", nargs="+", type=Path)
    args = parser.parse_args()
    status = 0
    for path in args.wheels:
        try:
            print(json.dumps(audit(path), sort_keys=True))
        except (AuditError, FileNotFoundError, PermissionError, BadZipFile, OSError, UnicodeDecodeError) as exc:
            print(f"INVALID {path}: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
