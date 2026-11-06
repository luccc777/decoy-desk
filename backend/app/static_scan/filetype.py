"""What a file really is, judged by its bytes (magic numbers), never by its name.

Pure: nothing is written, opened as a program or run. Also holds the file-name
helpers the static checks share (extensions, hidden characters, display).
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict

Family = Literal["executable", "script", "shortcut", "disk_image", "archive", "document", "image", "text", "unknown"]


class FileKind(BaseModel):
    model_config = ConfigDict(frozen=True)

    label: str      # short human name, written to read well mid-sentence: "Windows program", "text file"
    family: Family
    mime: str       # a guess
    clue: str = ""  # what gave it away, e.g. "starts with MZ"


DANGEROUS_FAMILIES = frozenset({"executable", "script", "shortcut", "disk_image"})
MAX_ZIP_ENTRIES = 10_000
TEXT_SAMPLE = 2 * 1024 * 1024  # how much of a text file the script patterns read

MIME_PDF = "application/pdf"
MIME_ZIP = "application/zip"
MIME_RTF = "application/rtf"
MIME_TAR = "application/x-tar"
MIME_CAB = "application/vnd.ms-cab-compressed"
MIME_ISO = "application/x-iso9660-image"
MIME_GZIP = "application/gzip"
MIME_BZIP2 = "application/x-bzip2"
MIME_XZ = "application/x-xz"
MIME_MSI = "application/x-msi"
MIME_OLE = "application/x-ole-storage"
MIME_WORD_XML = "application/vnd.ms-word.document.xml"
MIME_FLAT_OPC = "application/vnd.ms-office.flatopc+xml"
MIME_MHT = "multipart/related"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# (zip folder, label, mime, macro-enabled mime)
OOXML_KINDS = (
    ("word/", "Word document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "application/vnd.ms-word.document.macroEnabled.12"),
    ("xl/", "Excel spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
     "application/vnd.ms-excel.sheet.macroEnabled.12"),
    ("ppt/", "PowerPoint presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
     "application/vnd.ms-powerpoint.presentation.macroEnabled.12"),
)
OOXML_MIMES = frozenset(m for _, _, plain, macro in OOXML_KINDS for m in (plain, macro))
OFFICE_XML_MIMES = frozenset({MIME_WORD_XML, MIME_FLAT_OPC, MIME_MHT})

_MSI_CLSIDS = {  # root storage CLSIDs of Windows Installer packages, patches and transforms
    "000C1084-0000-0000-C000-000000000046",
    "000C1086-0000-0000-C000-000000000046",
    "000C1082-0000-0000-C000-000000000046",
}


def _k(label: str, family: Family, mime: str, clue: str) -> FileKind:
    return FileKind(label=label, family=family, mime=mime, clue=clue)


# ---------------------------------------------------------------- detect_type

def detect_type(data: bytes) -> FileKind:
    """The file's real type from its content. Never raises on malformed input."""
    if not data:
        return _k("empty file", "unknown", "application/x-empty", "it has no content")
    for sniff in (_executable, _container, _media):
        kind = sniff(data)
        if kind:
            return kind
    if b"%PDF-" in data[:1024]:  # readers accept the header anywhere in the first 1 KB
        return _k("PDF document", "document", MIME_PDF, "starts with %PDF")
    return _text(data) or _k("file of unknown type", "unknown", "application/octet-stream",
                             "it doesn't match any type we know")


def _u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off:off + 2], "little")


def _u32(d: bytes, off: int) -> int:
    return int.from_bytes(d[off:off + 4], "little")


def _executable(d: bytes) -> Optional[FileKind]:
    if d[:2] == b"MZ":
        off = _u32(d, 0x3C) if len(d) >= 0x40 else 0
        has_pe = bool(off) and off + 24 <= len(d) and d[off:off + 4] == b"PE\0\0"
        # A DOS header always holds zero bytes; without them it's text that happens to start with "MZ".
        if has_pe or b"\x00" in d[2:64]:
            label = "Windows library (DLL)" if has_pe and _u16(d, off + 22) & 0x2000 else "Windows program"
            return _k(label, "executable", "application/vnd.microsoft.portable-executable", "starts with MZ")
    if d[:4] == b"\x7fELF":
        return _k("Linux program", "executable", "application/x-executable", "starts with ELF")
    if d[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return _k("Mac program", "executable", "application/x-mach-binary", "starts with a Mach-O header")
    if d[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") and len(d) >= 8:
        # Java class files share CAFEBABE with fat Mach-O; the next word is a small
        # architecture count for Mach-O and a class-file version (45 and up) for Java.
        n = int.from_bytes(d[4:8], "big")
        if d[3] == 0xBF or 0 < n < 20:
            return _k("Mac program", "executable", "application/x-mach-binary", "starts with a universal Mach-O header")
        if n >= 45:
            return _k("Java class file", "executable", "application/java-vm", "starts with CAFEBABE")
    if d[:8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00":
        return _k("Windows shortcut", "shortcut", "application/x-ms-shortcut", "starts with the .lnk header")
    if d[:2] == b"#!" or d[:5] == b"\xef\xbb\xbf#!":
        return _shebang(d)
    return None


_SHEBANGS = (
    ("python", "Python script", "text/x-python"),
    ("node", "Node.js script", "application/javascript"),
    ("pwsh", "PowerShell script", "application/x-powershell"),
    ("perl", "Perl script", "text/x-perl"),
    ("ruby", "Ruby script", "text/x-ruby"),
    ("sh", "shell script", "text/x-shellscript"),  # also bash, zsh, dash
)


def _shebang(d: bytes) -> FileKind:
    line = d[:256].split(b"\n", 1)[0].decode("latin-1").lower()
    for key, label, mime in _SHEBANGS:
        if key in line:
            return _k(label, "script", mime, "starts with #!")
    return _k("script", "script", "text/plain", "starts with #!")


def _container(d: bytes) -> Optional[FileKind]:
    if d[:8] == OLE_MAGIC:
        return _ole(d)
    if d[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _zip(d)
    if d[:7] == b"Rar!\x1a\x07\x00" or d[:8] == b"Rar!\x1a\x07\x01\x00":
        return _k("RAR archive", "archive", "application/vnd.rar", "starts with Rar!")
    if d[:6] == b"7z\xbc\xaf\x27\x1c":
        return _k("7z archive", "archive", "application/x-7z-compressed", "starts with 7z")
    if d[:2] == b"\x1f\x8b":
        return _k("gzip file", "archive", MIME_GZIP, "starts with the gzip header")
    if d[:3] == b"BZh" and d[3:4] in b"123456789" and len(d) > 3:
        return _k("bzip2 file", "archive", MIME_BZIP2, "starts with BZh")
    if d[:6] == b"\xfd7zXZ\x00":
        return _k("xz file", "archive", MIME_XZ, "starts with the xz header")
    if d[:4] == b"MSCF":
        return _k("CAB archive", "archive", MIME_CAB, "starts with MSCF")
    if d[257:262] == b"ustar":
        return _k("tar archive", "archive", MIME_TAR, "has a tar header")
    if d[:4] == b"{\\rt":  # Word accepts "{\rt" followed by anything, not only "{\rtf1"
        return _k("RTF document", "document", MIME_RTF, "starts with {\\rtf")
    if any(d[off:off + 5] == b"CD001" for off in (0x8001, 0x8801, 0x9001)):
        return _k("ISO disk image", "disk_image", MIME_ISO, "has CD001 at the ISO 9660 offset")
    if d[0x8001:0x8006] == b"BEA01":
        return _k("UDF disk image", "disk_image", "application/x-udf-image", "has a UDF volume header")
    if d[:8] == b"vhdxfile":
        return _k("VHDX disk image", "disk_image", "application/x-vhdx", "starts with vhdxfile")
    if d[:8] == b"conectix" or (len(d) >= 512 and d[-512:-504] == b"conectix"):
        return _k("VHD disk image", "disk_image", "application/x-vhd", "has a VHD footer")
    if len(d) >= 512 and d[-512:-508] == b"koly":
        return _k("Mac disk image (DMG)", "disk_image", "application/x-apple-diskimage", "has a DMG trailer")
    return None


def _ole(d: bytes) -> FileKind:
    clue = "starts with the OLE header (D0 CF 11 E0)"
    try:
        import olefile  # installed with oletools
        with olefile.OleFileIO(io.BytesIO(d)) as ole:
            clsid = (ole.root.clsid or "").upper()
            paths = ole.listdir(streams=True, storages=True)
    except Exception:
        return _k("damaged Office file", "document", MIME_OLE, clue)
    if clsid in _MSI_CLSIDS:
        return _k("Windows installer", "executable", MIME_MSI, "is an OLE file with the Windows Installer ID")
    top = {p[0].lower() for p in paths if p}
    parts = {part.lower() for p in paths for part in p}
    if "encryptedpackage" in top:
        return _k("password-protected Office document", "document", MIME_OLE, clue)
    macros = " with macros" if parts & {"macros", "_vba_project_cur", "vba"} else ""
    if "worddocument" in top:
        return _k("Word document" + macros, "document", "application/msword", clue)
    if top & {"workbook", "book"}:
        return _k("Excel spreadsheet" + macros, "document", "application/vnd.ms-excel", clue)
    if "powerpoint document" in top:
        return _k("PowerPoint presentation" + macros, "document", "application/vnd.ms-powerpoint", clue)
    if any(t.startswith("__substg1.0_") for t in top):
        return _k("Outlook email", "document", "application/vnd.ms-outlook", clue)
    return _k("Office file" + macros, "document", MIME_OLE, clue)


def zip_entry_count(data: bytes) -> int:
    """Central-directory records in a zip, counted before any parser builds them all in memory."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if eocd >= 0 and eocd + 22 <= len(data):
        cd_size = _u32(data, eocd + 12)
        if cd_size != 0xFFFFFFFF:
            # zipfile parses exactly this region, so this bounds what it will build.
            return data.count(b"PK\x01\x02", max(0, eocd - cd_size), eocd)
    return data.count(b"PK\x01\x02")


def _zip(d: bytes) -> FileKind:
    zip_kind = _k("ZIP archive", "archive", MIME_ZIP, "starts with PK")
    if zip_entry_count(d) > MAX_ZIP_ENTRIES:
        return zip_kind
    try:
        with zipfile.ZipFile(io.BytesIO(d)) as zf:
            names = [n.lower() for n in zf.namelist()]
    except Exception:
        return zip_kind
    present = set(names)
    if "[content_types].xml" in present:
        macro = any(n.endswith("vbaproject.bin") for n in names)
        for folder, label, mime, macro_mime in OOXML_KINDS:
            if any(n.startswith(folder) for n in names):
                if macro:
                    return _k(label + " with macros", "document", macro_mime, "is an Office file with a macro project")
                return _k(label, "document", mime, "is an Office Open XML package")
        if "extension.vsixmanifest" in present:
            return _k("VS Code extension (VSIX)", "archive", "application/vsix", "is a VSIX package")
    if "meta-inf/manifest.mf" in present and any(n.endswith(".class") for n in names):
        return _k("Java program (JAR)", "executable", "application/java-archive", "is a ZIP with Java classes and a manifest")
    if "androidmanifest.xml" in present and "classes.dex" in present:
        return _k("Android app (APK)", "executable", "application/vnd.android.package-archive", "is an Android package")
    if d[30:38] == b"mimetype":  # ODF and EPUB store their type uncompressed as the first entry
        if b"opendocument" in d[38:120]:
            return _k("OpenDocument file", "document", "application/vnd.oasis.opendocument", "is an OpenDocument package")
        if b"epub" in d[38:120]:
            return _k("EPUB e-book", "document", "application/epub+zip", "is an EPUB package")
    return zip_kind


def _media(d: bytes) -> Optional[FileKind]:
    if d[:8] == b"\x89PNG\r\n\x1a\n":
        return _k("PNG image", "image", "image/png", "starts with the PNG header")
    if d[:3] == b"\xff\xd8\xff":
        return _k("JPEG image", "image", "image/jpeg", "starts with the JPEG header")
    if d[:6] in (b"GIF87a", b"GIF89a"):
        return _k("GIF image", "image", "image/gif", "starts with GIF8")
    if d[:4] == b"RIFF" and d[8:12] == b"WEBP":
        return _k("WEBP image", "image", "image/webp", "starts with RIFF WEBP")
    if d[:2] == b"BM" and len(d) >= 14 and _u32(d, 2) == len(d):
        return _k("BMP image", "image", "image/bmp", "starts with BM")
    if d[4:8] == b"ftyp":
        brand = d[8:12]
        if brand == b"qt  ":
            return _k("QuickTime video", "image", "video/quicktime", "has a QuickTime header")
        if brand in (b"heic", b"heix", b"mif1", b"msf1"):
            return _k("HEIC image", "image", "image/heic", "has a HEIF header")
        return _k("MP4 video", "image", "video/mp4", "has an MP4 header")
    if d[4:8] in (b"moov", b"mdat", b"wide"):
        return _k("QuickTime video", "image", "video/quicktime", "has a QuickTime header")
    return None


# ---------------------------------------------------------------- text and scripts

_BAD_TEXT = re.compile("[\x00-\x08\x0b\x0e-\x1a\x1c-\x1f\x7f�]")


def _decode(sample: bytes) -> Optional[str]:
    """The sample as text, or None when it looks binary."""
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = sample.decode("utf-16", errors="replace")
        return text if len(_BAD_TEXT.findall(text[:65536])) <= len(text[:65536]) * 0.02 else None
    if b"\x00" in sample[:65536]:
        return None
    for codec in ("utf-8", "cp1252"):
        text = sample.decode(codec, errors="replace")
        probe = text[:65536]
        if len(_BAD_TEXT.findall(probe)) <= len(probe) * 0.02:
            return text
    return None


# (label, mime, clue, pattern), tried in order; the first match wins.
_SCRIPTS = (
    ("HTML application (HTA)", "application/hta", "contains <hta:application>",
     re.compile(r"<hta:application", re.I)),
    ("PowerShell script", "application/x-powershell", "runs code with IEX",
     re.compile(r"\binvoke-expression\b|\|\s*iex\b"
                r"|\biex\s*(?:\(\s*(?:new-object|iwr|irm|invoke-|\[|\$|\()|\$\w)", re.I)),
    ("PowerShell script", "application/x-powershell", "runs an encoded PowerShell command",
     re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,200}?\s[-/](?:ec|e|en|enc[a-z]*)\s+[a-z0-9+/]{20,}", re.I)),
    ("PowerShell script", "application/x-powershell", "downloads with Net.WebClient",
     re.compile(r"new-object\s+(?:system\.)?net\.webclient|\.downloadstring\s*\(", re.I)),
    ("VBScript", "text/vbscript", "creates a WScript.Shell or similar object",
     re.compile(r"createobject\s*\(\s*[\"'](?:wscript\.shell|shell\.application|scripting\.filesystemobject"
                r"|msxml2\.(?:server)?xmlhttp|adodb\.stream)[\"']", re.I)),
    ("JScript", "text/jscript", "creates an ActiveXObject",
     re.compile(r"\bnew\s+activexobject\s*\(", re.I)),
    ("Windows Script Host script", "text/plain", "uses WScript",
     re.compile(r"\bwscript\.(?:createobject|shell|scriptfullname|sleep|arguments)\b", re.I)),
)
# Blank lines and comments may come first; [ \t] rather than \s keeps the repeat unambiguous (no backtracking blowup).
_BATCH = re.compile(r"\A(?:[ \t]*(?:(?:rem\b|::)[^\n]*)?\r?\n)*[ \t]*@echo[ \t]+off\b", re.I)


def _text(d: bytes) -> Optional[FileKind]:
    text = _decode(d[:TEXT_SAMPLE])
    if text is None:
        return None
    head = text.lstrip("﻿ \t\r\n")[:4096].lower()
    if head.startswith("[internetshortcut]"):
        return _k("internet shortcut", "shortcut", "application/x-mswinurl", "starts with [InternetShortcut]")
    if head.startswith("[desktop entry]"):
        return _k("Linux desktop shortcut", "shortcut", "application/x-desktop", "starts with [Desktop Entry]")
    for label, mime, clue, pattern in _SCRIPTS:
        if pattern.search(text):
            return _k(label, "script", mime, clue)
    if _BATCH.match(text[:65536].lstrip("﻿")):
        return _k("Windows batch script", "script", "application/x-bat", "starts with @echo off")
    if "http://schemas.microsoft.com/office/word/2003/wordml" in text:
        return _k("Word XML document", "document", MIME_WORD_XML, "is Word 2003 XML")
    if "http://schemas.microsoft.com/office/2006/xmlpackage" in text[:65536].lower():
        return _k("Office XML document", "document", MIME_FLAT_OPC, "is a flat Office XML package")
    if "mime-version" in head and "multipart" in head:
        return _k("web archive (MHT)", "document", MIME_MHT, "is a MIME web archive")
    if head.startswith(("<!doctype html", "<html")) or "<html" in head[:1024]:
        return _k("web page", "text", "text/html", "is HTML")
    if "<svg" in head[:1024]:
        return _k("SVG image", "image", "image/svg+xml", "is SVG")
    return _k("text file", "text", "text/plain", "is plain text")


# ---------------------------------------------------------------- file names

EXECUTABLE_EXTS = frozenset({"exe", "scr", "com", "pif", "msi", "msp", "cpl", "dll", "jar", "app"})
SCRIPT_EXTS = frozenset({"bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "sh"})
SHORTCUT_EXTS = frozenset({"lnk", "url"})
DISK_IMAGE_EXTS = frozenset({"iso", "img", "vhd", "vhdx"})
RISKY_EXTS = EXECUTABLE_EXTS | SCRIPT_EXTS | SHORTCUT_EXTS
# A name may claim one of these while its content is a program (S7).
DOCUMENT_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
                           "jpg", "jpeg", "png", "gif", "mp4", "mov", "zip"})
# What a double extension pretends to be: "resume.pdf.exe".
DECOY_EXTS = DOCUMENT_EXTS | {"docm", "xlsm", "pptm", "odt", "ods", "odp", "bmp", "webp", "mp3", "wav",
                              "avi", "rar", "7z"}

_EXT_NAMES = {
    "exe": "a Windows program", "scr": "a Windows screensaver program", "com": "a DOS program",
    "pif": "a Windows program", "msi": "a Windows installer", "msp": "a Windows installer patch",
    "cpl": "a Control Panel program", "dll": "a Windows library", "jar": "a Java program", "app": "a Mac app",
    "bat": "a batch script", "cmd": "a batch script", "js": "a JavaScript file", "jse": "an encoded JScript",
    "vbs": "a VBScript", "vbe": "an encoded VBScript", "wsf": "a Windows script", "wsh": "a Windows script",
    "hta": "an HTML application", "ps1": "a PowerShell script", "psm1": "a PowerShell module",
    "sh": "a shell script", "lnk": "a Windows shortcut", "url": "an internet shortcut",
    "iso": "a disk image, which can hide programs", "img": "a disk image, which can hide programs",
    "vhd": "a disk image, which can hide programs", "vhdx": "a disk image, which can hide programs",
}

BIDI_CONTROLS = frozenset({"؜", "‎", "‏", *map(chr, range(0x202A, 0x202F)),
                           *map(chr, range(0x2066, 0x206A))})
INVISIBLE = frozenset({"​", "‌", "‍", "⁠", "﻿", "ㅤ", "⠀"})
_DOT_LOOKALIKES = str.maketrans({"․": ".", "．": ".", "﹒": "."})


def base_name(name: str) -> str:
    return re.split(r"[\\/]", name or "")[-1]


def has_bidi(name: str) -> bool:
    return any(c in BIDI_CONTROLS for c in name or "")


def extensions(name: str) -> list[str]:
    """Extensions from the real (last) one backwards, lowercased: 'a.PDF .exe' -> ['exe', 'pdf']."""
    clean = "".join(c for c in base_name(name).translate(_DOT_LOOKALIKES)
                    if c not in BIDI_CONTROLS and c not in INVISIBLE)
    parts = clean.rstrip(" .\t").split(".")  # Windows drops trailing dots and spaces
    return [p.strip().lower() for p in reversed(parts[1:])]


def name_risk(path: str) -> Optional[str]:
    """Why an archive entry's name marks it as a program, script or shortcut, or None."""
    parts = re.split(r"[\\/]", path)
    if any(p.lower().endswith(".app") for p in parts[:-1]):
        return "part of a Mac app"
    exts = extensions(path)
    if exts and exts[0] in _EXT_NAMES:
        return _EXT_NAMES[exts[0]]
    if has_bidi(path):
        return "its name hides its real ending with a right-to-left character"
    return None


def display_name(name: str, *, keep_path: bool = False, limit: int = 90) -> str:
    """A name safe to show: hidden characters made visible, long space runs counted, long names cut."""
    s = (name or "") if keep_path else base_name(name)
    if not s:
        return "the file"
    s = "".join("[hidden character]" if c in BIDI_CONTROLS or c in INVISIBLE
                else "?" if ord(c) < 32 or ord(c) == 127 else c for c in s)
    s = re.sub(r"\s{3,}", lambda m: f" [{len(m.group())} spaces] ", s)
    if len(s) > limit:
        s = s[:limit // 2 - 1] + "…" + s[-(limit // 2):]
    return s


def a(label: str) -> str:
    """'a' or 'an' before a label: 'an ISO disk image', 'a PDF document', 'an Excel spreadsheet'."""
    word = label.split(" ", 1)[0]
    if len(word) > 1 and word.isupper() and word not in ("RAR", "HEIC") and word[0] in "AEFHILMNORSX":
        return f"an {label}"
    return f"{'an' if label[:1].lower() in 'aeiou' else 'a'} {label}"
