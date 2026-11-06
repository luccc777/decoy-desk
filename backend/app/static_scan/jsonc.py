"""JSON with comments and trailing commas, the format of VS Code's tasks.json and settings.json."""

from __future__ import annotations

import json
import re
from typing import Any

_STRING = r'"(?:[^"\\\n]|\\.)*"'
# Strings come first in each alternation so "https://x" is kept whole, never read as a // comment.
_COMMENTS = re.compile(_STRING + r"|//[^\n]*|/\*.*?(?:\*/|\Z)", re.DOTALL)
_TRAILING_COMMA = re.compile(_STRING + r"|,(\s*[}\]])")


def _drop_comment(m: re.Match) -> str:
    s = m.group(0)
    if s.startswith('"'):
        return s
    return " " + "\n" * s.count("\n")  # keep line numbers


def strip_jsonc(text: str) -> str:
    """Plain JSON from JSONC: comments and trailing commas removed, strings untouched."""
    text = _COMMENTS.sub(_drop_comment, text.lstrip("\ufeff"))
    return _TRAILING_COMMA.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(0), text)


def loads_jsonc(text: str) -> Any:
    """Parses JSONC; raises ValueError if it still isn't valid JSON."""
    return json.loads(strip_jsonc(text))
