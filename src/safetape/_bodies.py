"""Small helpers for headers and bodies in vcrpy's cassette dicts."""

from __future__ import annotations

import importlib
import io
import json
import zlib
from collections.abc import Callable, Mapping, MutableMapping
from typing import Any

# Anything bigger than this after decompression isn't scanned, and so isn't saved.
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024


class UnscannableBody(Exception):
    """A body safetape can't turn into text to scan."""


def header_values(headers: Mapping[str, Any] | None, name: str) -> list[str]:
    """Every value of a header, found case-insensitively."""
    if not headers:
        return []
    wanted = name.lower()
    values: list[str] = []
    for key, value in headers.items():
        if str(key).lower() != wanted:
            continue
        items = value if isinstance(value, (list, tuple)) else [value]
        values.extend(_as_text(item) for item in items)
    return values


def set_header(headers: MutableMapping[str, Any], name: str, value: str) -> None:
    """Replace a header that's already there, keeping the key's spelling and list shape."""
    for key in list(headers):
        if str(key).lower() == name.lower():
            headers[key] = [value] if isinstance(headers[key], (list, tuple)) else value


def media_type(headers: Mapping[str, Any] | None) -> str:
    """The content type without parameters, in lower case."""
    values = header_values(headers, "content-type")
    if not values:
        return ""
    return values[0].split(";", 1)[0].strip().lower()


def content_encodings(headers: Mapping[str, Any] | None) -> list[str]:
    """Content encodings in the order they were applied, leaving out identity."""
    codings: list[str] = []
    for value in header_values(headers, "content-encoding"):
        codings.extend(part.strip().lower() for part in value.split(","))
    return [coding for coding in codings if coding and coding != "identity"]


def to_bytes(body: Any) -> bytes | None:
    """A body as bytes, whatever shape vcrpy gave it to us in."""
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, (bytearray, memoryview)):
        return bytes(body)
    if isinstance(body, str):
        # surrogatepass, because a body loaded from JSON can hold a lone surrogate.
        return body.encode("utf-8", "surrogatepass")
    if isinstance(body, io.BytesIO):
        return body.getvalue()
    if isinstance(body, int):
        # One item of a body that vcrpy stored as an iterable of byte values.
        return bytes([body])
    if hasattr(body, "__iter__"):
        # vcrpy keeps iterator request bodies as their chunks.
        return b"".join(to_bytes(part) or b"" for part in body)
    return str(body).encode("utf-8")


def text_for_scan(body: Any, headers: Mapping[str, Any] | None) -> str:
    """Decompress a body if needed and decode it, so it can be scanned.

    Raises UnscannableBody when a compressed body can't be opened.
    """
    if isinstance(body, str):
        return body
    raw = to_bytes(body)
    if raw is None:
        return ""
    for coding in reversed(content_encodings(headers)):
        raw = _decompress(raw, coding)
    return raw.decode("utf-8", errors="replace")


def _decompress(data: bytes, coding: str) -> bytes:
    if coding in ("gzip", "x-gzip", "deflate"):
        # wbits 47 reads gzip or zlib headers. Raw deflate needs negative wbits.
        for wbits in (zlib.MAX_WBITS | 32, -zlib.MAX_WBITS):
            decompressor = zlib.decompressobj(wbits)
            try:
                result = decompressor.decompress(data, MAX_DECOMPRESSED_BYTES)
            except zlib.error:
                continue
            if decompressor.unconsumed_tail:
                raise UnscannableBody(f"{coding} body is bigger than safetape will scan")
            return result
        # Like vcrpy, treat a body that won't decompress as already decompressed.
        return data
    decompress = _optional_decompressor(coding)
    if decompress is None:
        raise UnscannableBody(
            f"body is {coding}-compressed and safetape can't decompress it to scan it",
        )
    try:
        return decompress(data)
    except Exception:
        return data


def _optional_decompressor(coding: str) -> Callable[[bytes], bytes] | None:
    modules = {"br": ("brotli", "brotlicffi"), "zstd": ("compression.zstd", "zstandard")}
    for module_name in modules.get(coding, ()):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        decompress: Callable[[bytes], bytes] = module.decompress
        return decompress
    return None


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} isn't valid JSON")


def strict_json(text: str) -> Any:
    """Parse JSON, refusing what wouldn't survive a round trip (NaN, repeated keys)."""
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
