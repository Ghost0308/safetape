"""Set up a vcrpy VCR object with safetape's defaults."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from vcr.cassette import CassetteContextDecorator
from vcr.record_mode import RecordMode

from . import serializer
from ._matchers import build_matchers
from ._persister import SafePersister, SafetapeError, StaleCassette
from ._settings import Settings

VCRPY_DEFAULT_MATCH_ON = ("method", "scheme", "host", "port", "path", "query")


def install(
    vcr: Any,
    settings: Settings | None = None,
    *,
    on_stale: Callable[[StaleCassette], object] | None = None,
) -> Any:
    """Make a ``vcr.VCR`` safe to record LLM traffic with, and return it.

    - cassettes are saved through SafePersister, which strips credentials and
      refuses to write anything that still looks secret
    - the "json" serializer becomes safetape's readable one
    - the query, uri and body matchers ignore stripped credentials, and requests
      are matched on their body too unless match_on was already changed
    - compressed responses are stored decompressed, so they can be scanned
    - in lockdown nothing is recorded, whatever record_mode says
    """
    settings = settings or Settings()
    _unpatch_when_save_fails()
    # pytest-recording loads extra cassettes named in the vcr marker through its own persister.
    extra_paths = tuple(getattr(vcr.persister, "extra_paths", None) or ())
    vcr.register_persister(SafePersister(settings, extra_paths=extra_paths, on_stale=on_stale))
    vcr.register_serializer("json", serializer)
    for name, matcher in build_matchers(settings).items():
        vcr.register_matcher(name, matcher)
    vcr.decode_compressed_response = True
    if tuple(vcr.match_on) == VCRPY_DEFAULT_MATCH_ON:
        # LLM APIs take nearly everything as a POST to one path, so without the body
        # two different prompts would replay each other's answers.
        vcr.match_on = (*VCRPY_DEFAULT_MATCH_ON, "body")
    if settings.lockdown_active:
        _lock(vcr)
    return vcr


_FINISH = "_CassetteContextDecorator__finish"


def _unpatch_when_save_fails() -> None:
    """Make vcrpy undo its HTTP patches even when saving a cassette raises.

    vcrpy saves the cassette and only then removes its patches, so an error from
    the save (like SecretFoundError) leaves them in place until the garbage
    collector gets to them, which breaks later tests in odd ways. safetape's own
    errors also get a fresh traceback here, so the secret they refused to write
    doesn't show up in a traceback either.
    """
    original = CassetteContextDecorator.__exit__
    if getattr(original, "_safetape", False):
        return

    @functools.wraps(original)
    def __exit__(self: Any, *exc_info: Any) -> Any:
        __tracebackhide__ = True
        try:
            return original(self, *exc_info)
        except SafetapeError as error:
            # The frames below this one hold the cassette before it was scrubbed, and
            # pytest prints function arguments in tracebacks. Start the traceback here.
            raise error.with_traceback(None)  # noqa: B904 - same error, shorter traceback
        finally:
            finish = getattr(self, _FINISH, None)
            if finish is not None:
                setattr(self, _FINISH, None)
                next(finish, None)

    __exit__._safetape = True  # type: ignore[attr-defined]
    CassetteContextDecorator.__exit__ = __exit__


def _lock(vcr: Any) -> None:
    vcr.record_mode = RecordMode.NONE
    original = vcr.use_cassette
    if getattr(original, "_safetape_locked", False):
        return

    @functools.wraps(original)
    def use_cassette(path: Any = None, **kwargs: Any) -> Any:
        kwargs["record_mode"] = RecordMode.NONE
        return original(path, **kwargs)

    use_cassette._safetape_locked = True  # type: ignore[attr-defined]
    vcr.use_cassette = use_cassette
