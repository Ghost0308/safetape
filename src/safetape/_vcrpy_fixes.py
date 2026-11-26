"""Fixes for vcrpy behaviour that would leak secrets or leave tests in a bad state.

They change vcrpy's classes for the whole process, so they apply to every VCR
object once safetape is in use. Each fix does nothing unless something goes
wrong, and applying them twice is harmless.
"""

from __future__ import annotations

import functools
from typing import Any

from vcr.cassette import CassetteContextDecorator
from vcr.errors import CannotOverwriteExistingCassetteException

from ._credentials import from_request, remember
from ._errors import SafetapeError
from ._redact import redact_text
from ._settings import Settings

_FINISH = "_CassetteContextDecorator__finish"


def harden_vcrpy() -> None:
    _unpatch_when_save_fails()
    _redact_playback_errors()


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


def _redact_playback_errors() -> None:
    """Mask secrets in vcrpy's "can't play back this request" error.

    The message describes the live request, which wasn't scrubbed, so it can show
    a key in the URL or, when matching on the body, a preview of the body.
    """
    original = CannotOverwriteExistingCassetteException.__init__
    if getattr(original, "_safetape", False):
        return

    @functools.wraps(original)
    def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        settings = _settings_of(getattr(self, "cassette", None))
        request = getattr(self, "failed_request", None)
        known = settings.known_credentials(
            from_request(request, settings.credential_headers, settings.query_params),
        )
        remember(known)
        self.args = tuple(
            redact_text(arg, settings, known) if isinstance(arg, str) else arg for arg in self.args
        )

    __init__._safetape = True  # type: ignore[attr-defined]
    CannotOverwriteExistingCassetteException.__init__ = __init__


def _settings_of(cassette: Any) -> Settings:
    settings = getattr(getattr(cassette, "_persister", None), "settings", None)
    return settings if isinstance(settings, Settings) else _default_settings()


@functools.cache
def _default_settings() -> Settings:
    return Settings()
