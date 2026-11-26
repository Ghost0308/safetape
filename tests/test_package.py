import pytest

import safetape
from safetape import _settings


def test_version_is_set() -> None:
    assert isinstance(safetape.__version__, str)
    assert safetape.__version__


def test_exports_load_when_first_used() -> None:
    assert set(safetape.__all__) <= set(dir(safetape))
    assert safetape.Settings is _settings.Settings
    assert safetape.serializer.serialize({"interactions": []}).startswith("{")
    with pytest.raises(AttributeError, match="has no attribute 'nope'"):
        getattr(safetape, "nope")  # noqa: B009
