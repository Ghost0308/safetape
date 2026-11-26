import safetape


def test_version_is_set() -> None:
    assert isinstance(safetape.__version__, str)
    assert safetape.__version__
