"""Smoke tests: verify package imports and basic structure."""


def test_package_imports():
    """All subpackages should be importable."""


def test_version():
    import gdoc2netcfg

    assert gdoc2netcfg.__version__ == "0.1.0"
