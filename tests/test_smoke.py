"""Smoke tests: verify package imports and basic structure."""


def test_package_imports():
    """All subpackages should be importable."""
    import gdoc2netcfg
    import gdoc2netcfg.models
    import gdoc2netcfg.sources
    import gdoc2netcfg.derivations
    import gdoc2netcfg.supplements
    import gdoc2netcfg.constraints
    import gdoc2netcfg.generators
    import gdoc2netcfg.audit
    import gdoc2netcfg.cli
    import gdoc2netcfg.utils


def test_version():
    import gdoc2netcfg

    assert gdoc2netcfg.__version__ == "0.1.0"
