"""Compatibility shim.

All real metadata lives in ``pyproject.toml``. This file only exists so that
older pip / setuptools combinations (as occasionally found on Raspberry Pi OS)
can still perform an editable (``pip install -e .``) install.
"""

from setuptools import setup

setup()
