"""
Unit and regression test for the cryptography package.
"""

# Import package, test suite, and other packages as needed
import sys

import pytest

import cryptography


def test_cryptography_imported():
    """Sample test, will always pass so long as import statement worked."""
    assert "cryptography" in sys.modules
