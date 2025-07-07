"""
MEF 3.0 Python Library - A modern, maintainable implementation of the MEF 3.0 specification.

This library provides high-level interfaces for reading and writing MEF 3.0 files,
with a focus on safety, maintainability, and ease of use.
"""

from mef_tools_2.reader import MefReader
from mef_tools_2.writer import MefWriter

__version__ = "0.1.0"
__all__ = ['MefReader', 'MefWriter']
