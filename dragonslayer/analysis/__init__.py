"""
Analysis package.
"""

from .binary_format import (  # noqa: F401
    ParsedBinary,
    Section,
    BinaryFormat,
    Architecture,
    parse_binary,
    detect_format,
    LIEF_AVAILABLE,
)
