# VMDragonSlayer Binary Ninja Plugin Package
"""
Binary Ninja plugin for VMDragonSlayer - VM protection analysis toolkit.

This module is a placeholder for future Binary Ninja integration.
Current development is focused on Ghidra and IDA Pro plugins.
"""

__version__ = "0.1.0-dev"
__author__ = "van1sh"
__license__ = "MIT"

# Future Binary Ninja plugin entry point
def plugin_init():
    """Initialize Binary Ninja plugin (placeholder)."""
    pass

# Planned plugin metadata
PLUGIN_INFO = {
    "name": "VMDragonSlayer",
    "description": "VM Protection Analysis and Handler Detection",
    "version": __version__,
    "author": __author__,
    "license": __license__,
    "dependencies": ["binaryninja"],
    "minimum_bn_version": "3.0.0"
}
