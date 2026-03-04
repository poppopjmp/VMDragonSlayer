# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
    "minimum_bn_version": "3.0.0",
}
