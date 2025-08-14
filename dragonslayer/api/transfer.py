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

"""
Binary Transfer Utilities
========================

Utilities for efficient binary data transfer in API operations.
"""

import base64
import gzip
import hashlib
import logging
from typing import BinaryIO, Iterator

from ..core.exceptions import DataError, InvalidDataError

logger = logging.getLogger(__name__)


class BinaryTransfer:
    """
    Utilities for efficient binary data transfer.

    Provides compression, chunking, and validation for binary data
    transfer operations in the API.
    """

    def __init__(self, chunk_size: int = 1024 * 1024, enable_compression: bool = True):
        """
        Initialize binary transfer utility.

        Args:
            chunk_size: Size of chunks for streaming transfer
            enable_compression: Whether to enable compression
        """
        self.chunk_size = chunk_size
        self.enable_compression = enable_compression
        self.logger = logging.getLogger(f"{__name__}.BinaryTransfer")

    def encode_binary(self, binary_data: bytes, compress: bool = None) -> str:
        """
        Encode binary data for transfer.

        Args:
            binary_data: Binary data to encode
            compress: Whether to compress (defaults to instance setting)

        Returns:
            Base64 encoded (and optionally compressed) string
        """
        if not isinstance(binary_data, (bytes, bytearray)):
            raise InvalidDataError("Data must be bytes or bytearray")

        if len(binary_data) == 0:
            return ""

        compress = compress if compress is not None else self.enable_compression

        try:
            # Optionally compress
            data_to_encode = binary_data
            if compress and len(binary_data) > 1024:  # Only compress if size > 1KB
                data_to_encode = gzip.compress(binary_data)
                self.logger.debug(
                    f"Compressed {len(binary_data)} bytes to {len(data_to_encode)} bytes"
                )

            # Base64 encode
            encoded = base64.b64encode(data_to_encode).decode("ascii")

            # Add metadata header if compressed
            if compress and len(data_to_encode) < len(binary_data):
                encoded = f"gzip:{encoded}"

            return encoded

        except Exception as e:
            self.logger.error(f"Failed to encode binary data: {e}")
            raise DataError(
                "Failed to encode binary data", error_code="ENCODE_FAILED", cause=e
            ) from e

    def decode_binary(self, encoded_data: str) -> bytes:
        """
        Decode binary data from transfer format.

        Args:
            encoded_data: Encoded string data

        Returns:
            Decoded binary data
        """
        if not isinstance(encoded_data, str):
            raise InvalidDataError("Encoded data must be string")

        if not encoded_data:
            return b""

        try:
            # Check for compression header
            is_compressed = False
            data_to_decode = encoded_data

            if encoded_data.startswith("gzip:"):
                is_compressed = True
                data_to_decode = encoded_data[5:]  # Remove "gzip:" prefix

            # Base64 decode
            decoded_data = base64.b64decode(data_to_decode)

            # Decompress if needed
            if is_compressed:
                decoded_data = gzip.decompress(decoded_data)
                self.logger.debug(f"Decompressed data to {len(decoded_data)} bytes")

            return decoded_data

        except Exception as e:
            self.logger.error(f"Failed to decode binary data: {e}")
            raise DataError(
                "Failed to decode binary data", error_code="DECODE_FAILED", cause=e
            ) from e

    def stream_encode(self, binary_stream: BinaryIO) -> Iterator[str]:
        """
        Stream encode binary data in chunks.

        Args:
            binary_stream: Binary stream to encode

        Yields:
            Encoded data chunks
        """
        try:
            while True:
                chunk = binary_stream.read(self.chunk_size)
                if not chunk:
                    break

                encoded_chunk = self.encode_binary(
                    chunk, compress=False
                )  # Don't compress chunks
                yield encoded_chunk

        except Exception as e:
            self.logger.error(f"Failed to stream encode binary data: {e}")
            raise DataError(
                "Failed to stream encode binary data",
                error_code="STREAM_ENCODE_FAILED",
                cause=e,
            ) from e

    def stream_decode(self, encoded_chunks: Iterator[str]) -> Iterator[bytes]:
        """
        Stream decode binary data from chunks.

        Args:
            encoded_chunks: Iterator of encoded data chunks

        Yields:
            Decoded binary chunks
        """
        try:
            for encoded_chunk in encoded_chunks:
                decoded_chunk = self.decode_binary(encoded_chunk)
                yield decoded_chunk

        except Exception as e:
            self.logger.error(f"Failed to stream decode binary data: {e}")
            raise DataError(
                "Failed to stream decode binary data",
                error_code="STREAM_DECODE_FAILED",
                cause=e,
            ) from e

    def calculate_checksum(self, binary_data: bytes, algorithm: str = "sha256") -> str:
        """
        Calculate checksum of binary data.

        Args:
            binary_data: Binary data to checksum
            algorithm: Hashing algorithm ("md5", "sha1", "sha256")

        Returns:
            Hexadecimal checksum string
        """
        if not isinstance(binary_data, (bytes, bytearray)):
            raise InvalidDataError("Data must be bytes or bytearray")

        try:
            # Note: md5/sha1 are insecure; allowed here for compatibility checks only.
            if algorithm == "md5":
                hasher = hashlib.md5()
            elif algorithm == "sha1":
                hasher = hashlib.sha1()
            elif algorithm == "sha256":
                hasher = hashlib.sha256()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            hasher.update(binary_data)
            return hasher.hexdigest()

        except Exception as e:
            self.logger.error(f"Failed to calculate checksum: {e}")
            raise DataError(
                "Failed to calculate checksum", error_code="CHECKSUM_FAILED", cause=e
            ) from e

    def verify_checksum(
        self, binary_data: bytes, expected_checksum: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Verify binary data checksum.

        Args:
            binary_data: Binary data to verify
            expected_checksum: Expected checksum value
            algorithm: Hashing algorithm

        Returns:
            True if checksum matches, False otherwise
        """
        try:
            actual_checksum = self.calculate_checksum(binary_data, algorithm)
            return actual_checksum.lower() == expected_checksum.lower()

        except Exception as e:
            self.logger.error(f"Failed to verify checksum: {e}")
            return False

    def create_transfer_metadata(self, binary_data: bytes) -> dict:
        """
        Create metadata for binary transfer.

        Args:
            binary_data: Binary data

        Returns:
            Metadata dictionary
        """
        return {
            "size": len(binary_data),
            "sha256": self.calculate_checksum(binary_data, "sha256"),
            "md5": self.calculate_checksum(binary_data, "md5"),
            "compressed": self.enable_compression and len(binary_data) > 1024,
        }

    def validate_transfer(self, binary_data: bytes, metadata: dict) -> bool:
        """
        Validate binary transfer using metadata.

        Args:
            binary_data: Received binary data
            metadata: Transfer metadata

        Returns:
            True if transfer is valid, False otherwise
        """
        try:
            # Check size
            if len(binary_data) != metadata.get("size", 0):
                self.logger.warning("Transfer size mismatch")
                return False

            # Check checksums
            if "sha256" in metadata:
                if not self.verify_checksum(binary_data, metadata["sha256"], "sha256"):
                    self.logger.warning("SHA256 checksum mismatch")
                    return False

            if "md5" in metadata:
                if not self.verify_checksum(binary_data, metadata["md5"], "md5"):
                    self.logger.warning("MD5 checksum mismatch")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Transfer validation failed: {e}")
            return False

    def get_compression_ratio(
        self, original_data: bytes, compressed_data: bytes
    ) -> float:
        """
        Calculate compression ratio.

        Args:
            original_data: Original data
            compressed_data: Compressed data

        Returns:
            Compression ratio (0.0 to 1.0)
        """
        if len(original_data) == 0:
            return 0.0

        return len(compressed_data) / len(original_data)

    def estimate_transfer_time(
        self, data_size: int, bandwidth_mbps: float = 100.0
    ) -> float:
        """
        Estimate transfer time for given data size.

        Args:
            data_size: Size of data in bytes
            bandwidth_mbps: Available bandwidth in Mbps

        Returns:
            Estimated transfer time in seconds
        """
        if bandwidth_mbps <= 0:
            return float("inf")

        # Convert bandwidth to bytes per second
        bandwidth_bps = bandwidth_mbps * 1024 * 1024 / 8

        # Account for base64 encoding overhead (33% increase)
        encoded_size = data_size * 1.33

        # Account for compression if enabled
        if self.enable_compression:
            encoded_size *= 0.7  # Assume 30% compression ratio

        return encoded_size / bandwidth_bps


# Global transfer utility instance
_transfer_util = None


def get_transfer_util(
    chunk_size: int = 1024 * 1024, enable_compression: bool = True
) -> BinaryTransfer:
    """Get global transfer utility instance"""
    global _transfer_util
    if _transfer_util is None:
        _transfer_util = BinaryTransfer(chunk_size, enable_compression)
    return _transfer_util


def encode_binary(binary_data: bytes, compress: bool = True) -> str:
    """Convenience function for encoding binary data"""
    return get_transfer_util().encode_binary(binary_data, compress)


def decode_binary(encoded_data: str) -> bytes:
    """Convenience function for decoding binary data"""
    return get_transfer_util().decode_binary(encoded_data)
