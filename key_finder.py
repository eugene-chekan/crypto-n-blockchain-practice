#!/usr/bin/env python3
"""Key Finder Script.

Given 128-bit keys in HEX format and a SHA-256 hash of the correct key,
this script finds which key matches the provided hash.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(message)s")

logger = logging.getLogger(__name__)

DELIMETER = "=" * 50


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string to bytes, handling common hex formats.

    :param hex_string: Hex string (with or without '0x' prefix)
    :return: The converted bytes
    :raises ValueError: If the hex string is invalid
    """
    if hex_string.startswith(("0x", "0X")):
        hex_string = hex_string[2:]

    hex_string = hex_string.replace(" ", "").lower()

    try:
        return bytes.fromhex(hex_string)
    except ValueError as e:
        msg = f"Invalid hex string: {hex_string}"
        raise ValueError(msg) from e


def compute_sha256_hash(data: bytes) -> str:
    """Compute SHA-256 hash of the given data.

    :param data: Input data as bytes
    :return: SHA-256 hash as lowercase hex string
    """
    return hashlib.sha256(data).hexdigest()


def _raise_file_not_found(csv_file: Path) -> None:
    """Raise FileNotFoundError for missing CSV file."""
    msg = f"CSV file not found: {csv_file}"
    raise FileNotFoundError(msg)


def _raise_no_valid_keys() -> None:
    """Raise ValueError for empty CSV file."""
    msg = "No valid keys found in CSV file"
    raise ValueError(msg)


def _raise_csv_error(csv_file: Path, error: Exception) -> None:
    """Raise ValueError for CSV reading errors."""
    msg = f"Error reading CSV file {csv_file}: {error}"
    raise ValueError(msg) from error


def read_keys_from_csv(csv_file: Path) -> list[str]:
    """Read keys from a CSV file.

    :param csv_file: Path to the CSV file containing keys
    :return: List of keys from the CSV file
    :raises FileNotFoundError: If the CSV file doesn't exist
    :raises ValueError: If the CSV file is malformed
    """
    if not csv_file.exists():
        _raise_file_not_found(csv_file)

    keys = []
    try:
        with csv_file.open("r", encoding="utf-8") as file:
            reader = csv.reader(file)
            for _, row in enumerate(reader, 1):
                if not row:
                    continue
                if len(row) > 0 and row[0].strip():
                    keys.append(row[0].strip())

        if not keys:
            _raise_no_valid_keys()

    except Exception as e:  # noqa: BLE001
        _raise_csv_error(csv_file, e)
    else:
        logger.info("Loaded %d keys from CSV file: %s", len(keys), csv_file)
        return keys


def find_matching_key(keys: list[str], target_hash: str) -> tuple | None:
    """Find which key matches the target SHA-256 hash.

    :param keys: List of hex keys (128-bit each)
    :param target_hash: Target SHA-256 hash to match
    :return: (key_index, key, computed_hash) if match found, None otherwise
    """
    target_hash = target_hash.replace(" ", "").lower()

    logger.info("Checking keys...")
    logger.debug(DELIMETER)

    try:
        for i, key in enumerate(keys, 1):
            key_bytes = hex_to_bytes(key)
            computed_hash = compute_sha256_hash(key_bytes)

            logger.debug("Key %s: %s", i, key)
            logger.debug("  As bytes: %s", key_bytes.hex())
            logger.debug("  SHA-256:  %s", computed_hash)

            if computed_hash == target_hash:
                logger.debug("  [MATCH FOUND!]")
                return (i, key, computed_hash)
            logger.debug("  [No match]")
            logger.debug("")

    except ValueError:
        logger.exception("Key %s: %s", i, key)
        logger.debug("")

    return None


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Find which key matches a target SHA-256 hash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using command line keys
  python key_finder.py -k key1 key2 key3 -t target_hash

  # Using CSV file
  python key_finder.py -c keys.csv -t target_hash

  # Using both (CSV keys + additional command line keys)
  python key_finder.py -c keys.csv -k additional_key1 additional_key2 -t target_hash

CSV Format:
  The CSV file should contain one key per row in the first column.
  Empty rows and empty cells are ignored.
        """,
    )

    parser.add_argument("-k", "--keys", nargs="*", help="Hex keys to check (128-bit each, 32 hex characters)")
    parser.add_argument("-c", "--csv", type=Path, help="CSV file containing keys (one per row in first column)")
    parser.add_argument("-t", "--target-hash", required=True, help="Target SHA-256 hash to match")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    return parser.parse_args()


def main() -> None:
    """Execute the key finder application."""
    args = parse_arguments()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("Key Finder - SHA-256 Hash Matching")
    logger.info(DELIMETER)

    keys = []

    if args.csv:
        try:
            csv_keys = read_keys_from_csv(args.csv)
            keys.extend(csv_keys)
        except (FileNotFoundError, ValueError):
            logger.exception("Error reading CSV file!")
            sys.exit(1)

    if args.keys:
        keys.extend(args.keys)
        logger.debug("Added %d keys from command line", len(args.keys))

    if not keys:
        logger.error("No keys provided. Use -k for command line keys or -c for CSV file.")
        sys.exit(1)

    logger.debug("Total keys to check: %d", len(keys))
    logger.debug("Target hash: %s", args.target_hash)
    logger.debug("")

    result = find_matching_key(keys, args.target_hash)

    if result:
        key_index, key, computed_hash = result
        logger.info(DELIMETER)
        logger.info("SUCCESS: Key %s matches the target hash!", key_index)
        logger.info("Key: %s", key)
        logger.info("Hash: %s", computed_hash)
    else:
        logger.info(DELIMETER)
        logger.info("No matching key found.")
        logger.info("Checked %d keys total.", len(keys))


if __name__ == "__main__":
    main()
