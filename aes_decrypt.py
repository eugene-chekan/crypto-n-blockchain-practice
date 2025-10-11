#!/usr/bin/env python3
"""AES-128-CBC Decryption Script.

This script decrypts AES-128 encrypted messages using CBC mode and a provided
initialization vector (IV). It uses the cryptography library for secure
cryptographic operations.
"""

from __future__ import annotations

import argparse
import base64
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


def base64_to_bytes(base64_string: str) -> bytes:
    """Convert a base64 string to bytes.

    :param base64_string: Base64 encoded string
    :return: The converted bytes
    :raises ValueError: If the base64 string is invalid
    """
    try:
        return base64.b64decode(base64_string)
    except Exception as e:
        msg = f"Invalid base64 string: {base64_string}"
        raise ValueError(msg) from e


def read_encrypted_data(data_input: str) -> bytes:
    """Read encrypted data from various input formats.

    :param data_input: Encrypted data as hex string, base64 string, or file path
    :return: The encrypted data as bytes
    :raises ValueError: If the input format is invalid
    :raises FileNotFoundError: If the file doesn't exist
    """
    # Check if it's a file path
    if Path(data_input).exists():
        try:
            with Path(data_input).open("rb") as f:
                return f.read()
        except Exception as e:
            msg = f"Error reading file {data_input}: {e}"
            raise ValueError(msg) from e

    # Try to parse as hex first
    try:
        return hex_to_bytes(data_input)
    except ValueError:
        pass

    # Try to parse as base64
    try:
        return base64_to_bytes(data_input)
    except ValueError:
        pass

    # If all parsing attempts fail, treat as raw bytes
    try:
        return data_input.encode("utf-8")
    except Exception as e:
        msg = f"Unable to parse encrypted data: {data_input}"
        raise ValueError(msg) from e


def decrypt_aes_cbc(key: bytes, iv: bytes, encrypted_data: bytes) -> bytes:
    """Decrypt AES-128-CBC encrypted data.

    :param key: 128-bit (16-byte) AES key
    :param iv: 128-bit (16-byte) initialization vector
    :param encrypted_data: The encrypted data to decrypt
    :return: The decrypted plaintext
    :raises ValueError: If key or IV length is invalid
    :raises Exception: If decryption fails
    """
    aes_key_length = 16
    aes_iv_length = 16
    if len(key) != aes_key_length:
        msg = f"Invalid key length: {len(key)} bytes. AES-128 requires exactly {aes_key_length} bytes."
        raise ValueError(msg)

    if len(iv) != aes_iv_length:
        msg = f"Invalid IV length: {len(iv)} bytes. CBC mode requires exactly {aes_iv_length} bytes."
        raise ValueError(msg)

    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except Exception as e:
        msg = f"Decryption failed: {e}"
        raise
    else:
        return decrypted_data

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Decrypt AES-128-CBC encrypted messages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt with hex key and IV
  python aes_decrypt.py -k 2b7e151628aed2a6abf7158809cf4f3c -i 000102030405060708090a0b0c0d0e0f -d "encrypted_hex_data"

  # Decrypt with base64 encrypted data
  python aes_decrypt.py -k 2b7e151628aed2a6abf7158809cf4f3c -i 000102030405060708090a0b0c0d0e0f -d "base64_encrypted_data" --base64

  # Decrypt from file
  python aes_decrypt.py -k 2b7e151628aed2a6abf7158809cf4f3c -i 000102030405060708090a0b0c0d0e0f -d encrypted_file.bin

  # Save decrypted output to file
  python aes_decrypt.py -k 2b7e151628aed2a6abf7158809cf4f3c -i 000102030405060708090a0b0c0d0e0f -d "encrypted_data" -o decrypted.txt

Key and IV Format:
  - Both key and IV should be 32 hex characters (16 bytes each)
  - Can include '0x' prefix or spaces (will be stripped)
  - Key: 128-bit AES key
  - IV: 128-bit initialization vector for CBC mode

Encrypted Data Format:
  - Can be provided as hex string, base64 string, or file path
  - Use --base64 flag to force base64 interpretation
  - File paths are automatically detected
        """,  # noqa: E501
    )

    parser.add_argument("-k", "--key", required=True, help="AES-128 key as hex string (32 hex characters, 16 bytes)")
    parser.add_argument(
        "-i", "--iv", required=True, help="Initialization vector as hex string (32 hex characters, 16 bytes)",
    )
    parser.add_argument("-d", "--data", required=True, help="Encrypted data as hex string, base64 string, or file path")
    parser.add_argument("-o", "--output", help="Output file path (if not specified, prints to stdout)")
    parser.add_argument("--base64", action="store_true", help="Force interpretation of encrypted data as base64")
    parser.add_argument("--raw", action="store_true", help="Output raw bytes without any encoding")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    return parser.parse_args()


def main() -> None:
    """Execute the AES decryption application."""
    args = parse_arguments()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("AES-128-CBC Decryption Tool")
    logger.info(DELIMETER)

    try:
        logger.debug("Parsing key and IV...")
        key = hex_to_bytes(args.key)
        iv = hex_to_bytes(args.iv)

        logger.debug("Key: %s (%d bytes)", args.key, len(key))
        logger.debug("IV:  %s (%d bytes)", args.iv, len(iv))

        logger.debug("Reading encrypted data...")
        if args.base64:
            encrypted_data = base64_to_bytes(args.data)
            logger.debug("Interpreted data as base64")
        else:
            encrypted_data = read_encrypted_data(args.data)
            logger.debug("Encrypted data length: %d bytes", len(encrypted_data))

        logger.info("Decrypting data...")
        decrypted_data = decrypt_aes_cbc(key, iv, encrypted_data)

        logger.info(DELIMETER)
        logger.info("SUCCESS: Data decrypted successfully!")
        logger.info("Decrypted data length: %d bytes", len(decrypted_data))

        if args.output:
            with Path(args.output).open("wb") as f:
                f.write(decrypted_data)
            logger.info("Decrypted data saved to: %s", args.output)
            sys.exit(0)
        elif args.raw:
            sys.stdout.buffer.write(decrypted_data)
        else:
            try:
                decoded_text = decrypted_data.decode("utf-8")
                logger.info("Decoded text: %s", decoded_text)
            except UnicodeDecodeError:
                logger.info("Decrypted data (hex): %s", decrypted_data.hex())
                logger.info("Note: Data contains non-UTF-8 bytes. Use --raw flag for binary output.")
                sys.exit(1)

    except ValueError:
        logger.exception("Input error")
        sys.exit(1)
    except Exception:
        logger.exception("Decryption error")
        sys.exit(1)


if __name__ == "__main__":
    main()
