#!/usr/bin/env python3
"""ECC Key Generation Script.

This script generates Elliptic Curve Cryptography (ECC) key pairs using various
standard curves. It supports key generation, serialization, and validation
using the cryptography library.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig(level=logging.INFO, format="%(message)s")

logger = logging.getLogger(__name__)

DELIMETER = "=" * 50

# Available elliptic curves
CURVES = {
    "secp256r1": ec.SECP256R1(),  # P-256, widely used
    "secp384r1": ec.SECP384R1(),  # P-384, higher security
    "secp521r1": ec.SECP521R1(),  # P-521, highest security
    "secp256k1": ec.SECP256K1(),  # Used by Bitcoin
}


def get_curve_info(curve: type[ec.EllipticCurve]) -> dict[str, Any]:
    """Get information about an elliptic curve.

    :param curve: The elliptic curve object
    :return: Dictionary with curve information
    """
    return {
        "name": curve.name,
        "key_size": curve.key_size,
        "curve_type": type(curve).__name__,
    }


def generate_keypair(curve: type[ec.EllipticCurve]) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ECC key pair.

    :param curve: The elliptic curve to use
    :return: Tuple of (private_key, public_key)
    :raises Exception: If key generation fails
    """
    try:
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
    except Exception:
        logger.exception("Key generation failed.")
        raise
    else:
        return private_key, public_key

def serialize_private_key(
    private_key: ec.EllipticCurvePrivateKey,
    encoding: serialization.Encoding = serialization.Encoding.PEM,
    format_type: serialization.PrivateFormat = serialization.PrivateFormat.PKCS8,
    password: str | None = None,
) -> bytes:
    """Serialize a private key to bytes.

    :param private_key: The private key to serialize
    :param encoding: Encoding format (PEM or DER)
    :param format_type: Private key format
    :param password: Optional password for encryption
    :return: Serialized private key as bytes
    :raises Exception: If serialization fails
    """
    try:
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=encoding,
            format=format_type,
            encryption_algorithm=encryption,
        )
    except Exception:
        logger.exception("Private key serialization failed.")
        raise


def serialize_public_key(
    public_key: ec.EllipticCurvePublicKey,
    encoding: serialization.Encoding = serialization.Encoding.PEM,
    format_type: serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo,
) -> bytes:
    """Serialize a public key to bytes.

    :param public_key: The public key to serialize
    :param encoding: Encoding format (PEM or DER)
    :param format_type: Public key format
    :return: Serialized public key as bytes
    :raises Exception: If serialization fails
    """
    try:
        return public_key.public_bytes(
            encoding=encoding,
            format=format_type,
        )
    except Exception:
        logger.exception("Public key serialization failed.")
        raise


def save_keypair_to_files(
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    private_file: str | Path,
    public_file: str | Path,
    password: str | None = None,
    encoding: serialization.Encoding = serialization.Encoding.PEM,
) -> None:
    """Save key pair to files.

    :param private_key: The private key
    :param public_key: The public key
    :param private_file: Path to save private key
    :param public_file: Path to save public key
    :param password: Optional password for private key encryption
    :param encoding: Encoding format for files
    :raises Exception: If file operations fail
    """
    try:
        # Serialize keys
        private_pem = serialize_private_key(private_key, encoding=encoding, password=password)
        public_pem = serialize_public_key(public_key, encoding=encoding)

        # Save private key
        with Path(private_file).open("wb") as f:
            f.write(private_pem)

        # Save public key
        with Path(public_file).open("wb") as f:
            f.write(public_pem)

        logger.info("Private key saved to: %s", private_file)
        logger.info("Public key saved to: %s", public_file)

    except Exception:
        logger.exception("Failed to save key pair.")
        raise


def display_key_info(
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    curve: type[ec.EllipticCurve],
) -> None:
    """Display information about the generated key pair.

    :param private_key: The private key
    :param public_key: The public key
    :param curve: The elliptic curve used
    """
    curve_info = get_curve_info(curve)
    public_numbers = public_key.public_numbers()

    logger.info("Key Pair Information:")
    logger.info("  Curve: %s", curve_info["name"])
    logger.info("  Key Size: %d bits", curve_info["key_size"])
    logger.info("  Curve Type: %s", curve_info["curve_type"])
    logger.info("  Public Key Point:")
    logger.info("    X: %s", hex(public_numbers.x))
    logger.info("    Y: %s", hex(public_numbers.y))

    # Verify key pair relationship
    derived_public = private_key.public_key()
    if derived_public.public_numbers() == public_key.public_numbers():
        logger.info("  ✓ Key pair relationship verified")
    else:
        logger.error("  ✗ Key pair relationship verification failed")


def display_serialized_keys(
    private_key: ec.EllipticCurvePrivateKey,
    public_key: ec.EllipticCurvePublicKey,
    encoding: serialization.Encoding = serialization.Encoding.PEM,
) -> None:
    """Display serialized keys.

    :param private_key: The private key
    :param public_key: The public key
    :param encoding: Encoding format to display
    """
    try:
        private_serialized = serialize_private_key(private_key, encoding=encoding)
        public_serialized = serialize_public_key(public_key, encoding=encoding)

        logger.info(DELIMETER)
        logger.info("Serialized Keys (%s format):", encoding.name)
        logger.info(DELIMETER)
        logger.info("Private Key:")
        logger.info(private_serialized.decode() if encoding == serialization.Encoding.PEM else private_serialized.hex())
        logger.info("")
        logger.info("Public Key:")
        logger.info(public_serialized.decode() if encoding == serialization.Encoding.PEM else public_serialized.hex())

    except Exception:
        logger.exception("Failed to display serialized keys")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.

    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Generate ECC key pairs using various elliptic curves",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate SECP256R1 key pair (saves to private_key.pem and public_key.pem)
  python ecc_keygen.py

  # Generate SECP384R1 key pair
  python ecc_keygen.py -c secp384r1

  # Generate key pair and save to specific files
  python ecc_keygen.py -c secp256r1 -p my_private.pem -u my_public.pem

  # Generate key pair with password protection
  python ecc_keygen.py -c secp256r1 -w mypassword

  # Generate key pair and display in DER format
  python ecc_keygen.py -c secp256r1 --der

  # Generate key pair without saving to files
  python ecc_keygen.py --no-save

  # Display keys in output without saving to files
  python ecc_keygen.py --no-save --display

  # List available curves
  python ecc_keygen.py --list-curves

Available Curves:
  - secp256r1: P-256 curve, widely used, 256-bit security
  - secp384r1: P-384 curve, higher security, 384-bit security
  - secp521r1: P-521 curve, highest security, 521-bit security
  - secp256k1: Used by Bitcoin, 256-bit security

Output Formats:
  - PEM: Human-readable format (default)
  - DER: Binary format, more compact
        """,
    )

    parser.add_argument(
        "-c",
        "--curve",
        choices=list(CURVES.keys()),
        default="secp256r1",
        help="Elliptic curve to use (default: secp256r1)",
    )
    parser.add_argument(
        "-p",
        "--private-file",
        help="Path to save private key (default: private_key.pem)",
    )
    parser.add_argument(
        "-u",
        "--public-file",
        help="Path to save public key (default: public_key.pem)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save keys to files (only display if --display is used)",
    )
    parser.add_argument(
        "-w",
        "--password",
        help="Password to encrypt private key",
    )
    parser.add_argument(
        "--der",
        action="store_true",
        help="Use DER encoding instead of PEM",
    )
    parser.add_argument(
        "--display",
        action="store_true",
        help="Display serialized keys in output",
    )
    parser.add_argument(
        "--list-curves",
        action="store_true",
        help="List available curves and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def list_available_curves() -> None:
    """List all available elliptic curves with their information."""
    logger.info("Available Elliptic Curves:")
    logger.info(DELIMETER)

    for name, curve in CURVES.items():
        info = get_curve_info(curve)
        logger.info("%-12s: %s (%d bits)", name, info["name"], info["key_size"])

    logger.info("")
    logger.info("Usage: python ecc_keygen.py -c <curve_name>")


def main() -> None:
    """Execute the ECC key generation application."""
    args = parse_arguments()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Handle list curves option
    if args.list_curves:
        list_available_curves()
        sys.exit(0)

    logger.info("ECC Key Generation Tool")
    logger.info(DELIMETER)

    try:
        # Get the selected curve
        curve = CURVES[args.curve]
        curve_info = get_curve_info(curve)

        logger.info("Selected curve: %s (%d bits)", curve_info["name"], curve_info["key_size"])
        logger.debug("Curve type: %s", curve_info["curve_type"])

        # Generate key pair
        logger.info("Generating key pair...")
        private_key, public_key = generate_keypair(curve)
        logger.info("✓ Key pair generated successfully")

        # Display key information
        display_key_info(private_key, public_key, curve)

        # Determine output encoding
        encoding = serialization.Encoding.DER if args.der else serialization.Encoding.PEM
        logger.debug("Using %s encoding", encoding.name)

        # Save to files unless --no-save is specified
        if not args.no_save:
            private_file = args.private_file or "private_key.pem"
            public_file = args.public_file or "public_key.pem"

            # Adjust file extensions based on encoding
            if encoding == serialization.Encoding.DER:
                private_file = str(Path(private_file).with_suffix(".der"))
                public_file = str(Path(public_file).with_suffix(".der"))

            save_keypair_to_files(
                private_key,
                public_key,
                private_file,
                public_file,
                password=args.password,
                encoding=encoding,
            )

        # Display serialized keys if requested
        if args.display:
            display_serialized_keys(private_key, public_key, encoding)

        logger.info(DELIMETER)
        logger.info("SUCCESS: ECC key pair generation completed!")

    except Exception:
        logger.exception("Error")
        if args.verbose:
            logger.exception("Full error details:")
        sys.exit(1)


if __name__ == "__main__":
    main()
