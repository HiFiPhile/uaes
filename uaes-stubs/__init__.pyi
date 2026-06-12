"""
Micro AES (uaes) CPython extension module.

This module provides lightweight AES encryption and decryption
using a minimalist C backend. It supports ECB, CBC, CTR, GCM, and CMAC modes.

Key lengths of 16, 24, and 32 bytes are supported, implicitly configuring the 
cipher to AES-128, AES-192, or AES-256 respectively.
"""

from typing import Tuple, Optional

class AES_ECB:
    """
    AES Electronic Codebook (ECB) mode.
    
    Warning: ECB mode is deterministic and generally considered insecure for most
    applications because it does not hide data patterns well.
    """

    def __init__(self, key: bytes) -> None:
        """
        Initialize the AES ECB context.

        :param key: The symmetric key (16, 24, or 32 bytes).
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES ECB mode.
        
        :param data: The plaintext to encrypt. Must be a multiple of 16 bytes.
        :return: The encrypted ciphertext.
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using AES ECB mode.
        
        :param data: The ciphertext to decrypt. Must be a multiple of 16 bytes.
        :return: The decrypted plaintext.
        """
        ...


class AES_CBC:
    """
    AES Cipher Block Chaining (CBC) mode.
    """

    def __init__(self, key: bytes, iv: Optional[bytes] = None) -> None:
        """
        Initialize the AES CBC context.

        :param key: The symmetric key (16, 24, or 32 bytes).
        :param iv: Initialization vector (16 bytes). Defaults to all-zeros if None.
        """
        ...

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES CBC mode.
        
        :param data: The plaintext to encrypt. Must be a multiple of 16 bytes.
        :return: The encrypted ciphertext.
        """
        ...

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data using AES CBC mode.
        
        :param data: The ciphertext to decrypt. Must be a multiple of 16 bytes.
        :return: The decrypted plaintext.
        """
        ...

    def set_iv(self, iv: bytes) -> None:
        """
        Update the initialization vector without re-initializing the key.

        :param iv: Initialization vector (16 bytes).
        """
        ...


class AES_CTR:
    """
    AES Counter (CTR) mode.
    """

    def __init__(self, key: bytes, iv: Optional[bytes] = None) -> None:
        """
        Initialize the AES CTR context.

        :param key: The symmetric key (16, 24, or 32 bytes).
        :param iv: Initialization vector/nonce (16 bytes). The last 4 bytes are
                   used as the 32-bit counter value. Defaults to all-zeros if None.
        """
        ...

    def crypt(self, data: bytes) -> bytes:
        """
        Encrypt or decrypt data using AES CTR mode (symmetric operation).
        
        :param data: The input bytes. Does not need to be a multiple of 16 bytes.
        :return: The processed bytes.
        """
        ...

    def set_iv(self, iv: Optional[bytes] = None, ctr: int = 0) -> None:
        """
        Update the initialization vector and/or counter.

        :param iv: Initialization vector/nonce (16 bytes).
        :param ctr: A 32-bit integer representing the counter value.
        """
        ...


class AES_GCM:
    """
    AES Galois/Counter Mode (GCM).
    """

    def __init__(self, key: bytes, iv: Optional[bytes] = None) -> None:
        """
        Initialize the AES GCM context.

        :param key: The symmetric key (16, 24, or 32 bytes).
        :param iv: Initialization vector/nonce (12 bytes). Defaults to all-zeros if None.
        """
        ...

    def encrypt(self, data: bytes, aad: bytes = b"", tag_len: int = 16) -> Tuple[bytes, bytes]:
        """
        Encrypt and authenticate data using AES GCM mode.

        :param data: The plaintext to encrypt.
        :param aad: Additional Authenticated Data (AAD), verified but not encrypted.
        :param tag_len: The length of the authentication tag to generate.
        :return: A tuple of (ciphertext, tag).
        """
        ...

    def decrypt(self, data: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypt and verify data using AES GCM mode.

        :param data: The ciphertext to decrypt.
        :param tag: The authentication tag to verify.
        :param aad: Additional Authenticated Data (AAD) to verify.
        :return: The decrypted plaintext.
        :raises ValueError: If the authentication tag verification fails.
        """
        ...

    def set_iv(self, iv: bytes) -> None:
        """
        Update the initialization vector without re-initializing the key.

        :param iv: Initialization vector/nonce (12 bytes).
        """
        ...


class AES_CMAC:
    """
    AES Cipher-based Message Authentication Code (CMAC).
    """

    def __init__(self, key: bytes) -> None:
        """
        Initialize the AES CMAC context.

        :param key: The symmetric key (16, 24, or 32 bytes).
        """
        ...

    def cmac(self, data: bytes, mac_len: int = 16) -> bytes:
        """
        Calculate the CMAC tag for the given data.

        :param data: The input message to authenticate.
        :param mac_len: The length of the MAC to generate.
        :return: The generated MAC tag.
        """
        ...
