# uaes (Micro AES)

`uaes` is a lightweight, zero-dependency CPython extension module providing AES encryption and decryption. 

## Motivation

This module was created primarily targeting **resource-constrained embedded systems** where standard cryptographic libraries like `cryptography` or `pycryptodome` are not viable. Both of those libraries rely on CFFI (C Foreign Function Interface), which introduces significant CPU and memory overhead that is unacceptable for tightly constrained environments.

`uaes` bypasses CFFI entirely, binding a minimalist C backend directly to the CPython API. It maps the C context lifecycle seamlessly to Python object instantiation, delivering bare-metal speed with minimal memory footprint.

On SAM9X60 CPU running `python -X importtime /test/benchmark.py` shows `cryptography` needs more than 2 seconds just for import, while `uaes` needs 22 milliseconds.

However on x86 CPU conventional libraries are MUCH faster due to use of AES-NI hardware instructions.

## Features

- **No external dependencies**: Pure C implementation without reliance on OpenSSL, CFFI, or external crypto libraries.
- **Cross-platform**: Endian-independent design compiles uniformly on Little-Endian and Big-Endian architectures.
- **Supported Modes**: ECB, CBC, CTR, GCM, and CMAC.
- **Supported Key Lengths**: AES-128 (16 bytes), AES-192 (24 bytes), AES-256 (32 bytes). The mode is implicitly selected based on the size of the key provided.

## Installation / Build

You can build the module locally from the source directory using `setuptools`:

```bash
python setup.py build_ext --inplace
```

This will produce the compiled shared object (e.g., `uaes.cp312-win_amd64.pyd` or `uaes.cpython-312-x86_64-linux-gnu.so`), which you can import directly in Python.

## Usage

```python
import os
import uaes

key = os.urandom(16)  # AES-128
iv = os.urandom(12)   # 12-byte IV for GCM
data = b"Secret Message!"
aad = b"Header info"

# Initialize GCM context
ctx = uaes.AES_GCM(key=key, iv=iv)

# Encrypt
ciphertext, tag = ctx.encrypt(data=data, aad=aad)
print("Ciphertext:", ciphertext.hex())
print("Tag:", tag.hex())

# Decrypt
# Context state does not persist across encryptions, so re-initialize or reset IV:
ctx.set_iv(iv)
plaintext = ctx.decrypt(data=ciphertext, tag=tag, aad=aad)
assert plaintext == data
```

### Supported Classes
- `uaes.AES_ECB(key)`
- `uaes.AES_CBC(key, iv=None)`
- `uaes.AES_CTR(key, iv=None)`
- `uaes.AES_GCM(key, iv=None)`
- `uaes.AES_CMAC(key)`

For full type hints and method signatures, refer to the included [`uaes.pyi`](uaes.pyi) stub file.

## Acknowledgements

The C backend is based on:
- [tiny-AES-c](https://github.com/kokke/tiny-AES-c)
- [aes-min](https://github.com/cmcqueen/aes-min) (Galois Field operations)
