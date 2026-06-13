import os
import time
import sys

# Ensure uaes module can be found if running from tests folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import uaes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def format_mbps(bytes_processed, duration_sec):
    mb = bytes_processed / (1024 * 1024)
    return mb / duration_sec

def benchmark_ecb():
    print("--- Benchmark: AES-128 ECB (1MB chunks, 100MB total) ---")
    key = os.urandom(16)

    chunk_size = 1024 * 1024
    num_chunks = 100
    total_bytes = chunk_size * num_chunks

    data = os.urandom(chunk_size)

    # --- cryptography ---
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    start = time.time()
    encryptor = cipher.encryptor()
    for _ in range(num_chunks):
        encryptor.update(data)
    encryptor.finalize()
    duration = time.time() - start
    print(f"  cryptography      (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt (allocating) ---
    u_ctx = uaes.AES_ECB(key)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.encrypt(data)
    duration = time.time() - start
    print(f"  uaes              (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt_into (in-place) ---
    buf = bytearray(data)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.encrypt_into(buf)
    duration = time.time() - start
    print(f"  uaes         (encrypt_into): {format_mbps(total_bytes, duration):>10.2f} MB/s")

def benchmark_ecb_small():
    print("\n--- Benchmark: AES-128 ECB (256B chunks, 25MB total) ---")
    key = os.urandom(16)

    chunk_size = 256
    num_chunks = 100000
    total_bytes = chunk_size * num_chunks

    data = os.urandom(chunk_size)

    # --- cryptography ---
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    start = time.time()
    encryptor = cipher.encryptor()
    for _ in range(num_chunks):
        encryptor.update(data)
    encryptor.finalize()
    duration = time.time() - start
    print(f"  cryptography      (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt (allocating) ---
    u_ctx = uaes.AES_ECB(key)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.encrypt(data)
    duration = time.time() - start
    print(f"  uaes              (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt_into (in-place) ---
    buf = bytearray(data)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.encrypt_into(buf)
    duration = time.time() - start
    print(f"  uaes         (encrypt_into): {format_mbps(total_bytes, duration):>10.2f} MB/s")

def benchmark_gcm():
    print("\n--- Benchmark: AES-128 GCM (64KB chunks, 100MB total) ---")
    key = os.urandom(16)
    iv = os.urandom(12)
    aad = os.urandom(16)

    chunk_size = 64 * 1024
    num_chunks = (100 * 1024 * 1024) // chunk_size
    total_bytes = chunk_size * num_chunks

    data = os.urandom(chunk_size)

    # --- cryptography ---
    start = time.time()
    for _ in range(num_chunks):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
    duration = time.time() - start
    print(f"  cryptography      (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt (allocating) ---
    u_ctx = uaes.AES_GCM(key)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.set_iv(iv)
        ct, tag = u_ctx.encrypt(data, aad)
    duration = time.time() - start
    print(f"  uaes              (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt_into (in-place) ---
    buf = bytearray(data)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.set_iv(iv)
        tag = u_ctx.encrypt_into(buf, aad=aad)
    duration = time.time() - start
    print(f"  uaes         (encrypt_into): {format_mbps(total_bytes, duration):>10.2f} MB/s")

def benchmark_gcm_small():
    print("\n--- Benchmark: AES-128 GCM (256B chunks, 25MB total) ---")
    key = os.urandom(16)
    iv = os.urandom(12)
    aad = os.urandom(16)

    chunk_size = 256
    num_chunks = 100000
    total_bytes = chunk_size * num_chunks

    data = os.urandom(chunk_size)

    # --- cryptography ---
    start = time.time()
    for _ in range(num_chunks):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
    duration = time.time() - start
    print(f"  cryptography      (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt (allocating) ---
    u_ctx = uaes.AES_GCM(key)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.set_iv(iv)
        ct, tag = u_ctx.encrypt(data, aad)
    duration = time.time() - start
    print(f"  uaes              (encrypt): {format_mbps(total_bytes, duration):>10.2f} MB/s")

    # --- uaes encrypt_into (in-place) ---
    buf = bytearray(data)

    start = time.time()
    for _ in range(num_chunks):
        u_ctx.set_iv(iv)
        tag = u_ctx.encrypt_into(buf, aad=aad)
    duration = time.time() - start
    print(f"  uaes         (encrypt_into): {format_mbps(total_bytes, duration):>10.2f} MB/s")

if __name__ == '__main__':
    benchmark_ecb()
    benchmark_ecb_small()
    benchmark_gcm()
    benchmark_gcm_small()
