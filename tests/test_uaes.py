import os
import uaes

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ==============================================================================
# HARDCODED NIST TEST VECTORS (Known Answer Tests)
# ==============================================================================

NIST_VECTORS = [
    {
        "name": "NIST_ECB_128",
        "mode": "ECB",
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "iv": None,
        "pt": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "ct": bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_ECB_192",
        "mode": "ECB",
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        "iv": None,
        "pt": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "ct": bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_ECB_256",
        "mode": "ECB",
        "key": bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        "iv": None,
        "pt": bytes.fromhex("00112233445566778899aabbccddeeff"),
        "ct": bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CBC_128",
        "mode": "CBC",
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "iv": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("7649abac8119b246cee98e9b12e9197d"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CTR_128",
        "mode": "CTR",
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "iv": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("874d6191b620e3261bef6864990db6ce"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_GCM_128",
        "mode": "GCM",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308"),
        "iv": bytes.fromhex("cafebabefacedbaddecaf888"),
        "pt": bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        "ct": bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),
        "aad": bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        "tag": bytes.fromhex("da80ce830cfda02da2a218a1744f4c76")
    },
    {
        "name": "NIST_CMAC_128",
        "mode": "CMAC",
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "iv": None,
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": b"",
        "aad": b"",
        "tag": bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
    },
    {
        "name": "NIST_CBC_192",
        "mode": "CBC",
        "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        "iv": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("4f021db243bc633d7178183a9fa071e8"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CTR_192",
        "mode": "CTR",
        "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        "iv": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("1abc932417521ca24f2b0459fe7e6e0b"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CMAC_192",
        "mode": "CMAC",
        "key": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
        "iv": None,
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": b"",
        "aad": b"",
        "tag": bytes.fromhex("9e99a7bf31e710900662f65e617c5184")
    },
    {
        "name": "NIST_CBC_256",
        "mode": "CBC",
        "key": bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        "iv": bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CTR_256",
        "mode": "CTR",
        "key": bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        "iv": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": bytes.fromhex("601ec313775789a5b7a7f504bbf3d228"),
        "aad": b"",
        "tag": b""
    },
    {
        "name": "NIST_CMAC_256",
        "mode": "CMAC",
        "key": bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        "iv": None,
        "pt": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        "ct": b"",
        "aad": b"",
        "tag": bytes.fromhex("28a7023f452e8f82bd4bf28d8c37c35c")
    },
    {
        "name": "NIST_GCM_192",
        "mode": "GCM",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
        "iv": bytes.fromhex("cafebabefacedbaddecaf888"),
        "pt": bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        "ct": bytes.fromhex("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256"),
        "aad": bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        "tag": bytes.fromhex("12c9ff85fbe15c9c5757bee6fac3c674")
    },
    {
        "name": "NIST_GCM_256",
        "mode": "GCM",
        "key": bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
        "iv": bytes.fromhex("cafebabefacedbaddecaf888"),
        "pt": bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        "ct": bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"),
        "aad": bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        "tag": bytes.fromhex("2df7cd675b4f09163b41ebf980a7f638")
    }
]

# ==============================================================================
# DYNAMIC RANDOM TEST VECTORS (Using python's cryptography)
# ==============================================================================

def generate_random_vector(key_len, mode, pt_len=64, aad_len=32):
    key = os.urandom(key_len // 8)
    pt = os.urandom(pt_len)
    aad = os.urandom(aad_len) if aad_len > 0 else b""
    iv = b""
    ct = b""
    tag = b""

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
    elif mode == "CBC":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
    elif mode == "CTR":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
    elif mode == "GCM":
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(pt) + encryptor.finalize()
        tag = encryptor.tag
    elif mode == "CMAC":
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(pt)
        tag = c.finalize()

    return {
        "name": f"RND_{mode}_{key_len}",
        "mode": mode,
        "key": key,
        "iv": iv,
        "pt": pt,
        "ct": ct,
        "aad": aad,
        "tag": tag
    }

def generate_random_vectors():
    if not HAS_CRYPTOGRAPHY:
        return []

    rnd_vectors = []
    for key_len in [128, 192, 256]:
        for mode in ["ECB", "CBC", "CTR", "GCM", "CMAC"]:
            # Make sure pt length is block aligned for ECB and CBC
            if mode in ["ECB", "CBC"]:
                pt_len = 64
            else:
                pt_len = 61 # arbitrary non-block aligned size
            rnd_vectors.append(generate_random_vector(key_len, mode, pt_len=pt_len, aad_len=33 if mode == "GCM" else 0))
    return rnd_vectors

# ==============================================================================
# TEST RUNNER
# ==============================================================================

def run_tests():
    vectors = NIST_VECTORS + generate_random_vectors()
    passed = 0

    for v in vectors:
        name = v['name']
        try:
            if v['mode'] == 'ECB':
                ctx = uaes.AES_ECB(key=v['key'])
                # AES_ECB processes in blocks
                # Test multi-block at once
                ct_full = ctx.encrypt(v['pt'])
                assert ct_full == v['ct'], f"CT full mismatch. Expected {v['ct'].hex()}, got {ct_full.hex()}"
                pt_full = ctx.decrypt(v['ct'])
                assert pt_full == v['pt'], "PT full mismatch"

                # Test chunked processing
                ct = b''
                for i in range(0, len(v['pt']), 16):
                    ct += ctx.encrypt(v['pt'][i:i+16])
                assert ct == v['ct'], f"CT chunked mismatch. Expected {v['ct'].hex()}, got {ct.hex()}"

                pt = b''
                for i in range(0, len(v['ct']), 16):
                    pt += ctx.decrypt(v['ct'][i:i+16])
                assert pt == v['pt'], "PT chunked mismatch"

            elif v['mode'] == 'CBC':
                ctx = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                # Test multi-block at once
                ct_full = ctx.encrypt(v['pt'])
                assert ct_full == v['ct'], f"CT full mismatch. Expected {v['ct'].hex()}, got {ct_full.hex()}"
                ctx = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                pt_full = ctx.decrypt(v['ct'])
                assert pt_full == v['pt'], "PT full mismatch"

                # Test chunked processing
                ctx = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                ct = b''
                for i in range(0, len(v['pt']), 16):
                    ct += ctx.encrypt(v['pt'][i:i+16])
                assert ct == v['ct'], f"CT chunked mismatch. Expected {v['ct'].hex()}, got {ct.hex()}"

                ctx = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                pt = b''
                for i in range(0, len(v['ct']), 16):
                    pt += ctx.decrypt(v['ct'][i:i+16])
                assert pt == v['pt'], "PT chunked mismatch"

                # Test set_iv
                ctx_set_iv = uaes.AES_CBC(key=v['key'])
                ctx_set_iv.set_iv(v['iv'])
                ct_set_iv = b''
                for i in range(0, len(v['pt']), 16):
                    ct_set_iv += ctx_set_iv.encrypt(v['pt'][i:i+16])
                assert ct_set_iv == v['ct'], "set_iv CT mismatch"

            elif v['mode'] == 'CTR':
                ctx = uaes.AES_CTR(key=v['key'], iv=v['iv'])
                ct = ctx.crypt(v['pt'])
                assert ct == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {ct.hex()}"

                ctx = uaes.AES_CTR(key=v['key'], iv=v['iv'])
                pt = ctx.crypt(v['ct'])
                assert pt == v['pt'], "PT mismatch"

                # Test set_iv and set_ctr
                ctx_set_iv = uaes.AES_CTR(key=v['key'])
                ctx_set_iv.set_iv(v['iv'])
                ct_set_iv = ctx_set_iv.crypt(v['pt'])
                assert ct_set_iv == v['ct'], "set_iv CT mismatch"

                ctx_set_ctr = uaes.AES_CTR(key=v['key'])
                ctr_val = int.from_bytes(v['iv'][12:16], byteorder='big')
                ctx_set_ctr.set_iv(iv=v['iv'], ctr=ctr_val)
                ct_set_ctr = ctx_set_ctr.crypt(v['pt'])
                assert ct_set_ctr == v['ct'], "set_ctr CT mismatch"

            elif v['mode'] == 'GCM':
                ctx = uaes.AES_GCM(key=v['key'], iv=v['iv'])
                ct, tag = ctx.encrypt(data=v['pt'], aad=v['aad'] if v['aad'] else None, tag_len=len(v['tag']))
                assert ct == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {ct.hex()}"
                assert tag == v['tag'], f"Tag mismatch. Expected {v['tag'].hex()}, got {tag.hex()}"

                ctx = uaes.AES_GCM(key=v['key'], iv=v['iv'])
                pt = ctx.decrypt(data=v['ct'], tag=v['tag'], aad=v['aad'] if v['aad'] else None)
                assert pt == v['pt'], "PT mismatch"

                # Test set_iv
                ctx_set_iv = uaes.AES_GCM(key=v['key'])
                ctx_set_iv.set_iv(v['iv'])
                ct_set_iv, tag_set_iv = ctx_set_iv.encrypt(data=v['pt'], aad=v['aad'] if v['aad'] else None, tag_len=len(v['tag']))
                assert ct_set_iv == v['ct'] and tag_set_iv == v['tag'], "set_iv CT/Tag mismatch"

            elif v['mode'] == 'CMAC':
                ctx = uaes.AES_CMAC(key=v['key'])
                tag = ctx.cmac(data=v['pt'], mac_len=len(v['tag']))
                assert tag == v['tag'], f"Tag mismatch. Expected {v['tag'].hex()}, got {tag.hex()}"

            print(f"[PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")

    print(f"Passed {passed} / {len(vectors)} tests.")
    if passed != len(vectors):
        exit(1)

def run_into_tests():
    """Test all _into (in-place) methods against the same vectors."""
    vectors = NIST_VECTORS + generate_random_vectors()
    passed = 0
    total = 0

    for v in vectors:
        name = v['name'] + "_into"
        try:
            if v['mode'] == 'ECB':
                total += 1
                # encrypt_into
                buf = bytearray(v['pt'])
                ctx = uaes.AES_ECB(key=v['key'])
                ctx.encrypt_into(buf)
                assert buf == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {buf.hex()}"

                # decrypt_into
                ctx.decrypt_into(buf)
                assert buf == v['pt'], "PT mismatch"

                # Verify bytes input is rejected
                try:
                    ctx.encrypt_into(v['pt'])
                    assert False, "Should reject bytes input"
                except TypeError:
                    pass

            elif v['mode'] == 'CBC':
                total += 1
                # encrypt_into
                buf = bytearray(v['pt'])
                ctx = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                ctx.encrypt_into(buf)
                assert buf == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {buf.hex()}"

                # decrypt_into
                ctx2 = uaes.AES_CBC(key=v['key'], iv=v['iv'])
                ctx2.decrypt_into(buf)
                assert buf == v['pt'], "PT mismatch"

            elif v['mode'] == 'CTR':
                total += 1
                # crypt_into (encrypt)
                buf = bytearray(v['pt'])
                ctx = uaes.AES_CTR(key=v['key'], iv=v['iv'])
                ctx.crypt_into(buf)
                assert buf == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {buf.hex()}"

                # crypt_into (decrypt)
                ctx2 = uaes.AES_CTR(key=v['key'], iv=v['iv'])
                ctx2.crypt_into(buf)
                assert buf == v['pt'], "PT mismatch"

            elif v['mode'] == 'GCM':
                total += 1
                # encrypt_into: returns tag, encrypts buffer in-place
                buf = bytearray(v['pt'])
                ctx = uaes.AES_GCM(key=v['key'], iv=v['iv'])
                tag = ctx.encrypt_into(buf, aad=v['aad'] if v['aad'] else None, tag_len=len(v['tag']))
                assert buf == v['ct'], f"CT mismatch. Expected {v['ct'].hex()}, got {bytes(buf).hex()}"
                assert tag == v['tag'], f"Tag mismatch. Expected {v['tag'].hex()}, got {tag.hex()}"

                # decrypt_into: decrypts in-place, returns None
                ctx2 = uaes.AES_GCM(key=v['key'], iv=v['iv'])
                result = ctx2.decrypt_into(buf, tag=v['tag'], aad=v['aad'] if v['aad'] else None)
                assert result is None, "decrypt_into should return None"
                assert buf == v['pt'], "PT mismatch"

                # Verify bad tag raises ValueError
                ctx3 = uaes.AES_GCM(key=v['key'], iv=v['iv'])
                bad_tag = bytes(len(v['tag']))
                buf_bad = bytearray(v['ct'])
                try:
                    ctx3.decrypt_into(buf_bad, tag=bad_tag, aad=v['aad'] if v['aad'] else None)
                    assert False, "Should raise ValueError for bad tag"
                except ValueError:
                    pass

            elif v['mode'] == 'CMAC':
                # No _into method for CMAC
                continue

            print(f"[PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")

    print(f"Passed {passed} / {total} _into tests.")
    if passed != total:
        exit(1)

if __name__ == '__main__':
    run_tests()
    print()
    run_into_tests()
