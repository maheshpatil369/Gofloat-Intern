import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from crypto import AeadCipher, derive_nonce
from cryptography.exceptions import InvalidTag


def test_encrypt_decrypt_roundtrip():
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    nonce  = os.urandom(12)
    msg    = b"hello device b"
    aad    = b"header"
    ct     = cipher.encrypt(nonce, msg, aad)
    assert cipher.decrypt(nonce, ct, aad) == msg


def test_tag_appended_to_ciphertext():
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    nonce  = os.urandom(12)
    ct     = cipher.encrypt(nonce, b"test", b"")
    assert len(ct) == len(b"test") + 16


def test_tamper_ciphertext_raises():
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    nonce  = os.urandom(12)
    ct     = bytearray(cipher.encrypt(nonce, b"secret", b"aad"))
    ct[0] ^= 0x01
    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, bytes(ct), b"aad")


def test_tamper_aad_raises():
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    nonce  = os.urandom(12)
    ct     = cipher.encrypt(nonce, b"secret", b"original-aad")
    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, ct, b"modified-aad")


def test_wrong_key_raises():
    key1   = os.urandom(32)
    key2   = os.urandom(32)
    c1, c2 = AeadCipher(key1), AeadCipher(key2)
    nonce  = os.urandom(12)
    ct     = c1.encrypt(nonce, b"msg", b"")
    with pytest.raises(InvalidTag):
        c2.decrypt(nonce, ct, b"")


def test_aes_gcm_also_works():
    key    = os.urandom(32)
    cipher = AeadCipher(key, algorithm="aes-256-gcm")
    nonce  = os.urandom(12)
    ct     = cipher.encrypt(nonce, b"test aes", b"aad")
    assert cipher.decrypt(nonce, ct, b"aad") == b"test aes"


def test_derive_nonce_unique_per_seq():
    n1 = derive_nonce(0x00A1, 1)
    n2 = derive_nonce(0x00A1, 2)
    assert n1 != n2
    assert len(n1) == 12
    assert len(n2) == 12


def test_derive_nonce_unique_per_sender():
    n1 = derive_nonce(0x00A1, 1)
    n2 = derive_nonce(0x00B1, 1)
    assert n1 != n2


def test_derive_nonce_deterministic():
    assert derive_nonce(0x00A1, 42) == derive_nonce(0x00A1, 42)
