#!/usr/bin/env python3
"""
Prototipo de cifrado ChaCha20-Poly1305 para MAVLink v2
Implementación de referencia antes de portar a C
"""

import struct
import binascii
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# =============================================================================
# CONSTANTES MAVLink
# =============================================================================

MAVLINK_V2_STX = 0xFD
MAVLINK_V2_HDR_LEN = 10
MAVLINK_IFLAG_SIGNED = 0x01
MAVLINK_IFLAG_ENCRYPTED = 0x02

CHACHA_KEY_LEN = 32
CHACHA_NONCE_LEN = 12
CHACHA_TAG_LEN = 16

# =============================================================================
# CONTEXTO GLOBAL
# =============================================================================

class ChaChaContext:
    def __init__(self):
        self.key = None
        self.iv_boot = None
        self.initialized = False
    
    def init(self, key=None, iv_boot=None):
        if key is None:
            self.key = os.urandom(CHACHA_KEY_LEN)
            print(f"[CHACHA] Generated random key: {binascii.hexlify(self.key).decode()}")
        else:
            self.key = key
            print(f"[CHACHA] Using provided key: {binascii.hexlify(self.key).decode()}")
        
        if iv_boot is None:
            self.iv_boot = os.urandom(8)
            print(f"[CHACHA] Generated random iv_boot: {binascii.hexlify(self.iv_boot).decode()}")
        else:
            self.iv_boot = iv_boot
            print(f"[CHACHA] Using provided iv_boot: {binascii.hexlify(self.iv_boot).decode()}")
        
        self.initialized = True

g_ctx = ChaChaContext()

# =============================================================================
# FUNCIONES DE CONSTRUCCIÓN DE AAD Y NONCE
# =============================================================================

def build_aad_v2(len_field, incompat_flags, compat_flags, seq, sysid, compid, msgid):
    aad = bytearray(10)
    aad[0] = len_field
    aad[1] = incompat_flags
    aad[2] = compat_flags
    aad[3] = seq
    aad[4] = sysid
    aad[5] = compid
    aad[6] = msgid & 0xFF
    aad[7] = (msgid >> 8) & 0xFF
    aad[8] = (msgid >> 16) & 0xFF
    aad[9] = 0
    return bytes(aad)

def build_nonce12(iv_boot, sysid, compid, seq):
    nonce = bytearray(12)
    nonce[0:8] = iv_boot
    nonce[8] = sysid
    nonce[9] = compid
    nonce[10] = seq
    nonce[11] = 0
    return bytes(nonce)

# =============================================================================
# CRC MAVLink
# =============================================================================

def crc16_mavlink(data, crc_extra=0):
    crc = 0xFFFF
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
        crc &= 0xFFFF
    if crc_extra:
        tmp = crc_extra ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
        crc &= 0xFFFF
    return crc

# =============================================================================
# CIFRADO
# =============================================================================

def encrypt_mavlink_message(msg_bytes, crc_extra=0):
    if not g_ctx.initialized:
        print("[ERROR] Contexto no inicializado")
        return None
    
    if len(msg_bytes) < MAVLINK_V2_HDR_LEN + 2 or msg_bytes[0] != MAVLINK_V2_STX:
        print("[ERROR] No es MAVLink v2 válido")
        return None
    
    in_payload_len = msg_bytes[1]
    incompat_flags = msg_bytes[2]
    compat_flags = msg_bytes[3]
    seq = msg_bytes[4]
    sysid = msg_bytes[5]
    compid = msg_bytes[6]
    msgid = msg_bytes[7] | (msg_bytes[8] << 8) | (msg_bytes[9] << 16)
    
    print(f"\n[ENCRYPT] msgid={msgid}, sysid={sysid}, compid={compid}, seq={seq}")
    
    if incompat_flags & MAVLINK_IFLAG_SIGNED:
        return msg_bytes
    
    new_len = in_payload_len + CHACHA_TAG_LEN
    if new_len > 255:
        return msg_bytes
    
    plaintext = msg_bytes[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + in_payload_len]
    print(f"[ENCRYPT] Plaintext: {binascii.hexlify(plaintext).decode()}")
    
    aad = build_aad_v2(new_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
    nonce = build_nonce12(g_ctx.iv_boot, sysid, compid, seq)
    
    cipher = ChaCha20Poly1305(g_ctx.key)
    ciphertext_with_tag = cipher.encrypt(nonce, plaintext, aad)
    
    out = bytearray(msg_bytes[0:MAVLINK_V2_HDR_LEN])
    out[1] = new_len
    out.extend(ciphertext_with_tag)
    
    crc = crc16_mavlink(ciphertext_with_tag, crc_extra)
    out.append(crc & 0xFF)
    out.append((crc >> 8) & 0xFF)
    
    print(f"[ENCRYPT] Output: {binascii.hexlify(out).decode()}")
    return bytes(out)

# =============================================================================
# DESCIFRADO
# =============================================================================

def decrypt_mavlink_message(msg_bytes, crc_extra=0):
    if not g_ctx.initialized:
        return None
    
    if len(msg_bytes) < MAVLINK_V2_HDR_LEN + CHACHA_TAG_LEN + 2:
        return None
    
    if msg_bytes[0] != MAVLINK_V2_STX:
        return None
    
    in_payload_len = msg_bytes[1]
    incompat_flags = msg_bytes[2]
    compat_flags = msg_bytes[3]
    seq = msg_bytes[4]
    sysid = msg_bytes[5]
    compid = msg_bytes[6]
    msgid = msg_bytes[7] | (msg_bytes[8] << 8) | (msg_bytes[9] << 16)
    
    print(f"\n[DECRYPT] msgid={msgid}, sysid={sysid}, compid={compid}, seq={seq}")
    
    if in_payload_len < CHACHA_TAG_LEN:
        return None
    
    ciphertext_with_tag = msg_bytes[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + in_payload_len]
    
    aad = build_aad_v2(in_payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
    nonce = build_nonce12(g_ctx.iv_boot, sysid, compid, seq)
    
    cipher = ChaCha20Poly1305(g_ctx.key)
    
    try:
        plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)
        print(f"[DECRYPT] ✅ SUCCESS")
        print(f"[DECRYPT] Plaintext: {binascii.hexlify(plaintext).decode()}")
    except Exception as e:
        print(f"[DECRYPT] ❌ FAILED: {e}")
        return None
    
    out = bytearray(msg_bytes[0:MAVLINK_V2_HDR_LEN])
    out[1] = len(plaintext)
    out.extend(plaintext)
    
    crc = crc16_mavlink(plaintext, crc_extra)
    out.append(crc & 0xFF)
    out.append((crc >> 8) & 0xFF)
    
    print(f"[DECRYPT] Output: {binascii.hexlify(out).decode()}")
    return bytes(out)

# =============================================================================
# TESTS
# =============================================================================

def create_test_mavlink_message():
    """Crear mensaje HEARTBEAT"""
    msg = bytearray()
    msg.append(MAVLINK_V2_STX)
    msg.append(9)   # LEN
    msg.append(0)   # Incompat
    msg.append(0)   # Compat
    msg.append(42)  # Seq
    msg.append(1)   # Sysid
    msg.append(1)   # Compid
    msg.append(0)   # Msgid[0]
    msg.append(0)   # Msgid[1]
    msg.append(0)   # Msgid[2]
    
    # Payload: 9 bytes exactos
    payload = bytearray([2, 3, 81, 0, 0, 0, 0, 4, 3])
    assert len(payload) == 9
    msg.extend(payload)
    
    crc_extra = 50
    crc = crc16_mavlink(payload, crc_extra)
    msg.append(crc & 0xFF)
    msg.append((crc >> 8) & 0xFF)
    
    return bytes(msg), crc_extra

def test_roundtrip():
    print("="*80)
    print("TEST: Round-trip")
    print("="*80)
    
    test_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
    test_iv = bytes.fromhex('aabbccddeeff0011')
    g_ctx.init(key=test_key, iv_boot=test_iv)
    
    original, crc_extra = create_test_mavlink_message()
    print(f"\nOriginal: {binascii.hexlify(original).decode()}")
    
    encrypted = encrypt_mavlink_message(original, crc_extra)
    if not encrypted:
        return False
    
    decrypted = decrypt_mavlink_message(encrypted, crc_extra)
    if not decrypted:
        return False
    
    if decrypted == original:
        print("\n✅ SUCCESS")
        return True
    else:
        print(f"\n❌ FAIL")
        print(f"Expected: {binascii.hexlify(original).decode()}")
        print(f"Got:      {binascii.hexlify(decrypted).decode()}")
        return False

def test_tampering():
    print("\n" + "="*80)
    print("TEST: Tampering")
    print("="*80)
    
    test_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
    test_iv = bytes.fromhex('aabbccddeeff0011')
    g_ctx.init(key=test_key, iv_boot=test_iv)
    
    original, crc_extra = create_test_mavlink_message()
    encrypted = encrypt_mavlink_message(original, crc_extra)
    
    tampered = bytearray(encrypted)
    tampered[15] ^= 0xFF
    
    result = decrypt_mavlink_message(bytes(tampered), crc_extra)
    
    if result is None:
        print("\n✅ Tampering detected")
        return True
    else:
        print("\n❌ Tampering NOT detected")
        return False

def save_test_vectors():
    print("\n" + "="*80)
    print("SAVING TEST VECTORS")
    print("="*80)
    
    test_key = bytes.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
    test_iv = bytes.fromhex('aabbccddeeff0011')
    g_ctx.init(key=test_key, iv_boot=test_iv)
    
    original, crc_extra = create_test_mavlink_message()
    encrypted = encrypt_mavlink_message(original, crc_extra)
    
    if not encrypted:
        print("❌ Error")
        return
    
    with open('test_vectors.txt', 'w') as f:
        f.write("# ChaCha20-Poly1305 Test Vectors\n\n")
        f.write(f"KEY: {binascii.hexlify(test_key).decode()}\n")
        f.write(f"IV_BOOT: {binascii.hexlify(test_iv).decode()}\n")
        f.write(f"CRC_EXTRA: {crc_extra}\n\n")
        f.write(f"ORIGINAL: {binascii.hexlify(original).decode()}\n")
        f.write(f"ENCRYPTED: {binascii.hexlify(encrypted).decode()}\n")
    
    print("✅ Saved to test_vectors.txt")

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║          ChaCha20-Poly1305 MAVLink - Python Prototype                    ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    t1 = test_roundtrip()
    t2 = test_tampering()
    save_test_vectors()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Round-trip:  {'✅ PASS' if t1 else '❌ FAIL'}")
    print(f"Tampering:   {'✅ PASS' if t2 else '❌ FAIL'}")
    print("="*80)