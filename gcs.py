#!/usr/bin/env python3
"""
GCS Python con soporte ChaCha20-Poly1305 para MAVLink v2
Basado en el prototipo de cifrado validado
"""

import socket
import struct
import binascii
import time
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pymavlink import mavutil
from pymavlink.dialects.v20 import common as mavlink2

# =============================================================================
# CONSTANTES
# =============================================================================

MAVLINK_V2_STX = 0xFD
MAVLINK_V2_HDR_LEN = 10
MAVLINK_IFLAG_SIGNED = 0x01

CHACHA_KEY_LEN = 32
CHACHA_NONCE_LEN = 12
CHACHA_TAG_LEN = 16

# =============================================================================
# CONTEXTO DE CIFRADO
# =============================================================================

class ChaChaContext:
    def __init__(self):
        self.key = None
        self.iv_boot = None
        self.initialized = False
        self.stats = {
            'encrypted': 0,
            'decrypted': 0,
            'decrypt_failed': 0
        }
    
    def init(self, key_hex, iv_boot_hex):
        """Inicializar con claves en hexadecimal (de ArduPilot)"""
        self.key = bytes.fromhex(key_hex)
        self.iv_boot = bytes.fromhex(iv_boot_hex)
        self.initialized = True
        print(f"[CHACHA] ✅ Initialized")
        print(f"[CHACHA] Key: {key_hex[:32]}...")
        print(f"[CHACHA] IV:  {iv_boot_hex}")

# =============================================================================
# FUNCIONES DE CIFRADO (del prototipo validado)
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

def decrypt_mavlink_message(ctx, msg_bytes):
    """Descifrar mensaje MAVLink v2"""
    if not ctx.initialized:
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
    
    if in_payload_len < CHACHA_TAG_LEN:
        return None
    
    ciphertext_with_tag = msg_bytes[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + in_payload_len]
    
    aad = build_aad_v2(in_payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
    nonce = build_nonce12(ctx.iv_boot, sysid, compid, seq)
    
    cipher = ChaCha20Poly1305(ctx.key)
    
    try:
        plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)
        ctx.stats['decrypted'] += 1
        print(f"[DECRYPT] msgid={msgid:3d} sysid={sysid} seq={seq:3d} | {get_msgid_name(msgid)}")
    except Exception as e:
        ctx.stats['decrypt_failed'] += 1
        print(f"[DECRYPT] msgid={msgid:3d} sysid={sysid} seq={seq:3d} | FAILED")
        return None
    
    # Reconstruir mensaje descifrado
    out = bytearray(msg_bytes[0:MAVLINK_V2_HDR_LEN])
    out[1] = len(plaintext)
    out.extend(plaintext)
    
    # CRC (usar crc_extra correcto según msgid)
    crc_extra = get_crc_extra(msgid)
    crc = crc16_mavlink(plaintext, crc_extra)
    out.append(crc & 0xFF)
    out.append((crc >> 8) & 0xFF)
    
    return bytes(out)

def encrypt_mavlink_message(ctx, msg_bytes):
    """Cifrar mensaje MAVLink v2 (para enviar a ArduPilot)"""
    if not ctx.initialized:
        return None
    
    if len(msg_bytes) < MAVLINK_V2_HDR_LEN + 2 or msg_bytes[0] != MAVLINK_V2_STX:
        return None
    
    in_payload_len = msg_bytes[1]
    incompat_flags = msg_bytes[2]
    compat_flags = msg_bytes[3]
    seq = msg_bytes[4]
    sysid = msg_bytes[5]
    compid = msg_bytes[6]
    msgid = msg_bytes[7] | (msg_bytes[8] << 8) | (msg_bytes[9] << 16)
    
    if incompat_flags & MAVLINK_IFLAG_SIGNED:
        return msg_bytes
    
    new_len = in_payload_len + CHACHA_TAG_LEN
    if new_len > 255:
        return msg_bytes
    
    plaintext = msg_bytes[MAVLINK_V2_HDR_LEN:MAVLINK_V2_HDR_LEN + in_payload_len]
    
    aad = build_aad_v2(new_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
    nonce = build_nonce12(ctx.iv_boot, sysid, compid, seq)
    
    cipher = ChaCha20Poly1305(ctx.key)
    ciphertext_with_tag = cipher.encrypt(nonce, plaintext, aad)
    
    out = bytearray(msg_bytes[0:MAVLINK_V2_HDR_LEN])
    out[1] = new_len
    out.extend(ciphertext_with_tag)
    
    crc_extra = get_crc_extra(msgid)
    crc = crc16_mavlink(ciphertext_with_tag, crc_extra)
    out.append(crc & 0xFF)
    out.append((crc >> 8) & 0xFF)
    
    ctx.stats['encrypted'] += 1
    return bytes(out)

# =============================================================================
# HELPERS MAVLink
# =============================================================================

def get_msgid_name(msgid):
    """Obtener nombre del mensaje por ID"""
    names = {
        0: "HEARTBEAT",
        1: "SYS_STATUS",
        24: "GPS_RAW_INT",
        30: "ATTITUDE",
        33: "GLOBAL_POSITION_INT",
        74: "VFR_HUD",
        76: "COMMAND_LONG",
        110: "NAMED_VALUE_FLOAT",
        253: "STATUSTEXT",
    }
    return names.get(msgid, f"UNKNOWN_{msgid}")

def get_crc_extra(msgid):
    """CRC extra para validación (algunos ejemplos)"""
    crc_extras = {
        0: 50,    # HEARTBEAT
        1: 124,   # SYS_STATUS
        24: 24,   # GPS_RAW_INT
        30: 39,   # ATTITUDE
        33: 104,  # GLOBAL_POSITION_INT
        74: 20,   # VFR_HUD
        76: 152,  # COMMAND_LONG
        110: 252, # NAMED_VALUE_FLOAT
        253: 83,  # STATUSTEXT
    }
    return crc_extras.get(msgid, 0)

# =============================================================================
# CLASE GCS
# =============================================================================

class ChaChaGCS:
    def __init__(self, host='127.0.0.1', port=5760):
        self.host = host
        self.port = port
        self.sock = None
        self.ctx = ChaChaContext()
        self.running = False
        
    def connect(self):
        """Conectar al puerto de ArduPilot"""
        print(f"[GCS] Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(0.1)
        print(f"[GCS] Connected")
        
    def init_crypto(self, key_hex, iv_hex):
        """Inicializar cifrado con claves de ArduPilot"""
        self.ctx.init(key_hex, iv_hex)
        
    def receive_message(self):
        """Recibir y descifrar un mensaje"""
        try:
            header = self.sock.recv(MAVLINK_V2_HDR_LEN)
            if len(header) < MAVLINK_V2_HDR_LEN:
                return None

            print(f"[DEBUG] Received header: {binascii.hexlify(header).decode()}")

            if header[0] != MAVLINK_V2_STX:
                print(f"[DEBUG] Not MAVLink v2 (STX={header[0]:02x})")
                return None

            payload_len = header[1]
            print(f"[DEBUG] Payload length: {payload_len}")
            # Aquí podrías continuar leyendo el payload luego...
            return header

        except socket.timeout:
            # Si no llega nada, simplemente continúa el loop
            return None
        except Exception as e:
            print(f"[ERROR] receive_message: {e}")
            return None

    
    def run(self):
        """Loop principal"""
        print("\n" + "="*80)
        print("GCS RUNNING - Press Ctrl+C to stop")
        print("="*80 + "\n")
        
        self.running = True
        msg_count = 0
        
        try:
            while self.running:
                msg = self.receive_message()
                if msg:
                    msg_count += 1
                    
                    # Cada 10 mensajes, mostrar estadísticas
                    if msg_count % 10 == 0:
                        print(f"\n[STATS] Total: {msg_count} | "
                              f"Decrypted: {self.ctx.stats['decrypted']} | "
                              f"Failed: {self.ctx.stats['decrypt_failed']}")
                
                time.sleep(0.01)
                
        except KeyboardInterrupt:
            print("\n\n[GCS] Shutting down...")
            self.stop()
    
    def stop(self):
        """Detener GCS"""
        self.running = False
        if self.sock:
            self.sock.close()
        
        print("\n" + "="*80)
        print("FINAL STATISTICS")
        print("="*80)
        print(f"Messages decrypted: {self.ctx.stats['decrypted']}")
        print(f"Decrypt failures:   {self.ctx.stats['decrypt_failed']}")
        print(f"Messages encrypted: {self.ctx.stats['encrypted']}")
        print("="*80)

# =============================================================================
# MAIN
# =============================================================================

def main():
    print("""
╔══════════════════════════════════════════════════════════════════════════╗
║          ChaCha20-Poly1305 GCS for ArduPilot                             ║
║          Python implementation with encryption support                    ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    # IMPORTANTE: Usar las MISMAS claves que genera ArduPilot
    # Copia estos valores de la consola de ArduPilot cuando arranca
    
    print("\n CONFIGURATION NEEDED:")
    print("=" * 80)
    print("You need to copy the KEY and IV_boot from ArduPilot console output.")
    print("Look for lines like:")
    print("  [CHACHA] Key: 26CC9E68CCB87B88...")
    print("  [CHACHA] IV_boot: 2AAB9CF2EE2DB5D0")
    print()
    
    # EJEMPLO - REEMPLAZAR con valores reales de ArduPilot
    KEY_HEX = input("Enter KEY (hex): ").strip()
    IV_HEX = input("Enter IV_boot (hex): ").strip()
    
    if len(KEY_HEX) != 64 or len(IV_HEX) != 16:
        print(" Invalid key/IV length")
        print("   KEY should be 64 hex chars (32 bytes)")
        print("   IV should be 16 hex chars (8 bytes)")
        return
    
    print("\n" + "="*80)
    
    # Crear y arrancar GCS
    gcs = ChaChaGCS(host='127.0.0.1', port=5760)
    
    try:
        gcs.connect()
        gcs.init_crypto(KEY_HEX, IV_HEX)
        gcs.run()
    except KeyboardInterrupt:
        print("\n[GCS] Interrupted by user")
        gcs.stop()
    except Exception as e:
        print(f"[ERROR] {e}")
        gcs.stop()

if __name__ == '__main__':
    main()
