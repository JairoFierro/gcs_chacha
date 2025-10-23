#!/usr/bin/env python3
"""
GCS Python con soporte ChaCha20-Poly1305 para MAVLink v2
Con capacidad de enviar comandos al dron
"""

import socket
import struct
import binascii
import time
import sys
import threading
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# =============================================================================
# CONSTANTES
# =============================================================================

MAVLINK_V2_STX = 0xFD
MAVLINK_V2_HDR_LEN = 10
MAVLINK_IFLAG_SIGNED = 0x01

CHACHA_KEY_LEN = 32
CHACHA_NONCE_LEN = 12
CHACHA_TAG_LEN = 16

# MAVLink message IDs
MAVLINK_MSG_ID_HEARTBEAT = 0
MAVLINK_MSG_ID_COMMAND_LONG = 76
MAVLINK_MSG_ID_SET_MODE = 11
MAVLINK_MSG_ID_PARAM_REQUEST_READ = 20
MAVLINK_MSG_ID_MISSION_REQUEST_LIST = 43

# MAV_CMD commands
MAV_CMD_NAV_TAKEOFF = 22
MAV_CMD_NAV_LAND = 21
MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_COMPONENT_ARM_DISARM = 400
MAV_CMD_DO_SET_MODE = 176

# Flight modes (ArduCopter)
COPTER_MODE_STABILIZE = 0
COPTER_MODE_ACRO = 1
COPTER_MODE_ALT_HOLD = 2
COPTER_MODE_AUTO = 3
COPTER_MODE_GUIDED = 4
COPTER_MODE_LOITER = 5
COPTER_MODE_RTL = 6
COPTER_MODE_LAND = 9

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
# FUNCIONES DE CIFRADO
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
        print(f"[DECRYPT] ✅ msgid={msgid:3d} sysid={sysid} seq={seq:3d} | {get_msgid_name(msgid)}")
    except Exception as e:
        ctx.stats['decrypt_failed'] += 1
        print(f"[DECRYPT] ❌ msgid={msgid:3d} sysid={sysid} seq={seq:3d} | FAILED")
        return None
    
    out = bytearray(msg_bytes[0:MAVLINK_V2_HDR_LEN])
    out[1] = len(plaintext)
    out.extend(plaintext)
    
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
    print(f"[ENCRYPT] 📤 msgid={msgid} sysid={sysid} seq={seq}")
    return bytes(out)

# =============================================================================
# HELPERS MAVLink
# =============================================================================

def get_msgid_name(msgid):
    """Obtener nombre del mensaje por ID"""
    names = {
        0: "HEARTBEAT",
        1: "SYS_STATUS",
        11: "SET_MODE",
        24: "GPS_RAW_INT",
        30: "ATTITUDE",
        33: "GLOBAL_POSITION_INT",
        74: "VFR_HUD",
        76: "COMMAND_LONG",
        77: "COMMAND_ACK",
        110: "NAMED_VALUE_FLOAT",
        253: "STATUSTEXT",
    }
    return names.get(msgid, f"UNKNOWN_{msgid}")

def get_crc_extra(msgid):
    """CRC extra para validación"""
    crc_extras = {
        0: 50,    # HEARTBEAT
        1: 124,   # SYS_STATUS
        11: 89,   # SET_MODE
        24: 24,   # GPS_RAW_INT
        30: 39,   # ATTITUDE
        33: 104,  # GLOBAL_POSITION_INT
        74: 20,   # VFR_HUD
        76: 152,  # COMMAND_LONG
        77: 143,  # COMMAND_ACK
        110: 252, # NAMED_VALUE_FLOAT
        253: 83,  # STATUSTEXT
    }
    return crc_extras.get(msgid, 0)

# =============================================================================
# BUILDERS DE MENSAJES MAVLink
# =============================================================================

def build_heartbeat(sysid=255, compid=190, seq=0):
    """Construir mensaje HEARTBEAT"""
    msg = bytearray()
    msg.append(MAVLINK_V2_STX)
    msg.append(9)   # payload length
    msg.append(0)   # incompat_flags
    msg.append(0)   # compat_flags
    msg.append(seq & 0xFF)
    msg.append(sysid)
    msg.append(compid)
    msg.append(0)   # msgid (HEARTBEAT)
    msg.append(0)
    msg.append(0)
    
    # Payload: MAV_TYPE_GCS(6), MAV_AUTOPILOT_INVALID(8), base_mode(0), custom_mode(0), system_status(0)
    payload = struct.pack('<IBBBB', 0, 6, 8, 0, 0)
    msg.extend(payload)
    
    crc = crc16_mavlink(payload, 50)  # CRC_EXTRA para HEARTBEAT
    msg.append(crc & 0xFF)
    msg.append((crc >> 8) & 0xFF)
    
    return bytes(msg)

def build_command_long(command, param1=0, param2=0, param3=0, param4=0, 
                       param5=0, param6=0, param7=0, 
                       target_sysid=1, target_compid=1, 
                       sysid=255, compid=190, seq=0):
    """Construir mensaje COMMAND_LONG"""
    msg = bytearray()
    msg.append(MAVLINK_V2_STX)
    msg.append(33)  # payload length
    msg.append(0)   # incompat_flags
    msg.append(0)   # compat_flags
    msg.append(seq & 0xFF)
    msg.append(sysid)
    msg.append(compid)
    msg.append(76)  # msgid COMMAND_LONG
    msg.append(0)
    msg.append(0)
    
    # Payload
    payload = struct.pack('<fffffffHBBB',
                         param1, param2, param3, param4,
                         param5, param6, param7,
                         command,
                         target_sysid, target_compid,
                         0)  # confirmation
    msg.extend(payload)
    
    crc = crc16_mavlink(payload, 152)  # CRC_EXTRA para COMMAND_LONG
    msg.append(crc & 0xFF)
    msg.append((crc >> 8) & 0xFF)
    
    return bytes(msg)

def build_set_mode(custom_mode, base_mode=1, target_sysid=1, sysid=255, compid=190, seq=0):
    """Construir mensaje SET_MODE"""
    msg = bytearray()
    msg.append(MAVLINK_V2_STX)
    msg.append(6)   # payload length
    msg.append(0)   # incompat_flags
    msg.append(0)   # compat_flags
    msg.append(seq & 0xFF)
    msg.append(sysid)
    msg.append(compid)
    msg.append(11)  # msgid SET_MODE
    msg.append(0)
    msg.append(0)
    
    # Payload
    payload = struct.pack('<IBB', custom_mode, target_sysid, base_mode)
    msg.extend(payload)
    
    crc = crc16_mavlink(payload, 89)  # CRC_EXTRA para SET_MODE
    msg.append(crc & 0xFF)
    msg.append((crc >> 8) & 0xFF)
    
    return bytes(msg)

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
        self.seq = 0
        self.sysid = 255
        self.compid = 190
        
    def get_next_seq(self):
        """Obtener siguiente número de secuencia"""
        seq = self.seq
        self.seq = (self.seq + 1) % 256
        return seq
        
    def connect(self):
        """Conectar al puerto de ArduPilot"""
        print(f"[GCS] Connecting to {self.host}:{self.port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(0.1)
        print(f"[GCS] ✅ Connected")
        
    def init_crypto(self, key_hex, iv_hex):
        """Inicializar cifrado con claves de ArduPilot"""
        self.ctx.init(key_hex, iv_hex)
        
    def send_message(self, msg_bytes):
        """Enviar mensaje (cifrado si está habilitado)"""
        if self.ctx.initialized:
            encrypted = encrypt_mavlink_message(self.ctx, msg_bytes)
            if encrypted:
                self.sock.sendall(encrypted)
            else:
                print("[ERROR] Failed to encrypt message")
        else:
            self.sock.sendall(msg_bytes)
            
    def receive_message(self):
        """Recibir y descifrar un mensaje"""
        try:
            header = self.sock.recv(MAVLINK_V2_HDR_LEN)
            if len(header) < MAVLINK_V2_HDR_LEN:
                return None
                
            if header[0] != MAVLINK_V2_STX:
                return None
            
            payload_len = header[1]
            
            remaining = payload_len + 2
            payload_crc = b''
            while len(payload_crc) < remaining:
                chunk = self.sock.recv(remaining - len(payload_crc))
                if not chunk:
                    return None
                payload_crc += chunk
            
            full_msg = header + payload_crc
            
            # Intentar descifrar
            decrypted = decrypt_mavlink_message(self.ctx, full_msg)
            
            return decrypted if decrypted else full_msg
            
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[ERROR] {e}")
            return None
    
    # =============================================================================
    # COMANDOS DE ALTO NIVEL
    # =============================================================================
    
    def send_heartbeat(self):
        """Enviar HEARTBEAT"""
        msg = build_heartbeat(self.sysid, self.compid, self.get_next_seq())
        self.send_message(msg)
        print("[CMD] 💓 Sent HEARTBEAT")
    
    def arm(self):
        """Armar el dron"""
        msg = build_command_long(
            MAV_CMD_COMPONENT_ARM_DISARM,
            param1=1,  # 1=arm, 0=disarm
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print("[CMD] 🔓 ARM command sent")
    
    def disarm(self):
        """Desarmar el dron"""
        msg = build_command_long(
            MAV_CMD_COMPONENT_ARM_DISARM,
            param1=0,  # 0=disarm
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print("[CMD] 🔒 DISARM command sent")
    
    def takeoff(self, altitude=10):
        """Despegar a una altitud específica"""
        msg = build_command_long(
            MAV_CMD_NAV_TAKEOFF,
            param7=altitude,  # altitude in meters
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print(f"[CMD] 🚁 TAKEOFF to {altitude}m sent")
    
    def land(self):
        """Aterrizar"""
        msg = build_command_long(
            MAV_CMD_NAV_LAND,
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print("[CMD] 🛬 LAND command sent")
    
    def rtl(self):
        """Return to Launch"""
        msg = build_command_long(
            MAV_CMD_NAV_RETURN_TO_LAUNCH,
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print("[CMD] 🏠 RTL command sent")
    
    def set_mode(self, mode_name):
        """Cambiar modo de vuelo"""
        modes = {
            'STABILIZE': COPTER_MODE_STABILIZE,
            'ACRO': COPTER_MODE_ACRO,
            'ALT_HOLD': COPTER_MODE_ALT_HOLD,
            'AUTO': COPTER_MODE_AUTO,
            'GUIDED': COPTER_MODE_GUIDED,
            'LOITER': COPTER_MODE_LOITER,
            'RTL': COPTER_MODE_RTL,
            'LAND': COPTER_MODE_LAND,
        }
        
        if mode_name.upper() not in modes:
            print(f"[ERROR] Unknown mode: {mode_name}")
            return
        
        custom_mode = modes[mode_name.upper()]
        msg = build_set_mode(
            custom_mode,
            base_mode=1,
            target_sysid=1,
            sysid=self.sysid,
            compid=self.compid,
            seq=self.get_next_seq()
        )
        self.send_message(msg)
        print(f"[CMD] ✈️  SET_MODE to {mode_name} sent")
    
    # =============================================================================
    # LOOP PRINCIPAL
    # =============================================================================
    
    def run(self):
        """Loop principal con interfaz de comandos"""
        print("\n" + "="*80)
        print("GCS RUNNING")
        print("="*80)
        print("\nAvailable commands:")
        print("  heartbeat  - Send heartbeat")
        print("  arm        - Arm motors")
        print("  disarm     - Disarm motors")
        print("  takeoff [alt] - Takeoff to altitude (default 10m)")
        print("  land       - Land")
        print("  rtl        - Return to launch")
        print("  mode <name> - Set flight mode (GUIDED, AUTO, RTL, etc)")
        print("  quit       - Exit\n")
        print("="*80 + "\n")
        
        self.running = True
        
        # Thread para recibir mensajes
        receive_thread = threading.Thread(target=self._receive_loop)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Thread para enviar heartbeats periódicos
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
        # Loop de comandos
        try:
            while self.running:
                try:
                    cmd = input("[GCS] > ").strip().lower()
                    
                    if not cmd:
                        continue
                    
                    parts = cmd.split()
                    command = parts[0]
                    
                    if command == 'quit' or command == 'exit':
                        break
                    elif command == 'heartbeat':
                        self.send_heartbeat()
                    elif command == 'arm':
                        self.arm()
                    elif command == 'disarm':
                        self.disarm()
                    elif command == 'takeoff':
                        alt = float(parts[1]) if len(parts) > 1 else 10
                        self.takeoff(alt)
                    elif command == 'land':
                        self.land()
                    elif command == 'rtl':
                        self.rtl()
                    elif command == 'mode':
                        if len(parts) < 2:
                            print("[ERROR] Usage: mode <MODE_NAME>")
                        else:
                            self.set_mode(parts[1])
                    else:
                        print(f"[ERROR] Unknown command: {command}")
                        
                except EOFError:
                    break
                except Exception as e:
                    print(f"[ERROR] {e}")
                
        except KeyboardInterrupt:
            print("\n\n[GCS] Shutting down...")
        
        self.stop()
    
    def _receive_loop(self):
        """Loop para recibir mensajes (corre en thread separado)"""
        while self.running:
            try:
                msg = self.receive_message()
                time.sleep(0.01)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Receive loop: {e}")
                break
    
    def _heartbeat_loop(self):
        """Enviar heartbeat cada segundo"""
        while self.running:
            try:
                self.send_heartbeat()
                time.sleep(1)
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Heartbeat loop: {e}")
                break
    
    def stop(self):
        """Detener GCS"""
        self.running = False
        time.sleep(0.5)
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
║          Python implementation with encryption & command support          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    print("\n⚙️  CONFIGURATION:")
    print("=" * 80)
    print("Copy KEY and IV_boot from ArduPilot console")
    print()
    
    KEY_HEX = input("Enter KEY (hex): ").strip()
    IV_HEX = input("Enter IV_boot (hex): ").strip()
    
    if len(KEY_HEX) != 64 or len(IV_HEX) != 16:
        print("❌ Invalid key/IV length")
        return
    
    print("\n" + "="*80)
    
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
        import traceback
        traceback.print_exc()
        gcs.stop()

if __name__ == '__main__':
    main()