#!/usr/bin/env python3
"""
GCS con ChaCha20-Poly1305 - Monitoreo de telemetría del Bebop
Basado en test_simple_fixed.py que funciona
"""

from pymavlink import mavutil
import time
import socket
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# =============================================================================
# CONFIGURACIÓN DE CHACHA20 (debe coincidir con ArduPilot)
# =============================================================================

KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
IV_HEX = "aabbccddeeff0011"

CHACHA_KEY = bytes.fromhex(KEY_HEX)
CHACHA_IV_BOOT = bytes.fromhex(IV_HEX)

MAVLINK_V2_STX = 0xFD
CHACHA_TAG_LEN = 16

# =============================================================================
# FUNCIONES DE DESCIFRADO
# =============================================================================

def build_nonce12(iv_boot, sysid, compid, seq):
    """Construir nonce de 12 bytes para ChaCha20"""
    nonce = bytearray(12)
    nonce[0:8] = iv_boot
    nonce[8] = sysid
    nonce[9] = compid
    nonce[10] = seq
    nonce[11] = 0
    return bytes(nonce)

def build_aad_v2(len_field, incompat_flags, compat_flags, seq, sysid, compid, msgid):
    """Construir Additional Authenticated Data (AAD)"""
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

def decrypt_mavlink_packet(packet_bytes):
    """Descifrar paquete MAVLink v2 con ChaCha20-Poly1305"""
    try:
        if len(packet_bytes) < 10 + CHACHA_TAG_LEN + 2:
            return None
        
        if packet_bytes[0] != MAVLINK_V2_STX:
            return None
        
        # Extraer header
        payload_len = packet_bytes[1]
        incompat_flags = packet_bytes[2]
        compat_flags = packet_bytes[3]
        seq = packet_bytes[4]
        sysid = packet_bytes[5]
        compid = packet_bytes[6]
        msgid = packet_bytes[7] | (packet_bytes[8] << 8) | (packet_bytes[9] << 16)
        
        # Extraer ciphertext + tag
        if payload_len < CHACHA_TAG_LEN:
            return None
        
        ciphertext_with_tag = packet_bytes[10:10 + payload_len]
        
        # Construir AAD y nonce
        aad = build_aad_v2(payload_len, incompat_flags, compat_flags, seq, sysid, compid, msgid)
        nonce = build_nonce12(CHACHA_IV_BOOT, sysid, compid, seq)
        
        # Descifrar
        cipher = ChaCha20Poly1305(CHACHA_KEY)
        plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)
        
        # Reconstruir paquete MAVLink descifrado
        new_packet = bytearray(packet_bytes[0:10])
        new_packet[1] = len(plaintext)  # Actualizar longitud
        new_packet.extend(plaintext)
        
        # CRC se mantiene del paquete original
        crc_pos = 10 + payload_len
        if crc_pos + 2 <= len(packet_bytes):
            new_packet.extend(packet_bytes[crc_pos:crc_pos + 2])
        
        return bytes(new_packet)
        
    except Exception as e:
        # Descifrado falló
        return None

# =============================================================================
# CLASE MONITOR CON CHACHA20
# =============================================================================

class BebopMonitorChaCha20:
    def __init__(self, port=14550):
        """Inicializar conexión UDP con descifrado ChaCha20"""
        print(f"🔐 Inicializando monitor con ChaCha20-Poly1305")
        print(f"   Key:  {KEY_HEX[:32]}...")
        print(f"   IV:   {IV_HEX}")
        print()
        
        # Socket UDP para recibir paquetes cifrados
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.settimeout(3.0)
        
        print(f"🔌 Socket UDP escuchando en 0.0.0.0:{port}")
        
        # Conexión MAVLink (para parsear mensajes descifrados)
        self.master = mavutil.mavlink_connection('udpin:0.0.0.0:14551')  # Puerto auxiliar
        
        # Estadísticas
        self.stats = {
            'received': 0,
            'decrypted': 0,
            'failed': 0
        }
        
        print("✅ Monitor inicializado\n")
    
    def receive_and_decrypt_message(self):
        """Recibir paquete cifrado, descifrarlo y parsearlo"""
        try:
            # Recibir paquete cifrado
            encrypted_packet, addr = self.sock.recvfrom(2048)
            self.stats['received'] += 1
            
            # Intentar descifrar
            decrypted_packet = decrypt_mavlink_packet(encrypted_packet)
            
            if decrypted_packet:
                self.stats['decrypted'] += 1
                
                # Parsear con MAVLink
                # Inyectar el paquete descifrado en el parser
                parsed_msg = self.master.mav.decode(decrypted_packet)
                
                if parsed_msg:
                    return parsed_msg
                else:
                    # Parseo manual básico
                    msgid = decrypted_packet[7] | (decrypted_packet[8] << 8) | (decrypted_packet[9] << 16)
                    return {
                        'type': f'MSG_{msgid}',
                        'sysid': decrypted_packet[5],
                        'compid': decrypted_packet[6],
                        'msgid': msgid
                    }
            else:
                self.stats['failed'] += 1
                return None
                
        except socket.timeout:
            return None
        except Exception as e:
            print(f"❌ Error: {e}")
            return None
    
    def get_basic_status(self):
        """Obtener estado básico del dron (recibiendo paquetes cifrados)"""
        print("\n" + "="*60)
        print("📊 ESTADO DEL BEBOP (ChaCha20)")
        print("="*60)
        
        # Recibir varios mensajes para obtener estado completo
        messages = []
        timeout_count = 0
        
        while len(messages) < 20 and timeout_count < 5:
            msg = self.receive_and_decrypt_message()
            
            if msg:
                messages.append(msg)
                
                # Mostrar según tipo
                if hasattr(msg, 'get_type'):
                    msg_type = msg.get_type()
                    
                    if msg_type == 'HEARTBEAT':
                        try:
                            mode = mavutil.mode_string_v10(msg)
                            armed = "🔴 ARMADO" if msg.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED else "🟢 DESARMADO"
                            print(f"Modo de vuelo:  {mode}")
                            print(f"Estado:         {armed}")
                        except:
                            pass
                    
                    elif msg_type == 'SYS_STATUS':
                        try:
                            print(f"Batería:        {msg.battery_remaining}%")
                            print(f"Voltaje:        {msg.voltage_battery/1000:.2f}V")
                        except:
                            pass
                    
                    elif msg_type == 'ATTITUDE':
                        try:
                            import math
                            print(f"Roll:           {math.degrees(msg.roll):.1f}°")
                            print(f"Pitch:          {math.degrees(msg.pitch):.1f}°")
                            print(f"Yaw:            {math.degrees(msg.yaw):.1f}°")
                        except:
                            pass
            else:
                timeout_count += 1
        
        print("="*60)
        print(f"\n📊 Estadísticas:")
        print(f"   Recibidos:  {self.stats['received']}")
        print(f"   Descifrados: {self.stats['decrypted']}")
        print(f"   Fallidos:    {self.stats['failed']}")
    
    def monitor_continuous(self, count=20):
        """Monitorear mensajes continuamente"""
        print(f"\n📡 Monitoreando {count} mensajes cifrados...\n")
        
        for i in range(count):
            msg = self.receive_and_decrypt_message()
            
            if msg:
                if hasattr(msg, 'get_type'):
                    msg_type = msg.get_type()
                    print(f"{i+1:2d}. ✅ [{msg_type:20s}] Descifrado OK")
                else:
                    msgid = msg.get('msgid', '?')
                    print(f"{i+1:2d}. ✅ [MSG_{msgid:3s}           ] Descifrado OK")
            else:
                print(f"{i+1:2d}. ❌ Timeout o fallo de descifrado")
        
        print(f"\n📊 Resumen:")
        print(f"   Descifrados: {self.stats['decrypted']}")
        print(f"   Fallidos:    {self.stats['failed']}")


# =============================================================================
# MENÚ Y MAIN
# =============================================================================

def print_menu():
    """Menú simple"""
    print("\n" + "="*60)
    print("🔐 BEBOP MONITOR - ChaCha20-Poly1305")
    print("="*60)
    print("1. Ver estado actual del dron")
    print("2. Monitorear 20 mensajes")
    print("3. Monitorear continuamente (Ctrl+C para detener)")
    print("4. Ver estadísticas")
    print("0. Salir")
    print("="*60)


def main():
    """Función principal"""
    try:
        print("\n" + "="*60)
        print("🔐 BEBOP MONITOR CON CHACHA20-POLY1305")
        print("="*60)
        print("\n⚠️  Requiere ArduCopter con ChaCha20 habilitado")
        print("⚠️  Las claves deben coincidir exactamente")
        print("="*60 + "\n")
        
        # Inicializar monitor
        monitor = BebopMonitorChaCha20(port=14550)
        
        while True:
            print_menu()
            choice = input("\n➤ Opción: ").strip()
            
            if choice == '0':
                print("\n👋 Cerrando monitor...")
                break
            
            elif choice == '1':
                monitor.get_basic_status()
            
            elif choice == '2':
                monitor.monitor_continuous(count=20)
            
            elif choice == '3':
                print("\n📡 Monitoreo continuo (Presiona Ctrl+C para detener)...\n")
                try:
                    i = 0
                    while True:
                        i += 1
                        msg = monitor.receive_and_decrypt_message()
                        if msg:
                            if hasattr(msg, 'get_type'):
                                print(f"{i:4d}. ✅ [{msg.get_type():20s}]")
                            else:
                                print(f"{i:4d}. ✅ [MSG descifrado]")
                        else:
                            print(f"{i:4d}. ❌ Timeout o fallo")
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    print("\n⏸️  Monitoreo detenido")
            
            elif choice == '4':
                print(f"\n📊 ESTADÍSTICAS:")
                print(f"   Paquetes recibidos:  {monitor.stats['received']}")
                print(f"   Descifrados OK:      {monitor.stats['decrypted']}")
                print(f"   Fallos descifrado:   {monitor.stats['failed']}")
                if monitor.stats['received'] > 0:
                    success_rate = (monitor.stats['decrypted'] / monitor.stats['received']) * 100
                    print(f"   Tasa de éxito:       {success_rate:.1f}%")
            
            else:
                print("❌ Opción no válida")
    
    except KeyboardInterrupt:
        print("\n\n⏸️  Monitor interrumpido")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n👋 Monitor cerrado")


if __name__ == "__main__":
    # Verificar dependencias
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        main()
    except ImportError:
        print("\n❌ Error: Falta instalar cryptography")
        print("\nEjecuta:")
        print("   pip install cryptography")