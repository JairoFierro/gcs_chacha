// test_chacha_mavlink.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Simular estructura básica de MAVLink
typedef struct {
    uint8_t magic;              // 0xFD para MAVLink v2
    uint8_t len;                // Longitud del payload
    uint8_t incompat_flags;
    uint8_t compat_flags;
    uint8_t seq;
    uint8_t sysid;
    uint8_t compid;
    uint8_t  msgid[3];             // 3 bytes en realidad
    uint8_t payload[255];       // Payload variable
    uint16_t checksum;
    uint8_t signature[13];      // Opcional
} __attribute__((packed)) mavlink_message_t;

// ENCRIPTAR payload de MAVLink
int encrypt_mavlink_payload(
    mavlink_message_t *msg,
    const unsigned char *key,
    unsigned char *iv_out,      // Se genera y devuelve
    unsigned char *tag_out)     // Se genera y devuelve
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Generar IV único para este mensaje (96 bits)
    if(1 != RAND_bytes(iv_out, 12))
        handleErrors();

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // Inicializar ChaCha20-Poly1305
    if(1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv_out))
        handleErrors();

    // AAD: Header de MAVLink (primeros 10 bytes antes del payload)
    // Estos se autentican pero NO se cifran
    unsigned char *aad = (unsigned char*)msg;
    int aad_len = 10;  // Hasta msgid incluido

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    // Cifrar el payload en su lugar (in-place encryption)
    unsigned char *plaintext = msg->payload;
    int plaintext_len = msg->len;

    if(1 != EVP_EncryptUpdate(ctx, plaintext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    ciphertext_len += len;

    // Obtener tag de autenticación
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// DESENCRIPTAR payload de MAVLink
int decrypt_mavlink_payload(
    mavlink_message_t *msg,
    const unsigned char *key,
    const unsigned char *iv,
    const unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv))
        handleErrors();

    // Mismo AAD usado en encriptación
    unsigned char *aad = (unsigned char*)msg;
    int aad_len = 10;

    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    // Desencriptar payload en su lugar
    unsigned char *ciphertext = msg->payload;
    int ciphertext_len = msg->len;

    if(1 != EVP_DecryptUpdate(ctx, ciphertext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Verificar tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag))
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        printf("❌ Verificación de tag falló - mensaje corrompido o clave incorrecta\n");
        return -1;
    }
}

void print_message(const char *label, mavlink_message_t *msg) {
    printf("\n=== %s ===\n", label);
    printf("Magic: 0x%02X\n", msg->magic);
    printf("Len: %d\n", msg->len);
    printf("Seq: %d\n", msg->seq);
    printf("SysID: %d\n", msg->sysid);
    printf("CompID: %d\n", msg->compid);
    printf("MsgID: %u\n", msg->msgid);

    uint32_t msgid_value = msg->msgid[0] | (msg->msgid[1] << 8) | (msg->msgid[2] << 16);
    printf("MsgID: 0x%06X (%u)\n", msgid_value, msgid_value);
    
    printf("Payload: ");
    for(int i = 0; i < msg->len; i++)
        printf("%02X ", msg->payload[i]);
    printf("\n");
}

int main(void) {
    printf("=== TEST: Cifrado de Payload MAVLink con ChaCha20-Poly1305 ===\n");

    // Clave compartida (en producción debe ser secreta y bien gestionada)
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    // Crear mensaje MAVLink simulado
    mavlink_message_t msg_original;
    memset(&msg_original, 0, sizeof(msg_original));
    
    msg_original.magic = 0xFD;  // MAVLink v2
    msg_original.len = 44;      // Payload de 20 bytes
    msg_original.seq = 0x8F;
    msg_original.sysid = 1;
    msg_original.compid = 1;
    // msg_original.msgid = 30;    // ATTITUDE

    msg_original.msgid[0] = 0x16;  // Byte bajo
    msg_original.msgid[1] = 0x2B;  // Byte medio
    msg_original.msgid[2] = 0x00; 
    
    // // Payload de ejemplo: "DATOS TELEMETRIA DR"
    // const char *payload_text = "DATOS TELEMETRIA DR";
    // memcpy(msg_original.payload, payload_text, msg_original.len);

    unsigned char payload_real[44] = {
    0x8f, 0x06, 0x8f, 0x06, 0x8f, 0x06, 0x8f, 0x06,
    0x50, 0x00, 0x50, 0x00, 0x50, 0x00, 0x50, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf9, 0x49, 0xf9, 0x49, 0xf9, 0x49, 0xf9, 0x49,
    0x20, 0x20, 0x20, 0x20
    };
    memcpy(msg_original.payload, payload_real, msg_original.len);

    msg_original.checksum = 0x7935; 
    

    print_message("MENSAJE ORIGINAL", &msg_original);

    // Copiar para no perder el original
    mavlink_message_t msg_encrypted;
    memcpy(&msg_encrypted, &msg_original, sizeof(mavlink_message_t));

    // Buffers para IV y Tag
    unsigned char iv[12];
    unsigned char tag[16];

    // === ENCRIPTAR ===
    printf("\n--- ENCRIPTANDO ---\n");
    int encrypted_len = encrypt_mavlink_payload(&msg_encrypted, key, iv, tag);
    
    printf("✅ Payload encriptado (%d bytes)\n", encrypted_len);
    printf("IV: ");
    for(int i = 0; i < 12; i++) printf("%02X", iv[i]);
    printf("\nTag: ");
    for(int i = 0; i < 16; i++) printf("%02X", tag[i]);
    printf("\n");

    print_message("MENSAJE ENCRIPTADO", &msg_encrypted);

    // === DESENCRIPTAR ===
    printf("\n--- DESENCRIPTANDO ---\n");
    int decrypted_len = decrypt_mavlink_payload(&msg_encrypted, key, iv, tag);
    
    if(decrypted_len >= 0) {
        printf("✅ Payload desencriptado (%d bytes)\n", decrypted_len);
        print_message("MENSAJE DESENCRIPTADO", &msg_encrypted);
        
        // Verificar que coincide con el original
        if(memcmp(msg_original.payload, msg_encrypted.payload, msg_original.len) == 0) {
            printf("\n✅✅✅ ÉXITO: El payload recuperado coincide con el original\n");
        } else {
            printf("\n❌ ERROR: Los payloads no coinciden\n");
        }
    } else {
        printf("❌ Error en desencriptación\n");
    }

    // === PRUEBA DE INTEGRIDAD ===
    printf("\n--- PRUEBA: Modificar datos cifrados ---\n");
    msg_encrypted.payload[0] ^= 0xFF;
    
    int tampered = decrypt_mavlink_payload(&msg_encrypted, key, iv, tag);
    if(tampered < 0) {
        printf("✅ Correcto: Se detectó la modificación\n");
    }

    // === PRUEBA: Tag incorrecto ===
    printf("\n--- PRUEBA: Tag incorrecto ---\n");
    memcpy(&msg_encrypted, &msg_original, sizeof(mavlink_message_t));
    encrypt_mavlink_payload(&msg_encrypted, key, iv, tag);
    tag[0] ^= 0xFF;  // Corromper tag
    
    int bad_tag = decrypt_mavlink_payload(&msg_encrypted, key, iv, tag);
    if(bad_tag < 0) {
        printf("✅ Correcto: Se detectó tag inválido\n");
    }

    return 0;
}
