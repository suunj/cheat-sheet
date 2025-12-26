#include <openssl/evp.h>
#include <openssl/err.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define AES_GCM_TAG_SIZE_DEFAULT    16
#define AES_GCM_IV_SIZE_DEFAULT     12
#define AES_GCM_TAG_SIZE_MIN        12
#define AES_GCM_TAG_SIZE_MAX        16

typedef enum {
    AES_GCM_SUCCESS = 0,
    AES_GCM_ERR_CTX_NEW = -1,
    AES_GCM_ERR_INIT = -2,
    AES_GCM_ERR_SET_IVLEN = -3,
    AES_GCM_ERR_SET_KEY_IV = -4,
    AES_GCM_ERR_AAD_UPDATE = -5,
    AES_GCM_ERR_UPDATE = -6,
    AES_GCM_ERR_FINAL = -7,
    AES_GCM_ERR_TAG = -8,
    AES_GCM_ERR_VERIFY = -9,
    AES_GCM_ERR_INVALID_PARAM = -10
} aes_gcm_error_t;

typedef struct {
    const EVP_CIPHER *cipher;       // NULL for default (AES-256-GCM)
    size_t tag_size;                // Tag size in bytes (12-16)
    size_t iv_size;                 // IV size in bytes
} aes_gcm_config_t;

static const aes_gcm_config_t AES_GCM_CONFIG_DEFAULT = {
    .cipher = NULL,
    .tag_size = AES_GCM_TAG_SIZE_DEFAULT,
    .iv_size = AES_GCM_IV_SIZE_DEFAULT
};

const char* aes_gcm_error_string(aes_gcm_error_t err)
{
    switch (err) {
        case AES_GCM_SUCCESS:           return "Success";
        case AES_GCM_ERR_CTX_NEW:       return "Failed to create cipher context";
        case AES_GCM_ERR_INIT:          return "Failed to initialize cipher";
        case AES_GCM_ERR_SET_IVLEN:     return "Failed to set IV length";
        case AES_GCM_ERR_SET_KEY_IV:    return "Failed to set key/IV";
        case AES_GCM_ERR_AAD_UPDATE:    return "Failed to process AAD";
        case AES_GCM_ERR_UPDATE:        return "Failed to process data";
        case AES_GCM_ERR_FINAL:         return "Failed to finalize";
        case AES_GCM_ERR_TAG:           return "Failed to get/set tag";
        case AES_GCM_ERR_VERIFY:        return "Authentication failed";
        case AES_GCM_ERR_INVALID_PARAM: return "Invalid parameter";
        default:                        return "Unknown error";
    }
}

static void print_openssl_errors(void)
{
#ifdef DEBUG
    ERR_print_errors_fp(stderr);
#endif
}

static int validate_config(const aes_gcm_config_t *config)
{
    if (config == NULL) {
        return 1;
    }
    
    if (config->tag_size < AES_GCM_TAG_SIZE_MIN || 
        config->tag_size > AES_GCM_TAG_SIZE_MAX) {
        return 0;
    }
    
    if (config->iv_size == 0) {
        return 0;
    }
    
    return 1;
}

ssize_t aes_gcm_encrypt(
    const aes_gcm_config_t *config,
    const void *plaintext,
    size_t plaintext_size,
    const void *aad,
    size_t aad_size,
    const void *key,
    const void *iv,
    void *ciphertext,
    void *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    size_t tag_size, iv_size;
    int len = 0;
    ssize_t ciphertext_size = 0;
    aes_gcm_error_t ret = AES_GCM_SUCCESS;

    /* Validate parameters */
    if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }
    
    if (plaintext == NULL && plaintext_size > 0) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }

    if (!validate_config(config)) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }

    /* Apply configuration or defaults */
    if (config != NULL) {
        cipher = config->cipher ? config->cipher : EVP_aes_256_gcm();
        tag_size = config->tag_size;
        iv_size = config->iv_size;
    } else {
        cipher = EVP_aes_256_gcm();
        tag_size = AES_GCM_TAG_SIZE_DEFAULT;
        iv_size = AES_GCM_IV_SIZE_DEFAULT;
    }

    /* Create context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        print_openssl_errors();
        errno = ENOMEM;
        return AES_GCM_ERR_CTX_NEW;
    }

    do {
        /* Initialize cipher */
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_INIT;
            break;
        }

        /* Set IV length */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size, NULL) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_SET_IVLEN;
            break;
        }

        /* Set key and IV */
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, 
                               (const unsigned char *)key, 
                               (const unsigned char *)iv) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_SET_KEY_IV;
            break;
        }

        /* Process AAD if provided */
        if (aad != NULL && aad_size > 0) {
            if (EVP_EncryptUpdate(ctx, NULL, &len, 
                                  (const unsigned char *)aad, 
                                  (int)aad_size) != 1) {
                print_openssl_errors();
                ret = AES_GCM_ERR_AAD_UPDATE;
                break;
            }
        }

        /* Encrypt plaintext */
        if (plaintext_size > 0) {
            if (EVP_EncryptUpdate(ctx, 
                                  (unsigned char *)ciphertext, 
                                  &len,
                                  (const unsigned char *)plaintext, 
                                  (int)plaintext_size) != 1) {
                print_openssl_errors();
                ret = AES_GCM_ERR_UPDATE;
                break;
            }
            ciphertext_size = len;
        }

        /* Finalize encryption */
        if (EVP_EncryptFinal_ex(ctx, 
                                (unsigned char *)ciphertext + ciphertext_size, 
                                &len) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_FINAL;
            break;
        }
        ciphertext_size += len;

        /* Get authentication tag */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
                                (int)tag_size, tag) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_TAG;
            break;
        }

    } while (0);

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);

    if (ret != AES_GCM_SUCCESS) {
        errno = EINVAL;
        return ret;
    }

    return ciphertext_size;
}

ssize_t aes_gcm_decrypt(
    const aes_gcm_config_t *config,
    const void *ciphertext,
    size_t ciphertext_size,
    const void *aad,
    size_t aad_size,
    const void *tag,
    const void *key,
    const void *iv,
    void *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;
    size_t tag_size, iv_size;
    int len = 0;
    ssize_t plaintext_size = 0;
    aes_gcm_error_t ret = AES_GCM_SUCCESS;

    /* Validate parameters */
    if (key == NULL || iv == NULL || tag == NULL || plaintext == NULL) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }
    
    if (ciphertext == NULL && ciphertext_size > 0) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }

    if (!validate_config(config)) {
        errno = EINVAL;
        return AES_GCM_ERR_INVALID_PARAM;
    }

    /* Apply configuration or defaults */
    if (config != NULL) {
        cipher = config->cipher ? config->cipher : EVP_aes_256_gcm();
        tag_size = config->tag_size;
        iv_size = config->iv_size;
    } else {
        cipher = EVP_aes_256_gcm();
        tag_size = AES_GCM_TAG_SIZE_DEFAULT;
        iv_size = AES_GCM_IV_SIZE_DEFAULT;
    }

    /* Create context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        print_openssl_errors();
        errno = ENOMEM;
        return AES_GCM_ERR_CTX_NEW;
    }

    do {
        /* Initialize cipher */
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_INIT;
            break;
        }

        /* Set IV length */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size, NULL) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_SET_IVLEN;
            break;
        }

        /* Set key and IV */
        if (EVP_DecryptInit_ex(ctx, NULL, NULL,
                               (const unsigned char *)key,
                               (const unsigned char *)iv) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_SET_KEY_IV;
            break;
        }

        /* Process AAD if provided */
        if (aad != NULL && aad_size > 0) {
            if (EVP_DecryptUpdate(ctx, NULL, &len,
                                  (const unsigned char *)aad,
                                  (int)aad_size) != 1) {
                print_openssl_errors();
                ret = AES_GCM_ERR_AAD_UPDATE;
                break;
            }
        }

        /* Decrypt ciphertext */
        if (ciphertext_size > 0) {
            if (EVP_DecryptUpdate(ctx,
                                  (unsigned char *)plaintext,
                                  &len,
                                  (const unsigned char *)ciphertext,
                                  (int)ciphertext_size) != 1) {
                print_openssl_errors();
                ret = AES_GCM_ERR_UPDATE;
                break;
            }
            plaintext_size = len;
        }

        /* Set expected tag value (must be before DecryptFinal) */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                (int)tag_size, (void *)tag) != 1) {
            print_openssl_errors();
            ret = AES_GCM_ERR_TAG;
            break;
        }

        /* Finalize decryption and verify tag */
        if (EVP_DecryptFinal_ex(ctx,
                                (unsigned char *)plaintext + plaintext_size,
                                &len) != 1) {
            print_openssl_errors();
            /* Clear plaintext on authentication failure for security */
            memset(plaintext, 0, ciphertext_size);
            ret = AES_GCM_ERR_VERIFY;
            break;
        }
        plaintext_size += len;

    } while (0);

    /* Cleanup */
    EVP_CIPHER_CTX_free(ctx);

    if (ret != AES_GCM_SUCCESS) {
        errno = (ret == AES_GCM_ERR_VERIFY) ? EACCES : EINVAL;
        return ret;
    }

    return plaintext_size;
}

ssize_t encrypt_AES_GCM(
    const EVP_CIPHER *s_cipher,
    const void *s_plaintext,
    size_t s_plaintext_size,
    const void *s_aad,
    size_t s_aad_size,
    const void *s_key,
    const void *s_iv,
    size_t s_iv_size,
    void *s_ciphertext,
    void *s_tag)
{
    aes_gcm_config_t config = {
        .cipher = s_cipher,
        .tag_size = AES_GCM_TAG_SIZE_DEFAULT,
        .iv_size = s_iv_size
    };
    
    return aes_gcm_encrypt(&config, s_plaintext, s_plaintext_size,
                           s_aad, s_aad_size, s_key, s_iv,
                           s_ciphertext, s_tag);
}

ssize_t decrypt_AES_GCM(
    const EVP_CIPHER *s_cipher,
    const void *s_ciphertext,
    size_t s_ciphertext_size,
    const void *s_aad,
    size_t s_aad_size,
    const void *s_tag,
    const void *s_key,
    const void *s_iv,
    size_t s_iv_size,
    void *s_plaintext)
{
    aes_gcm_config_t config = {
        .cipher = s_cipher,
        .tag_size = AES_GCM_TAG_SIZE_DEFAULT,
        .iv_size = s_iv_size
    };
    
    return aes_gcm_decrypt(&config, s_ciphertext, s_ciphertext_size,
                           s_aad, s_aad_size, s_tag, s_key, s_iv,
                           s_plaintext);
}


int main(void)
{
    /* Test vectors */
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    const char *plaintext = "Hello, AES-GCM! This is a test message.";
    const char *aad = "Additional Authenticated Data";
    
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    unsigned char tag[16];
    
    ssize_t encrypted_len, decrypted_len;

    printf("=== AES-GCM Test ===\n\n");
    printf("Plaintext: %s\n", plaintext);
    printf("AAD: %s\n\n", aad);

    /* Encrypt */
    encrypted_len = aes_gcm_encrypt(
        NULL,  /* Use default config */
        plaintext, strlen(plaintext),
        aad, strlen(aad),
        key, iv,
        ciphertext, tag
    );

    if (encrypted_len < 0) {
        fprintf(stderr, "Encryption failed: %s\n", 
                aes_gcm_error_string((aes_gcm_error_t)encrypted_len));
        return 1;
    }

    printf("Encrypted %zd bytes\n", encrypted_len);
    printf("Tag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n\n");

    /* Decrypt */
    decrypted_len = aes_gcm_decrypt(
        NULL,  /* Use default config */
        ciphertext, encrypted_len,
        aad, strlen(aad),
        tag, key, iv,
        decrypted
    );

    if (decrypted_len < 0) {
        fprintf(stderr, "Decryption failed: %s\n",
                aes_gcm_error_string((aes_gcm_error_t)decrypted_len));
        return 1;
    }

    decrypted[decrypted_len] = '\0';
    printf("Decrypted: %s\n", decrypted);

    /* Verify */
    if (memcmp(plaintext, decrypted, strlen(plaintext)) == 0) {
        printf("\n✓ Test PASSED\n");
        return 0;
    } else {
        printf("\n✗ Test FAILED\n");
        return 1;
    }
}
