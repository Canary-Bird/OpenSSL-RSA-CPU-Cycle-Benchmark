#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <iostream>
#include <memory>
#include <intrin.h>
#include <thread>
#include <vector>
#include <windows.h>
#define RSA_PKCS1_OAEP_PADDING 4

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void pinThreadToCore(int core_id) {
    DWORD_PTR mask = (DWORD_PTR)1 << core_id;
    SetThreadAffinityMask(GetCurrentThread(), mask);
}

int main() {
    // Pin the main thread to core 0
    pinThreadToCore(0);

    unsigned __int64 total_generate_cycles = 0;
    unsigned __int64 total_encrypt_cycles = 0;
    unsigned __int64 total_decrypt_cycles = 0;
    const int iterations = 50;

    for (int i = 0; i < iterations; ++i) {
        // Initialize OpenSSL
        OPENSSL_init_crypto(0, NULL);

        // Generate RSA key pair
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!pctx) {
            printf("Error creating context\n");
            return 1;
        }

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            printf("Error initializing keygen\n");
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        unsigned __int64 start_generate = __rdtsc();
        if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
            printf("Error generating RSA key pair\n");
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        unsigned __int64 end_generate = __rdtsc();
        total_generate_cycles += (end_generate - start_generate);

        if (pkey == NULL) {
            printf("Error generating RSA key pair\n");
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        else {
            // Create a BIO to hold the public key
            BIO* bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PUBKEY(bio, pkey);

            // Read the public key from the BIO
            char* pubkey_data;
            long pubkey_len = BIO_get_mem_data(bio, &pubkey_data);

            // Free the BIO
            BIO_free(bio);

            // Create a BIO to hold the private key
            bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL);

            // Read the private key from the BIO
            char* privkey_data;
            long privkey_len = BIO_get_mem_data(bio, &privkey_data);

            // Free the BIO
            BIO_free(bio);
        }

        ENGINE* eng = NULL;
        EVP_PKEY* key;
        unsigned char* out;
        size_t outlen, inlen;
        inlen = 30;
        static const unsigned char in[]{ "123456789" };

        // Encrypt data
        EVP_PKEY_CTX_free(pctx);
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, pkey);
        key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        pctx = EVP_PKEY_CTX_new(pkey, eng);
        if (!pctx) {
            printf("Error encryptying1\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        if (EVP_PKEY_encrypt_init(pctx) <= 0) {
            printf("Error encrypting2\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            printf("Error encrypting\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        if (EVP_PKEY_encrypt(pctx, NULL, &outlen, in, inlen) <= 0) {
            printf("Error encrypting3\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        out = (unsigned char*)OPENSSL_malloc(outlen);

        if (!out) {
            printf("Error encrypting4\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        unsigned __int64 start_encrypt = __rdtsc();
        if (EVP_PKEY_encrypt(pctx, out, &outlen, in, inlen) <= 0) {
            printf("Error encrypting5\n");
            handleErrors();
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        unsigned __int64 end_encrypt = __rdtsc();
        total_encrypt_cycles += (end_encrypt - start_encrypt);

        // Decrypt data
        EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(pkey, eng);
        if (!dctx) {
            printf("Error creating decryption context\n");
            handleErrors();
            return 1;
        }

        if (EVP_PKEY_decrypt_init(dctx) <= 0) {
            printf("Error initializing decryption\n");
            handleErrors();
            EVP_PKEY_CTX_free(dctx);
            return 1;
        }

        if (EVP_PKEY_CTX_set_rsa_padding(dctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            printf("Error setting RSA padding for decryption\n");
            handleErrors();
            EVP_PKEY_CTX_free(dctx);
            return 1;
        }

        size_t decrypted_len;
        if (EVP_PKEY_decrypt(dctx, NULL, &decrypted_len, out, outlen) <= 0) {
            printf("Error determining decrypted length\n");
            handleErrors();
            EVP_PKEY_CTX_free(dctx);
            return 1;
        }

        unsigned char* decrypted = (unsigned char*)OPENSSL_malloc(decrypted_len);
        if (!decrypted) {
            printf("Error allocating memory for decrypted data\n");
            handleErrors();
            EVP_PKEY_CTX_free(dctx);
            return 1;
        }

        unsigned __int64 start_decrypt = __rdtsc();
        if (EVP_PKEY_decrypt(dctx, decrypted, &decrypted_len, out, outlen) <= 0) {
            printf("Error decrypting data\n");
            handleErrors();
            EVP_PKEY_CTX_free(dctx);
            OPENSSL_free(decrypted);
            return 1;
        }
        unsigned __int64 end_decrypt = __rdtsc();
        total_decrypt_cycles += (end_decrypt - start_decrypt);

        // Free the allocated memory
        OPENSSL_free(out);
        OPENSSL_free(decrypted);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_CTX_free(pctx);
    }

    printf("Average CPU cycles for EVP_PKEY_generate: %llu\n", total_generate_cycles / iterations);
    printf("Average CPU cycles for EVP_PKEY_encrypt: %llu\n", total_encrypt_cycles / iterations);
    printf("Average CPU cycles for EVP_PKEY_decrypt: %llu\n", total_decrypt_cycles / iterations);

    return 0;
}