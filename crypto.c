//
// Created by yeol on 2022/3/4.
//
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include "crypto.h"


typedef unsigned char byte;

void hmac_sha256(char *key, size_t key_len,
                 byte *message, size_t message_len,
                 byte *i_key_pad_opt, bool set_i_key_pad,
                 byte *o_key_pad_opt, bool set_o_key_pad,
                 byte *res_hash) {
    const size_t block_size = 64;
    byte key_hash[SHA256_DIGEST_LENGTH];

    // 如果 key 长度大于 64，进行 sha256 运算使长度变为 32
    if (key_len > block_size) {
        SHA256_CTX key_ctx;

        SHA256_Init(&key_ctx);
        SHA256_Update(&key_ctx, key, key_len);
        SHA256_Final(key_hash, &key_ctx);
        key = key_hash;
        key_len = SHA256_DIGEST_LENGTH;
    }


    byte i_key_pad[block_size];
    byte o_key_pad[block_size];

    // 复用 i_key_pad 和 o_key_pad
    if (set_i_key_pad) {
        *i_key_pad = *i_key_pad_opt;
    } else {
        for (size_t i = 0; i < key_len; i++) i_key_pad[i] = 0x36 ^ key[i];
        for (size_t i = key_len; i < block_size; i++) i_key_pad[i] = 0x36;
        *i_key_pad_opt = *i_key_pad;
    }
    if (set_o_key_pad) {
        *o_key_pad = *o_key_pad_opt;
    } else {
        for (size_t i = 0; i < key_len; i++) o_key_pad[i] = 0x5c ^ key[i];
        for (size_t i = key_len; i < block_size; i++) o_key_pad[i] = 0x5c;
        *o_key_pad_opt = *o_key_pad;
    }


    byte tmp[block_size*2];
    SHA256_CTX res_ctx;
    // byte res_hash[SHA256_DIGEST_LENGTH];

    // hash(_i_key_pad || message)
    memcpy(tmp, i_key_pad, block_size);
    memcpy(&tmp[block_size], message, message_len);
    SHA256_Init(&res_ctx);
    SHA256_Update(&res_ctx, tmp, block_size + message_len);
    SHA256_Final(res_hash, &res_ctx);

    // hash(o_key_pad || hash(_i_key_pad || message))
    memcpy(tmp, o_key_pad, block_size);
    memcpy(&tmp[block_size], res_hash, SHA256_DIGEST_LENGTH);
    SHA256_Init(&res_ctx);
    SHA256_Update(&res_ctx, tmp, block_size + SHA256_DIGEST_LENGTH);
    SHA256_Final(res_hash, &res_ctx);
}

void pbkdf2(char *pass, size_t pass_len,
            byte *salt, size_t salt_len,
            size_t iter_count, byte *result) {

    // byte result[SHA256_DIGEST_LENGTH];
    byte u1[SHA256_DIGEST_LENGTH];
    byte u2[SHA256_DIGEST_LENGTH];

    // Salt + INT_32_BE(i)
    byte salt_data[salt_len + 4];
    memcpy(salt_data, salt, salt_len);
    salt_data[salt_len] = 0x00;
    salt_data[salt_len + 1] = 0x00;
    salt_data[salt_len + 2] = 0x00;
    salt_data[salt_len + 3] = 0x01;


    byte i_key_pad[64];  // block_size = 64
    byte o_key_pad[64];

    hmac_sha256(pass, pass_len, salt_data, salt_len + 4,
                i_key_pad, false, o_key_pad, false, u1);
    memcpy(result, u1, SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < iter_count - 1; i++) {
        hmac_sha256(pass, pass_len, u1, SHA256_DIGEST_LENGTH,
                    i_key_pad, true, o_key_pad, true, u2);
        memcpy(u1, u2, SHA256_DIGEST_LENGTH);
        for (size_t j = 0; j < SHA256_DIGEST_LENGTH; j++) result[j] ^= u2[j];
    }
}
