//
// Created by yeol on 2022/3/4.
//

#ifndef LAINCRACK_CRYPTO_H
#define LAINCRACK_CRYPTO_H

#endif //LAINCRACK_CRYPTO_H

typedef unsigned char byte;
void pbkdf2(char *pass, size_t pass_len,
            byte *salt, size_t salt_len,
            size_t iter_count, byte *result);
