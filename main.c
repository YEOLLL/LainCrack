#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>

#include "crypto.h"


typedef unsigned char byte;
typedef struct {
    byte signature[8];
    byte header_crc32[4];
    byte header_size;
    byte header_type;
    byte header_flag;
    byte encryption_version;
    byte encryption_flag;
    byte kdf_count;
    byte salt[16];
    byte check_value[16];
} RAR5;

byte KdfCount;  // 迭代次数
byte Salt[16];  // 盐值
byte RARPwCheck[8];  // 文件中 Check value 的前 8 bytes

char **Dicts = NULL;  // 字典数组
size_t Count;  // 字典总数
int ThreadNum = 4;  // 线程数

int Finished = 0;  // 完成标识
pthread_rwlock_t FinishedRWLock = PTHREAD_RWLOCK_INITIALIZER;

int Quiet = 0;  // 安静输出

void generate_pwcheck(char *pass, int pass_len,
                      byte *salt, int salt_len,
                      int kdf_count, byte *pwcheck) {
    memset(pwcheck, 0, 8);
    byte out[32];
    pbkdf2(pass, pass_len, salt, salt_len, (1 << kdf_count) + 32, out);
    for (int i = 0; i < 32; i++) {
        pwcheck[i % 8] ^= out[i];
    }
}


int get_rar_info(char *path, byte *kdf_count, byte *salt, byte *pwcheck) {
    RAR5 rar;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    if (fread(&rar, sizeof(rar), 1, fp) == 1) {
        memcpy(kdf_count, &rar.kdf_count, sizeof(rar.kdf_count));
        memcpy(salt, &rar.salt, sizeof(rar.salt));
        memcpy(pwcheck, &rar.check_value, 8);
        fclose(fp);
        return 0;
    } else {
        if (feof(fp)) {
            //
        } else if (ferror(fp)) {
            //
        }
        fclose(fp);
        return -1;
    }
}


char **load_dicts(char *path, size_t *count) {
    char **dicts = NULL;
    char buf[32];

    FILE *fp = fopen(path, "r");
    if (fp == NULL) return NULL;

    long i = 0;
    while (!feof(fp)) {
        if (fscanf(fp, "%s", buf) == 1) {
            dicts = realloc(dicts, (i + 1) * sizeof(char *));
            if (dicts == NULL) return NULL;

            dicts[i] = malloc(strlen(buf) + 1);
            if (dicts[i] == NULL) return NULL;
            memcpy(dicts[i], buf, strlen(buf) + 1);

            i += 1;

        } else if (ferror(fp)) {
            fclose(fp);
            return NULL;
        }
    }
    fclose(fp);
    memcpy(count, &i, sizeof(i));
    return dicts;
}


typedef struct {
    int offset;
    size_t count;
} CrackArgs;

void *crack(void *args) {
    CrackArgs *crack_args = (CrackArgs *) args;
    byte pwcheck[8];  // 猜解密码对应 pwcheck

    // 遍历每一条密码
    for (int i = 0; i < crack_args->count; i++) {

        pthread_rwlock_rdlock(&FinishedRWLock);
        if (Finished) {
            pthread_rwlock_unlock(&FinishedRWLock);
            break;
        }
        pthread_rwlock_unlock(&FinishedRWLock);

        // 进度
        if (!Quiet) {
            printf("STATUS: %s\n", (Dicts + crack_args->offset)[i]);
            fflush(stdout);

        }

        // 生成 PwCheck
        generate_pwcheck(
                (Dicts + crack_args->offset)[i], (int) strlen((Dicts + crack_args->offset)[i]),
                Salt, sizeof(Salt),
                KdfCount, pwcheck);

        // 比对
        if (memcmp(pwcheck, RARPwCheck, 8) == 0) {
            pthread_rwlock_wrlock(&FinishedRWLock);
            Finished = 1;
            pthread_rwlock_unlock(&FinishedRWLock);
            printf("RIGHT PASSWORD: %s\n", (Dicts + crack_args->offset)[i]);
            break;
        }
    }
    // 回收
    for (int i = 0; i < crack_args->count; i++) {
        free((Dicts + crack_args->offset)[i]);
    }
    return NULL;
}


int run(char *dicts_path, char *rar_path) {
    printf("================ START =================\n");

    Dicts = load_dicts(dicts_path, &Count);  // 加载字典
    if (Dicts == NULL) return -1;

    // 获得 RAR 压缩包信息
    if (get_rar_info(rar_path, &KdfCount, Salt, RARPwCheck)) {
        for (int i = 0; i < Count; i++) free(Dicts[i]);
        free(Dicts);
        return -2;
    }

    // 创建 线程
    pthread_t threads[ThreadNum];
    CrackArgs crack_args[ThreadNum];
    size_t step = Count / ThreadNum;
    for (int i = 0; i < ThreadNum; i++) {
        crack_args[i].offset = (int) step * i;
        if (i == ThreadNum - 1) {
            crack_args[i].count = Count - crack_args[i].offset;
        } else {
            crack_args[i].count = step;
        }
        pthread_create(&threads[i], NULL, crack, (void *) &crack_args[i]);
    }

    for (int i = 0; i < ThreadNum; i++) {
        pthread_join(threads[i], NULL);
    }
    free(Dicts);
    pthread_rwlock_destroy(&FinishedRWLock);

    if (Finished) return 1;
    else return 0;
}


static const char *opt_str = "R:D:T:Q";
static struct option opts[] = {
        {"rar", required_argument, NULL, 'R'},
        {"dicts", required_argument, NULL, 'D'},
        {"threads", required_argument, NULL, 'T'},
        {"quiet", optional_argument, NULL, 'Q'},
        {"help", optional_argument, NULL, 'H'},
};
static char help[] = "Usage LainCrack [OPTIONS]\n"
                     "OPTIONS:\n"
                     "  -R, --rar TEXT\tEncrypted RAR file path  [required]\n"
                     "  -D, --dicts TEXT\tDictionary file path  [required]\n"
                     "  -T, --threads NUM\tThreads {default: 4}\n"
                     "  -Q, --quiet \t\tDon't show status\n"
                     "  --help \t\tShow this message and exit\n";


int main(int argc, char *argv[]) {
    char *rar_path;  // RAR 路径
    char *dicts_path;  // 字典路径

    // 处理命令行参数
    if (argc == 1) {
        printf("%s", help);
        exit(EXIT_FAILURE);
    }
    int opt;
    while ((opt = getopt_long(argc, argv, opt_str, opts, NULL)) != EOF) {
        switch (opt) {
            case 'H':
                printf("%s", help);
                exit(EXIT_SUCCESS);
            case 'R':
                rar_path = optarg;
                break;
            case 'D':
                dicts_path = optarg;
                break;
            case 'T':
                ThreadNum = (int) strtol(optarg, NULL, 10);
                break;
            case 'Q':
                Quiet = 1;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    printf("================ INFO ==================\n");
    printf("[RAR]: %s\n[DICT]: %s\n", rar_path, dicts_path);

    switch (run(dicts_path, rar_path)) {
        case 1:
            printf("================ SUCCESS ===============\n");
            exit(EXIT_SUCCESS);
        case 0:
            printf("================ DONE ==================\n");
            exit(EXIT_SUCCESS);
        case -1:
            fprintf(stderr, "Error loading dictionary file\n");
            printf("================ ERROR =================\n");
            exit(EXIT_FAILURE);
        case -2:
            fprintf(stderr, "Error reading RAR file\n");
            printf("================ ERROR =================\n");
            exit(EXIT_FAILURE);
        case -3:
            fprintf(stderr, "Error generating PwCheck\n");
            printf("================ ERROR =================\n");
            exit(EXIT_FAILURE);
    }
}