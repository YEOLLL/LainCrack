# LainCrack
边写代码边记录的，许多地方可能之后又做了改动，导致观感很跳跃。
## 概述

用于破解压缩文件密码的命令行工具。

目前，RAR 5.x 的加密方式不存在有效的逆向方法，只能暴力猜解，网络上的大多工具调用`unrar`程序来实现，不够轻量和灵活，在不使用多线程的情况下速度堪忧。

这次尝试不使用外部程序，实现对 RAR 5.x 格式的压缩包文件的解析和爆破，构建一个完备的命令行工具，并探究其他工具的效率问题，对比加以改进。

## 建立测试环境

### 基本信息

```
> neofetch
                               yeol@yeol-20ym
██████████████████  ████████   --------------
██████████████████  ████████   OS: Manjaro Linux x86_64
██████████████████  ████████   Host: 20YM ThinkBook 16p G2 ACH
████████            ████████   Kernel: 5.15.21-1-MANJARO
████████  ████████  ████████   Uptime: 2 days, 1 hour, 6 mins
████████  ████████  ████████   Packages: 1322 (pacman)
████████  ████████  ████████   Shell: fish 3.3.1
████████  ████████  ████████   Resolution: 2560x1600
████████  ████████  ████████   WM: i3
████████  ████████  ████████   Theme: Adapta-Nokto-Eta-Maia [GTK2/3]
████████  ████████  ████████   Icons: Papirus-Adapta-Nokto-Maia [GTK2/3]
████████  ████████  ████████   Terminal: alacritty
████████  ████████  ████████   CPU: AMD Ryzen 7 5800H with Radeon Graphics (16) @ 3.200GHz
                               GPU: AMD ATI 06:00.0 Cezanne
                               GPU: NVIDIA GeForce RTX 3060 Mobile / Max-Q
                               Memory: 9826MiB / 15422MiB
```

```
> rar
RAR 6.10   Copyright (c) 1993-2022 Alexander Roshal   24 Jan 2022
Trial version             Type 'rar -?' for help
```

### 创建样本文件

建立 `flag.txt` 文件，内容为`This is FLAG`。

```
> echo 'This is FLAG' > 'flag.txt'
> cat flag.txt
This is FLAG
```

建立密码为`123456`的压缩文件`flag.rar`，指定`-hp`（不能是`-p`），将`flag.txt`存入。

```
> rar a -hp flag.rar flag.txt
> type password: 123456

> file flag.rar
flag.rar: RAR archive data, v5
```

## 创建字典文件

以换行符分割的文本文件即可。

```
> cat wordlist.txt
12345
admin
password
test123
a12345678
123321
123456
```

## 分析 RAR 5.x 文件格式

### 数据类型

#### vint

`vint` 是由 RAR 官方自定义的一种**变长整形**类型，可以包含一个或多个字节，其中每个字节的低七位包含整形数据，最高位是延续标志，如果最高位是 0，则这是`vint`的最后一个字节，否则表示还有下一个字节，以此类推。

#### byte, uint16, uint32, uint64

`byte`、`16bit、32bit、64bit 无符号整形`均使用小端序。

### 文件结构

RAR 文件由 `Archive blocks` 所组成，每一个 `Block` 存储的数据相对独立。

主要分析加密文件拥有的`Archive encryption header`。其位于 8 bytes 的签名（RAR 5.x Signature）之后，数据结构如下：

| Content            | Data Type | Description                                                  |
| :----------------- | --------- | :----------------------------------------------------------- |
| Header CRC32       | uint32    | 头数据（从 `Header size` 到 `Check value`）的 CRC32 值。     |
| Header size        | vint      | 头数据（从 `Header size` 到 `Check value`）的大小            |
| Header type        | vint      | `0x04` 表示此为 `Archive encryption header`                  |
| Header flags       | vint      | 所有 Header 通用的标志<br/>`0x01` - 头末尾存在扩展区域。<br/>`0x02` - 头末尾存在数据区域。<br/>`0x04` - 当更新压缩文档时，必须跳过类型未知并拥有该标志的块。<br/>`0x08` - 数据区域从上一卷继续。<br/>`0x10` - 数据区域从下一卷继续。<br/>`0x20` - 块取决于前一个文件块。<br/>`0x40` - 如果修改了主块，则保留一个子块。 |
| Encryption version | vint      | `PBKDF2`函数所使用的散列算法版本，目前只有`AES-256`<br />`0x00` - AES-256 |
| Encryption flags   | vint      | 加密标志<br/>`0x00` - 不存在 `Check Value`<br/>`0x01` - 存在 `Check Value` |
| KDF count          | 1 byte    | `PBKDF2`函数的迭代数的二进制对数                             |
| Salt               | 16 bytes  | `PBKDF2`函数的盐值，全局作用于所有`Archive encryption header` |
| Check Value        | 12 bytes  | 密码检查字段<br/> 前 8 bytes 使用`PBKDF2`函数加上一些异或计算得出<br/>后 4 bytes 是额外的校验和，与`Header CRC32`一起构成 64 位校验和，以此校验此字段完整性并区分无效的密码和损坏的数据 |

### 分析样本文件

查看文件数据：

```
> hexdump -e '16/1 "%02X " " | "' -e '16/1 "%_p" "\n"' flag.rar

52 61 72 21 1A 07 01 00 BD 16 67 EC 21 04 00 00 | Rar!......g.!...
01 0F 05 58 80 82 DE B1 4A 7E 49 7A 48 CC 0D B7 | ...X....J~IzH...
49 7A 1C 16 24 BC 46 34 FE 2D F8 A2 32 C6 E7 D7 | Iz..$.F4.-..2...
64 64 AE 14 53 49 B7 68 E7 E5 ED AC FE 87 EF A3 | dd..SI.h........
00 D7 56 6B 4E B8 88 1A EA 49 15 82 52 08 FB AD | ..VkN....I..R...
E2 92 D2 72 F4 BA 6B 32 A6 11 7B 14 36 DF 34 B1 | ...r..k2..{.6.4.
5E 0E AC C8 CD E8 B4 D2 0F F0 4E 04 3A 4B 88 5D | ^.........N.:K.]
00 86 23 89 66 75 13 4C D5 01 2C C6 5B 34 DC EA | ..#.fu.L..,.[4..
0E FF FB 16 01 98 00 06 6E 92 17 B8 5F B4 AE C6 | ........n..._...
82 B8 5D 75 91 09 CE 20 E3 5A 7A D7 6E 64 9A 56 | ..]u... .Zz.nd.V
88 42 E6 4B E6 91 0C 3F E0 D7 51 F5 97 78 8B 35 | .B.K...?..Q..x.5
7B 23 25 AD 24 C1 63 02 D7 6E 08 DC A4 91 D9 0C | {#%.$.c..n......
EA 6A 52 C2 A9 37 18 D9 AA A6 E0 92 CD 38 D7 63 | .jR..7.......8.c
D9 FC 5F 92 58 0B 54 FA A0 4A 02 4C 89 FE 30 62 | .._.X.T..J.L..0b
29 DA 45 2B 15 A1 03 C5 8C B6 8F B4 80 C3 7D D7 | ).E+..........}.
98 67 39 0C E9 08 B7 40 84 B9 71 E5 B7 8D       | .g9....@..q...
```

签名（RAR 5.x Signature）：

```
52 61 72 21 1A 07 01 00
```

Header CRC32：

```
BD 16 67 EC
```

Header Size：

```
21
```

Header Type：

```
04
```

Header Flag：

```
00
```

Encryption version：

```
00
```

Encryption Flag：

```
01
```

KDF count：

```
0F
```

Salt：

```
05 58 80 82 DE B1 4A 7E 49 7A 48 CC 0D B7 49 7A 
```

Check Value：

```
1C 16 24 BC 46 34 FE 2D F8 A2 32 C6
```

较为重要的几个字段有：

`KDF count`：`0F`

`Salt`：`05 58 80 82 DE B1 4A 7E 49 7A 48 CC 0D B7 49 7A `

`Check Value` 的前 8 byte：`1C 16 24 BC 46 34 FE 2D`，以下简称`PwCheck`

## 分析加密算法

根据`unrar`源码所写：

```cpp
// https://github.com/pmachapman/unrar/blob/master/crypt5.cpp
// ...

void pbkdf2(const byte *Pwd, size_t PwdLength, 
            const byte *Salt, size_t SaltLength,
            byte *Key, byte *V1, byte *V2, uint Count)
{
  // ...

  SaltData[SaltLength + 0] = 0; // Salt concatenated to 1.
  SaltData[SaltLength + 1] = 0;
  SaltData[SaltLength + 2] = 0;
  SaltData[SaltLength + 3] = 1;

  // First iteration: HMAC of password, salt and block index (1).
  byte U1[SHA256_DIGEST_SIZE];
  hmac_sha256(Pwd, PwdLength, SaltData, SaltLength + 4, U1, NULL, NULL, NULL, NULL);
  byte Fn[SHA256_DIGEST_SIZE]; // Current function value.
  memcpy(Fn, U1, sizeof(Fn)); // Function at first iteration.

  uint  CurCount[] = { Count-1, 16, 16 };

  for (uint I = 0; I < 3; I++) // For output key and 2 supplementary values.
  {
    for (uint J = 0; J < CurCount[I]; J++) 
    {
      // U2 = PRF (P, U1).
      hmac_sha256(Pwd, PwdLength, U1, sizeof(U1), U2, &ICtxOpt, &SetIOpt, &RCtxOpt, &SetROpt);
      memcpy(U1, U2, sizeof(U1));
      for (uint K = 0; K < sizeof(Fn); K++) // Function ^= U.
        Fn[K] ^= U1[K];
    }
    memcpy(CurValue[I], Fn, SHA256_DIGEST_SIZE);
  }
    
  // ...
}

// ...
void CryptData::SetKey50(bool Encrypt,SecPassword *Password,const wchar *PwdW,
     const byte *Salt,const byte *InitV,uint Lg2Cnt,byte *HashKey,
     byte *PswCheck)
{
  // ...
  if (!Found)
  {
    char PwdUtf[MAXPASSWORD*4];
    WideToUtf(PwdW,PwdUtf,ASIZE(PwdUtf));
    
    pbkdf2((byte *)PwdUtf,strlen(PwdUtf),Salt,SIZE_SALT50,Key,HashKeyValue,PswCheckValue,(1<<Lg2Cnt));
    cleandata(PwdUtf,sizeof(PwdUtf));

    KDF5CacheItem *Item=KDF5Cache+(KDF5CachePos++ % ASIZE(KDF5Cache));
    Item->Lg2Count=Lg2Cnt;
    Item->Pwd=*Password;
    memcpy(Item->Salt,Salt,SIZE_SALT50);
    memcpy(Item->Key,Key,sizeof(Item->Key));
    memcpy(Item->PswCheckValue,PswCheckValue,sizeof(PswCheckValue));
    memcpy(Item->HashKeyValue,HashKeyValue,sizeof(HashKeyValue));
    SecHideData(Item->Key,sizeof(Item->Key),true,false);
  }
  if (HashKey!=NULL)
    memcpy(HashKey,HashKeyValue,SHA256_DIGEST_SIZE);    free()

  if (PswCheck!=NULL)
  {
    memset(PswCheck,0,SIZE_PSWCHECK);
    for (uint I=0;I<SHA256_DIGEST_SIZE;I++)
      PswCheck[I%SIZE_PSWCHECK]^=PswCheckValue[I];
    cleandata(PswCheckValue,sizeof(PswCheckValue));
  }
  // ...
}
```

关键代码：

```cpp
pbkdf2((byte *)PwdUtf,strlen(PwdUtf),Salt,SIZE_SALT50,Key,HashKeyValue,PswCheckValue,(1<<Lg2Cnt));
```

`pbkdf2`函数生成了一个迭代数为`KDF count`的 32 bytes 密钥`key`，还有两个迭代数为`KDF count + 16`和`KDF count + 32`的补充值`v1`和`v2`，用于校验`checksum`（Check Value 后 4 bytes）和`PwCheck`（Check Value 前 8 bytes）。

而后，代码将`v2`进行一些异或操作，得到 8 bytes 的 `PwCheck`：

```cpp
    for (uint I=0;I<SHA256_DIGEST_SIZE;I++)
      PswCheck[I%SIZE_PSWCHECK]^=PswCheckValue[I];
```

异或规则如下：

```python
pwcheck[0] = v2[0] ^ v2[8]  ^ v2[16] ^ v2[24]
pwcheck[1] = v2[1] ^ v2[9]  ^ v2[17] ^ v2[25]
pwcheck[2] = v2[2] ^ v2[10] ^ v2[18] ^ v2[26]
pwcheck[3] = v2[3] ^ v2[11] ^ v2[19] ^ v2[27]
pwcheck[4] = v2[4] ^ v2[12] ^ v2[20] ^ v2[28]
pwcheck[5] = v2[5] ^ v2[13] ^ v2[21] ^ v2[29]
pwcheck[6] = v2[6] ^ v2[14] ^ v2[22] ^ v2[30]
pwcheck[7] = v2[7] ^ v2[15] ^ v2[23] ^ v2[31]
```



至此，可以写出一个简易的 Python 脚本：

```python
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from binascii import hexlify, unhexlify

password = b'123456'  # 压缩包密码
salt = unhexlify('05588082DEB14A7E497A48CC0DB7497A')  # 加密头中的盐值

# 加密 2 的 KDF count 次方 + 32，也就是 1<<15+32 = 32800
v2 = PBKDF2(password, salt, dkLen=32, count=(1<<15)+32, prf=lambda p,s:HMAC.new(p,s,SHA256).digest())
# v2 = b'4acb97998f89ae28db15f8afa7124c636da776234151247ce06f3da92ffe381a'

pwcheck = bytearray(8)
for i in range(32):
  pwcheck[i % 8] ^= v2[i]

print(hexlify(pwcheck))
# b'1c1624bc4634fe2d'
```

输出结果`1c1624bc4634fe2d`与样本文件中的`pwcheck`一致，说明`123456`是正确的密码。

## 编写代码

### 读出文件加密头

先定义一个`Archive encryption header`基本数据结构，这里没有专门对`vint`处理，先简单地将其设定为定长 1 byte。

```c
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
```

读出文件中的信息（`KDF count`、`Salt`、`pwcheck`），错误信息被我省略，留在后面重新设计：

```c
#include <stdio.h>
#include <string.h>

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
```

### 生成 `PwCheck`

代码很简易，`PBKDF2`加密部分直接使用了` OpenSSL`中的库。

```c
#include <openssl/evp.h>

int generate_pwcheck(char *pass, int pass_len,
                     byte *salt, int salt_len,
                     int kdf_count, byte *pwcheck)
{
    memset(pwcheck, 0, 8);
    byte out[32];
    if (PKCS5_PBKDF2_HMAC(
            pass, pass_len, salt, salt_len,
            (1 << kdf_count) + 32, EVP_sha256(), 32, out
    )) {
        for (int i = 0; i < 32; i++) {
            pwcheck[i % 8] ^= out[i];
        }
        return 0;
    } else {
        return -1;
    }
}

```

### 测试穷举模式

目前，已经可以组合函数完成最基本的功能了，就像这样：

```c
int main() {
    char path[] = "../flag.rar";  // 文件路径
    byte kdf_count;  // 迭代次数
    byte salt[16];  // 盐值
    byte rar_pwcheck[8];  // 文件中 Check value 的前 8 bytes

    char pass[7];  // 用于猜解的密码，多一位是因为 \0
    byte pwcheck[8];  // 猜解密码对应 pwcheck

    if (get_rar_info(path, &kdf_count, salt, rar_pwcheck)) {
        exit(EXIT_FAILURE);
    }

    for(int i = 100000; i < 1000000; i++) {
        sprintf(pass, "%.6d", i);
        if (generate_pwcheck(pass, (int) strlen(pass), salt, sizeof(salt), kdf_count, pwcheck)) {
            exit(EXIT_FAILURE);
        }
        if (memcmp(pwcheck, rar_pwcheck, 8) == 0) {
            printf("Success: %s\n", pass);
            exit(EXIT_SUCCESS);
        }
    }

    exit(EXIT_SUCCESS);
}
```

当然，这有点慢。

```
> time ./LainCrack
Success: 123456
________________________________________________________
Executed in  145.57 secs    fish           external
   usr time  145.57 secs  164.00 micros  145.57 secs
   sys time    0.00 secs  128.00 micros    0.00 secs
```

花费 145 秒，根据结果预估速度为`160 pwd/s`，难以接受的速度，但在优化之前，先让我完成其他功能。

### 加载字典

返回一个代表字典内容的二维数组，顺带写了个释放内存的函数，以备不时之需。

同样的，错误信息留在程序框架完成后完成，先忽略。

```c
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

            dicts[i] = malloc(strlen(buf)+1);
            if (dicts[i] == NULL) return NULL;
            memcpy(dicts[i], buf, strlen(buf)+1);

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

void free_dicts(char **dicts, size_t count) {
    for (int i = 0; i < count; i++) {
        free(dicts[i]);
    }
    free(dicts);
}
```

测试代码：

```c
int main() {
    size_t count;
    char **dicts = load_dicts("../wordlist.txt", &count);
    if (dicts == NULL) exit(EXIT_FAILURE);
    
    for (int i = 0; i < count; i++) {
        printf("line[%d]: %s\n", i, dicts[i]);
        free(dicts[i]);
    }
    free(dicts);
    return 0;
}
```

```
> ./LainCrack
line[0]: 12345
line[1]: admin
line[2]: password
line[3]: test123
line[4]: a12345678
line[5]: 123321
line[6]: 123456
```

### 测试字典模式

在穷举模式上修改一些代码：

```c
int main() {
    char path[] = "../flag.rar";  // 文件路径
    byte kdf_count;  // 迭代次数
    byte salt[16];  // 盐值
    byte rar_pwcheck[8];  // 文件中 Check value 的前 8 bytes

    byte pwcheck[8];  // 猜解密码对应 pwcheck

    size_t count;
    char **dicts = load_dicts("../wordlist.txt", &count);  // 字典数组
    if (dicts == NULL) exit(EXIT_FAILURE);

    // 获得 RAR 压缩包信息
    if (get_rar_info(path, &kdf_count, salt, rar_pwcheck)) {
        exit(EXIT_FAILURE);
    }

    // 遍历每一条密码
    for (int i = 0; i < count; i++) {
        printf("now: %s\n", dicts[i]);
        // 生成 PwCheck
        if (generate_pwcheck(dicts[i], (int) strlen(dicts[i]), salt, sizeof(salt), kdf_count, pwcheck)) {
            exit(EXIT_FAILURE);
        }
        // 比对
        if (memcmp(pwcheck, rar_pwcheck, 8) == 0) {
            printf("Success: %s", dicts[i]);
            exit(EXIT_SUCCESS);
        }
        free(dicts[i]);
    }
    free(dicts);

    exit(EXIT_SUCCESS);
}
```

```
> ./LainCrack
now: 12345
now: admin
now: password
now: test123
now: a12345678
now: 123321
now: 123456
Success: 123456
```

### 命令行参数解析

这是一个命令行工具必备的。

添加了三个选项，用`-R`或`--rar`指定 RAR 文件路径，用`-D`或`--dicts`指定字典文件路径，当无选项或者键入`--help`时会打印帮助信息。

```c
static const char *opt_str = "R:D:";
static struct option opts[] = {
        {"rar", required_argument, NULL, 'R'},
        {"dicts", required_argument, NULL, 'D'},
        {"help", optional_argument, NULL, 'H'},
};
static char help[] = "Usage LainCrack [OPTIONS]\n"
                     "OPTIONS:\n"
                     "  -R, --rar \t\tEncrypted RAR file path  [required]\n"
                     "  -D, --dicts \t\tDictionary file path  [required]\n"
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
    while((opt = getopt_long(argc, argv, opt_str, opts, NULL)) != EOF){
        switch (opt) {
            case 'R':
                rar_path = optarg;
                break;
            case 'D':
                dicts_path = optarg;
                break;
            case 'H':
                printf("%s", help);
                exit(EXIT_SUCCESS);
            default:
                exit(EXIT_FAILURE);
        }
    }

    printf("================ INFO ==================\n");
    printf("[RAR]: %s\n[DICT]: %s\n", rar_path, dicts_path);

    switch (run(dicts_path, rar_path)) {
        case -1:
            printf("Error loading dictionary file\n");
            exit(EXIT_FAILURE);
        case -2:
            printf("Error reading RAR file\n");
            exit(EXIT_FAILURE);
        case -3:
            printf("Error generating PwCheck\n");
            exit(EXIT_FAILURE);
        case 0:
            printf("================ DONE ==================\n");
            exit(EXIT_SUCCESS);
    }

```

```
> ./LainCrack --help
Usage LainCrack [OPTIONS]
OPTIONS:
  -R, --rar 		Encrypted RAR file path  [required]
  -D, --dicts 		Dictionary file path  [required]
  --help 		Show this message and exit
```

```
> ./LainCrack -R ../flag.rar -D ../wordlist.txt
...
Success: 123456
Done
```

同时我将程序执行的主要部分从`main`函数抽离，放进了`run`函数。

```c
int run(char *dicts_path, char *rar_path) {
    byte kdf_count;  // 迭代次数
    byte salt[16];  // 盐值
    byte rar_pwcheck[8];  // 文件中 Check value 的前 8 bytes

    byte pwcheck[8];  // 猜解密码对应 pwcheck
    char **dicts = NULL;  // 字典数组
    size_t count;  // 字典条目数量

    printf("================ START =================\n");

    dicts = load_dicts(dicts_path, &count);  // 加载字典
    if (dicts == NULL) return -1;

    // 获得 RAR 压缩包信息
    if (get_rar_info(rar_path, &kdf_count, salt, rar_pwcheck)) {
        free_dicts(dicts, count);
        return -2;
    }

    // 遍历每一条密码
    for (int i = 0; i < count; i++) {
        // 生成 PwCheck
        printf("Now: %s\n", dicts[i]);  // 进度
        if (generate_pwcheck(dicts[i], (int) strlen(dicts[i]), salt, sizeof(salt), kdf_count, pwcheck)) {
            free_dicts(dicts, count);
            return -3;
        }
        // 比对
        if (memcmp(pwcheck, rar_pwcheck, 8) == 0) {
            printf("================ SUCCESS ===============\n");
            printf("PASSWORD: %s\n", dicts[i]);
            free_dicts(dicts, count);
            return 0;
        }
    }
    free_dicts(dicts, count);
    printf("================ FAILED ================\n");
    printf("Failed to find password\n");
    return 0;
}
```

增加了提示信息后，程序输出美观了许多：

```
> ./LainCrack -R ../flag.rar -D ../wordlist.txt
================ INFO ==================
[RAR]: ../flag.rar
[DICT]: ../wordlist.txt
================ START =================
Now: 123451
Now: 12321
Now: 14221
Now: 132456
Now: 123456
================ SUCCESS ===============
PASSWORD: 123456
================ DONE ==================

> ./LainCrack -R ../flag.rar -D ../wordlist.txt
================ INFO ==================
[RAR]: ../flag.rar
[DICT]: ../wordlist.txt
================ START =================
Now: 123451
Now: 12321
Now: 14221
Now: 132456
================ FAILED ================
Failed to find password
================ DONE ==================
```

## 优化程序

### 对比现有工具

对比一下`rarcrack`单线程时的速度（它是调用`unrar`实现的），我将配置文件修改为从`100000`开始的数字：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rarcrack>
  <abc>0123456789</abc>
  <current>100000</current>
  <good_password></good_password>
</rarcrack>
```

```
> time rarcrack flag.rar  --threads 1
...
GOOD: password cracked: '123456'

________________________________________________________
Executed in  486.06 secs    fish           external
   usr time  446.15 secs  309.00 micros  446.14 secs
   sys time   43.59 secs  189.00 micros   43.59 secs
```

由于其只支持字符集模式，我使用测试穷举时的结果进行对比。之前测试穷举时估算的速度为`160 pwd/s`，而`rarcrack`在同是单线程的情况下速度为`48 pwd/s`，慢了几倍，这应该与`unrar`的算法无关，大概是调用系统命令时造成的损耗。

但是，`rarcrack`在多线程（我指定了八个）时就快了太多，约为`325 pwd/s`。

```
> time rarcrack flag.rar  --threads 8
...
GOOD: password cracked: '123456'

________________________________________________________
Executed in   72.02 secs    fish           external
   usr time  511.46 secs  281.00 micros  511.46 secs
   sys time   40.97 secs  172.00 micros   40.97 secs
```

比起优化核心的`pbkdf2`算法，使用多线程可能性价比更高。

### 加速加速加速（多线程）

Linux 下多线程属于即开即用状态，倒是省了一些心。

加了个读写锁，控制程序完毕状态，但并不必要，因为程序逻辑上可以允许读到旧值。

首先我将先前的一些变量放进了全局，因为它们各个线程内都需要，且不会更改。

```c
byte KdfCount;  // 迭代次数
byte Salt[16];  // 盐值
byte RARPwCheck[8];  // 文件中 Check value 的前 8 bytes
char **Dicts = NULL;  // 字典数组
size_t Count;  // 字典总数
int ThreadNum = 4;  // 线程数

int Finished = 0;  // 完成标记
pthread_rwlock_t FinishedRWLock = PTHREAD_RWLOCK_INITIALIZER;  // 锁
```

建立了一个结构体向各个线程函数传参，其中包含偏移值`offset`和本轮数量`count`。通过`offset`可以控制从某一起点（将密码字典拆分给了多个线程）开始遍历密码字典，直到测试完`count`个密码。

```c
typedef struct {
    int offset;
    size_t count;
} CrackArgs;

void *crack(void *args) {
    CrackArgs *crack_args = (CrackArgs *) args;
    byte pwcheck[8];  // 字典密码对应 pwcheck

    // 遍历每一条密码
    for (int i = 0; i < crack_args->count; i++) {

        pthread_rwlock_rdlock(&FinishedRWLock);
        if (Finished) {
            pthread_rwlock_unlock(&FinishedRWLock);
            break;
        }
        pthread_rwlock_unlock(&FinishedRWLock);

        printf("STATUS: %s\n", (Dicts + crack_args->offset)[i]);  // 进度

        // 生成 PwCheck
        if (generate_pwcheck(
                (Dicts + crack_args->offset)[i], (int) strlen((Dicts + crack_args->offset)[i]),
                Salt, sizeof(Salt),
                KdfCount, pwcheck)) {
            fprintf(stderr, "[WARNING] Failed to generate PwCheck, password: %s", (Dicts + crack_args->offset)[i]);
            continue;
        }

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
```



假设有 101 条密码，四个线程`thread{1-4}`，那么任务分配逻辑如下：

```
thread1: offset=0,  count=25
thread2: offset=25, count=25
thread3: offset=50, count=25
thread4: offset=75, count=25+1
```

最后一个线程负责额外处理多余出的一部分。

```c
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
```



线程数由`-T`或`--threads`控制

```c
static const char *opt_str = "R:D:T:";
static struct option opts[] = {
        {"rar",     required_argument, NULL, 'R'},
        {"dicts",   required_argument, NULL, 'D'},
        {"threads", required_argument, NULL, 'T'},
        {"help",    optional_argument, NULL, 'H'},
};
static char help[] = "Usage LainCrack [OPTIONS]\n"
                     "OPTIONS:\n"
                     "  -R, --rar \t\tEncrypted RAR file path  [required]\n"
                     "  -D, --dicts \t\tDictionary file path  [required]\n"
                     "  -T, --threads \tThreads {default: 4}\n"
                     "  --help \t\tShow this message and exit\n";

int main(int argc, char *argv[]) {
	// ...
    while ((opt = getopt_long(argc, argv, opt_str, opts, NULL)) != EOF) {
        switch (opt) {
            // ...
            case 'T':
                ThreadNum = (int) strtol(optarg, NULL, 10);
                break;
			// ...
        }
    }

```



测试一下速度，字典文件包含数字`000000-999999`，线程 `8`，略微修改了程序使它跑出正确密码后继续执行，直到字典全部测试完成。

```
> seq -f '%06g' 000000 999999 > ../wordlist.txt 
> time ./LainCrack -R ../flag.rar -D ../worldlist.txt -T 8
================ INFO ==================
[RAR]: ../flag.rar
[DICT]: ../wordlist.txt
================ START =================
RIGHT PASSWORD: 123456
================ DONE ==================

________________________________________________________
Executed in   25.06 mins    fish           external
   usr time  176.12 mins  537.00 micros  176.12 mins
   sys time    0.00 mins    0.00 micros    0.00 mins
```

速度约为`665 pwd/s`，提升很明显。

### 再快点再快点（自己实现 PBKDF2）

建立一个`crypto.c`文件。

先实现一个基本的 `hmac_sha256`，标准公式：` HMAC(K, M) = H((K’⊕opad)|H((K’⊕ipad)|M))`

```c
void hmac_sha256(byte *key, size_t key_len,
                 byte *message, size_t message_len,
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

    // 生成 IKeyPad 和 OKeyPad
    // 不足位数补零被融合在此操作里
    byte i_key_pad[block_size];
    byte o_key_pad[block_size];
    for (size_t i = 0; i < key_len; i++) {
        i_key_pad[i] = 0x36 ^ key[i];
        o_key_pad[i] = 0x5c ^ key[i];
    }
    for (size_t i = key_len; i < block_size; i++) {
        i_key_pad[i] = 0x36;
        o_key_pad[i] = 0x5c;
    }


    byte tmp[block_size＊2];
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
```

 接下来是`pbkdf2`

标准公式如下，其中`PRF`使用`hmac_sha256`，这里没有实现完全的算法，仅使`dkLen`为固定的`SHA256_DIGEST_LENGTH`

```
DK = PBKDF2(PRF, Password, Salt, c, dkLen)
DK = T1 + T2 + ⋯ + Tdklen/hlen
Ti = F(Password, Salt, c, i)
F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
U1 = PRF(Password, Salt + INT_32_BE(i))
U2 = PRF(Password, U1)
⋮
Uc = PRF(Password, Uc−1)
```

代码：

```c
void pbkdf2(byte *pass, size_t pass_len,
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

    hmac_sha256(pass, pass_len, salt_data, salt_len + 4, u1);
    memcpy(result, u1, SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < iter_count - 1; i++) {
        hmac_sha256(pass, pass_len, u1, SHA256_DIGEST_LENGTH, u2);
        memcpy(u1, u2, SHA256_DIGEST_LENGTH);
        for (size_t j = 0; j < SHA256_DIGEST_LENGTH; j++) result[j] ^= u2[j];
    }
}
```



回到刚刚的`hmac_sha256`可以发现，`i_key_pad`和`o_key_pad`只随`key`改变，而迭代时`key`一直为我们传入的`pass`，它们其实只需要计算一次即可。

修改`hmac_256`，当`set_i_key_pad`和`set_o_key_pad`为真时，将会使用传入的`i_key_pad_opt`和`o_key_pad_opt`，否则将计算结果保存倒`i_key_pad_opt`和`o_key_pad_opt`。

```c
void hmac_sha256(byte *key, size_t key_len,
                 byte *message, size_t message_len,
                 byte *i_key_pad_opt, bool set_i_key_pad,
                 byte *o_key_pad_opt, bool set_o_key_pad,
                 byte *res_hash) {
	// ...

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

	// ...
}

void pbkdf2(byte *pass, size_t pass_len,
            byte *salt, size_t salt_len,
            size_t iter_count, byte *result) {
	// ...

    byte i_key_pad[64];  // block_size = 64
    byte o_key_pad[64];

    hmac_sha256(pass, pass_len, salt_data, salt_len + 4,
                i_key_pad, false, o_key_pad, false, u1);  // 这里先计算一次
    memcpy(result, u1, SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < iter_count - 1; i++) {
        hmac_sha256(pass, pass_len, u1, SHA256_DIGEST_LENGTH,
                    i_key_pad, true, o_key_pad, true, u2);  // 这里开始复用计算结果
        memcpy(u1, u2, SHA256_DIGEST_LENGTH);
        for (size_t j = 0; j < SHA256_DIGEST_LENGTH; j++) result[j] ^= u2[j];
    }
}
```

替换`main.c`中的`PKCS5_PBKDF2_HMAC()`为刚刚写的`pbkdf2()`，重新测试：

```
> time ./LainCrack -R ../flag.rar -D ../wordlist.txt -T 8 -Q
================ INFO ==================
[RAR]: ../flag.rar
[DICT]: ../wordlist.txt
================ START =================
RIGHT PASSWORD: 123456
================ DONE ==================

________________________________________________________
Executed in   18.37 mins    fish           external
   usr time  146.37 mins  408.00 micros  146.37 mins
   sys time    0.00 mins    0.00 micros    0.00 mins
```

同是八个线程，速度约为`900 pwd/s`，又快了 50 % 。

## 后话

研究过程中最大的阻碍是有关 RAR 密钥生成的资料太少，但事实证明，代码会是更好的参考。

改进空间还很大，像是：错误处理还待完善；对于输入的校验不足（RAR 文件格式、字典文件格式、线程数量）；执行进度没能简洁地输出。

但这只是个实验，大概不会继续做太多的工作了，用 Rust 重构倒是值得考虑的事情。

## 参考

[rarlab](https://www.rarlab.com/technote.htm#enchead)

[RAR文件格式分析](https://sp4n9x.github.io/2020/04/10/RAR%E6%96%87%E4%BB%B6%E6%A0%BC%E5%BC%8F%E5%88%86%E6%9E%90/#2-2-3%E3%80%81Archive-blocks-%E5%8E%8B%E7%BC%A9%E6%96%87%E6%A1%A3%E5%9D%97)

[RAR 5.0 密码破解](https://xugr.me/writing/blog/rar-crack/)

[https://connect.ed-diamond.com/MISC/misc-092/usage-de-la-cryptographie-par-les-formats-d-archives-zip-rar-et-7z](https://connect.ed-diamond.com/MISC/misc-092/usage-de-la-cryptographie-par-les-formats-d-archives-zip-rar-et-7z)

[https://github.com/lclevy/unarcrypto/blob/master/unarcrypto.py](https://github.com/lclevy/unarcrypto/blob/master/unarcrypto.py)

[https://github.com/pmachapman/unrar/blob/master/crypt5.cpp](https://github.com/pmachapman/unrar/blob/master/crypt5.cpp)

[基于多核FPGA的压缩文件高效能口令恢复算法的研究与实现](https://kns.cnki.net/kcms/detail/detail.aspx?dbcode=CMFD&dbname=CMFD201902&filename=1019098098.nh&uniplatform=NZKPT&v=L9acCveNZq-UZPekbioEXizFvYFEuCLxWqtLSZJ3xVk85XILBn1_-XYmTUQvC8c6)

[https://whu-pzhang.github.io/dynamic-allocate-2d-array/](https://whu-pzhang.github.io/dynamic-allocate-2d-array/)

[https://github.com/ziman/rarcrack/blob/master/rarcrack.c](https://whu-pzhang.github.io/dynamic-allocate-2d-array/)

[http://www.codebaoku.com/jwt/jwt-hmac-sha256.html](http://www.codebaoku.com/jwt/jwt-hmac-sha256.html)

[https://en.wikipedia.org/wiki/PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)

[PBKDF2函数的一种快速实现](https://chn.oversea.cnki.net/KCMS/detail/detail.aspx?dbcode=CJFD&dbname=CJFDHIS2&filename=TXBM201312026&uniplatform=OVERSEAS_CHS&v=aOEvJECgoI7esPVNXrpeXiG5iIFYGXaetctEpzH2rD2CiCAY5pjEbzMqarcpL9Ia)