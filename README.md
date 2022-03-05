# LainCrack
更快的 RAR 密码爆破工具，使用纯 C 语言实现，不依赖外部程序（如`unrar`）  
仅支持 RAR 5.x  
测试 8 线程时速度为`900 pwd/s`，同情况下`rarcrack`在`160 pwd/s`。
# 使用
```
./LainCrack --help
Usage LainCrack [OPTIONS]
OPTIONS:
  -R, --rar TEXT	Encrypted RAR file path  [required]
  -D, --dicts TEXT	Dictionary file path  [required]
  -T, --threads NUM	Threads {default: 4}
  -Q, --quiet 		Don't show status
  --help 		Show this message and exit
```
```
./LainCrack -R encrypted.rar -D wordlist.txt -T 16 -Q
================ INFO ==================
[RAR]: encrypted.rar
[DICT]: wordlist.txt
================ START =================
RIGHT PASSWORD: 123456
================ SUCCESS =============== 
```
# 说明
这是我的实训作业，不喜欢`xxx管理系统`，就写了这个。  
代码现学现卖写的不好，许多地方还没有完善。这个仓库仅为了记录一下分析 RAR 加密格式的过程，当然，也不是不能用。  
过程记录： [note.md](note.md)