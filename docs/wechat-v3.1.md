# 一个 Bash 单文件,45 模块,Linux 失陷主机一键应急排查

> 写给蓝队/应急响应工程师:把 9 本应急手册的精华压进 1064 行 Bash,零依赖、纯只读、SIEM 可消费。

---

## 一、为什么又造一个轮子

市面上的 Linux 应急响应工具,要么是 chkrootkit/rkhunter 这种**专精 Rootkit** 的老牌工具,要么是 GScan 这种**功能全但需要 Python 环境**的工程化方案。

但实战现场经常是这样的:

- 客户给的跳板机是**最小化安装的 CentOS 6**,连 `python3` 都没有
- Docker 容器里被植入了 Webshell,但容器**没有包管理器**,装不了任何工具
- 内网横向时拿到一台 Linux 跳板,**不能改主机**(只能看不能动),需要 5 分钟内出结论
- 应急结束后要把发现喂给 SIEM,但**不想装 filebeat/logstash**

这些场景的共同诉求是:**一个文件、零依赖、纯只读、能输出结构化日志**。

XWAY IR 就是干这个的。

---

## 二、它是什么

**XWAY IR v3.1** 是一个纯 Bash 单文件 Linux 应急响应工具,1064 行代码,45 个检查模块,跑完不修改主机任何文件。

```bash
sudo bash xway_ir.sh
```

输出三路:

1. **彩色 stdout** —— SSH 终端直接看,分段横幅 + 45 模块逐项 + 综合结论 + 横向移动分析 + 攻击路径时间线
2. **`.log` 文件** —— 含 ANSI 颜色,`less -R` 还原,取证留存
3. **`.jsonl` 文件** —— 每行一条 JSON,字段 `ts/level/module/title/file/hint/score`,直接 `jq` 或喂 SIEM

```json
{"ts":"2026-07-19T12:52:36+08:00","level":"HIGH","module":"file","title":"无主/无组文件 (攻击者账号已删)","file":"/bin/addgnupghome","hint":"find -nouser 溯源","score":8}
```

---

## 三、45 个模块覆盖什么

按类别分,涵盖应急响应主流场景:

| 类别 | 模块编号 | 检查点 |
|---|---|---|
| **进程** | 01, 31, 32 | 挖矿/RCE 进程、deleted 文件占用、隐藏进程(proc vs ps) |
| **网络** | 02, 35 | C2 端口外联、Maltrail IOC 命中、SSH/Socks/DNS/HTTP/ICMP 隧道 |
| **持久化** | 03, 19, 21-23, 26 | crontab/at/systemd、SSH key command= 后门、motd、TCP Wrappers、udev、/etc/skel |
| **Rootkit** | 04, 29 | LKM 模块、ld.so.preload、60+ 文件签名、kallsyms、内核模块签名 |
| **权限** | 05, 12, 17 | SUID/SGID、sudoers、capabilities、shadow/passwd 权限、UID=0 |
| **文件** | 06, 09, 42 | 7 天改动、临时目录可执行、银狐 .so、无主/777/欺骗名/大文件 |
| **Web** | 07, 11, 38-40 | Webshell、Java 内存马、access log 内存马、Behinder/蚁剑 UA、网页暗链 |
| **挖矿** | 08 | 高 CPU + 矿池配置 + Maltrail 矿池域名 |
| **横向移动** | 10, 43-45 | SSH 公钥/爆破/known_hosts、SSH 软连接后门、strace 凭据捕获、登录聚合 |
| **后门** | 14-16, 20, 24, 25 | LD_PRELOAD、alias、sshd wrapper、BASH 函数/trap、Python .pth、PAM |
| **暴力破解** | 36, 37 | SSH/MySQL/FTP/MongoDB/SMTP/Redis |
| **完整性** | 28, 30 | rpm -Va / debsums、GPG 密钥 |
| **数据库** | 41 | SQLi 痕迹(union/sleep/load_file/xp_cmdshell) |

---

## 四、v3.1 新增的 8 个模块

这次更新基于 9 本公开应急手册的 gap 分析,补齐了之前漏检的 8 类场景:

| # | 模块 | 实战价值 |
|---|---|---|
| 38 | **Web 内存马(access log)** | 同一 URL 先 404 后 200(内存马典型特征)+ POST 响应 16 字节对齐(Behinder AES-128 块特征) |
| 39 | **Webshell 工具流量** | Behinder/蚁剑/Chopper/Cknife/Godzilla/天蝎 的 UA 指纹库,即使流量加密也能识别 |
| 40 | **网页暗链** | 赌博/色情关键词 + JS `location.href` 劫持 + Nginx `sub_filter` 配置劫持 |
| 41 | **数据库 SQLi 痕迹** | `~/.mysql_history` + MySQL/PostgreSQL 日志中 `union select`/`sleep(`/`load_file`/`xp_cmdshell` |
| 42 | **文件系统异常** | 无主/无组文件(攻击者账号被删后残留)+ 777 可执行 + 欺骗性文件名(`...`/`.. `)+ 临时目录 >10M 大文件 |
| 43 | **SSH 软连接后门** | `pam_rootok` 劫持:argv[0]=`su`/`chsh`/`chfn` 但 exe 指向 sshd + `find -lname *sshd*` |
| 44 | **strace 凭据捕获注入** | `/etc/bashrc` 中 `strace -o /tmp/.xxx.log` 包裹 `ssh`/`su`/`sudo`/`passwd`,悄悄记录管理员密码 |
| 45 | **登录痕迹聚合** | `lastb` 失败 Top IP + `last` 成功 + `useradd`/`userdel` 日志 + `lastlog` 非空账号 |

### 资料来源

- 奇安信安服团队《网络安全应急响应技术实战指南》
- 深信服《网络安全事件应急指南》
- 《应急响应实战笔记 2020》
- 《Linux 应急响应流程及实战演练》
- 《应急响应 溯源分析》
- 《冰蝎、蚁剑过流量监控改造及红队经典案例分享》

> **致谢**:以上手册的作者和团队。XWAY IR 只是把散落在 9 本书里的检测点压进一个可执行文件,真正的知识归属原作者。

---

## 五、最有价值的部分:横向移动证据链

45 个模块里,**模块 10(横向移动)是最核心的**。它不是简单"列出来",而是采集 9 类证据后做三档判定:

### 情形 A:0 条证据
```
✅ 未发现横向移动痕迹
结论:这台主机大概率是初始入侵点或孤立失陷端
```

### 情形 B:1-2 条证据
```
⚠️ 横向移动证据有限
建议:拉 auth.log / .bash_history / 同网段比对
```

### 情形 C:≥3 条证据
```
🔴 高度怀疑已发生横向移动
立即行动:
  1. 立即隔离(iptables -I INPUT 1 -j DROP)
  2. 拉内存 dump(avml/LiME)+ 磁盘镜像(dd)
  3. 排查所有 authorized_keys 主机
  4. 排查 known_hosts 目标主机
  5. 排查 SSH 失败登录源 IP
  6. 全网段 SSH/crontab 审计
```

这个判定的意义:**告诉操作员"这台机器是不是跳板"**,而不只是"这台机器有没有失陷"。前者决定处置范围(单机 vs 全网),后者只决定处置动作。

---

## 六、v3.1 还修了 4 个真 bug

迭代时顺便修了之前审计发现的 4 个 P0 bug(都是新模块也会踩的坑):

### Bug 1:`--severity` 子串匹配

旧版 `[[ "$SEVERITY_FILTER" == *crit* ]]` 会误匹配 `critical`/`critlow`,而且 `--severity high` 不包含 CRIT。

新版改成精确成员比对 + hierarchy:`--severity high` 自动包含 CRIT(因为 CRIT 比 HIGH 更严重)。

### Bug 2:JSONL 转义不全

旧版只转义双引号,漏了反斜杠、换行、控制字符。攻击者控制的 hostname 如果含 `\033[2J`,会污染 SIEM 的 JSON 解析,甚至在 `less` 查看时清屏。

新版加了 `strip_ctl()`(删除控制字符)+ `json_escape()`(纯 Bash 字符串替换,转义 `\`/`"`/`\n`/`\r`/`\t`),无 jq 依赖。

### Bug 3:IOC 文件 regex 注入

旧版 `load_ioc_pattern` 把 IOC 文件直接拼成 `pat1|pat2|pat3` 喂给 `grep -E`。如果 IOC 文件里有 `.*` 或 `(`,grep 会退化成 regex,`home`/`cwd` 这种普通词被反向匹配,**全场误报**。

新版加 awk 转义所有 regex 元字符后拼 alternation,IOC 文件里写什么都安全。

### Bug 4:FINDINGS 分隔符错位

旧版 timeline 用 `|` 分隔字段,但 `file` 字段含 `|` 时(如 `echo a | nc` 这种 bash_history 命中行)列错位。

新版改用 ASCII Unit Separator `\x1f` + `LC_ALL=C sort`,彻底解决。

---

## 七、设计哲学:为什么是 Bash

很多人会问:这种工具为什么不用 Python/Go/Rust 重写?

答案是**现场可用性**:

| 场景 | Python 工具 | Bash 工具 |
|---|---|---|
| 最小化 CentOS 6 | 需要 `yum install python3` | `bash xway_ir.sh` 直接跑 |
| Docker slim 镜像 | 镜像里没 python | `bash` 一定有 |
| Alpine | `apk add python3` | `apk add bash`(很多 Alpine 默认就有) |
| 国产化 OS(UOS/Kylin) | Python 版本碎片化 | Bash 永远在 |
| 内网横向拿到的跳板 | 不能装包 | SCP 过去就能跑 |
| 离线环境 | 要带 pip 依赖 | 单文件 + lib/ 目录 |

Bash 的"丑"是它的优势:没有依赖地狱,没有版本碎片化,没有虚拟环境。**只要主机能起来,Bash 就在,XWAY IR 就能跑**。

代价是代码不如 Python 优雅,JSON 转义要手写,错误处理要靠 `set +e`。但这些代价换来的是**部署零摩擦**,值得。

---

## 八、IOC 数据外置,改文本就能扩展

所有检测规则外置到 `lib/` 目录,22 个文本文件,改文本就能加新 IOC,不动代码:

```
lib/
├── iocs/                    # Maltrail 精选 IOC
│   ├── miners.txt           # 挖矿矿池域名 + 进程名
│   ├── c2.txt               # APT/勒索/银行木马 C2
│   ├── backdoors.txt        # 已知 Webshell 文件名
│   ├── rshell.txt           # 反向 shell 命令模式
│   ├── behinder_uas.txt     # Webshell 工具 UA (v3.1 新)
│   └── LICENSE.notice       # Maltrail MIT 归属
├── rootkit_signatures.txt   # 60+ Rootkit 文件/目录签名
├── bad_lkm.txt              # 80+ 恶意 LKM 模块名
├── suid_whitelist.txt       # 默认 SUID 白名单
├── suspicious_ports.txt     # 可疑端口
├── darklink_keywords.txt    # 网页暗链关键词 (v3.1 新)
├── sqli_patterns.txt        # SQLi 特征模式 (v3.1 新)
└── bpftrace_monitor.bt      # bpftrace 隧道监控脚本
```

想加新的挖矿矿池?编辑 `lib/iocs/miners.txt` 加一行就行。想加新的 Webshell 工具 UA?编辑 `lib/iocs/behinder_uas.txt`。**不用懂 Bash**。

---

## 九、6 个 CLI flags,够用就好

```bash
sudo bash xway_ir.sh                            # 全量扫描
sudo bash xway_ir.sh --module 1,3,10            # 只跑指定模块
sudo bash xway_ir.sh --severity crit,high        # 只看高危(含 CRIT)
sudo bash xway_ir.sh --timeout 30                # 每检查限时 30s
sudo bash xway_ir.sh --no-color                  # 关颜色
sudo bash xway_ir.sh --out-dir /tmp/ir           # 指定输出目录
sudo bash xway_ir.sh --json-only                 # 只输出 JSONL
```

不搞配置文件、不搞 YAML、不搞 INI。**应急现场没时间看文档,flag 越少越好**。

---

## 十、CI + 119 个 bats 测试

代码托管在 GitHub,CI 跑三件事:

1. **shellcheck** —— Bash 静态检查
2. **bats** —— 119 个功能测试用例
3. **bash -n** —— 语法检查

每次 PR 都自动跑,回归有保障。

---

## 十一、和其他工具的差距

XWAY IR 不是万能的,有明确的边界:

| 能力 | XWAY IR | chkrootkit/rkhunter | GScan |
|---|---|---|---|
| 部署难度 | ✅ 单文件零依赖 | ✅ 编译安装 | ⚠️ Python 环境 |
| 模块数 | 45 | ~20 | ~100 |
| JSONL 输出 | ✅ | ❌ | ✅ |
| 横向移动证据链 | ✅ | ❌ | ❌ |
| 攻击路径时间线 | ✅ | ❌ | ❌ |
| Web 内存马检测 | ✅ | ❌ | ❌ |
| 二进制 hash 校验 | ⚠️ 仅 rpm-Va | ✅ 全 | ⚠️ |
| 高级 Rootkit 检测 | ⚠️ | ✅ | ⚠️ |
| 多主机 fan-out | ❌ | ❌ | ❌ |

**定位**:**快速排查 + 结构化输出 + 横向移动判定**。深度分析还是要配合 chkrootkit/rkhunter/avml/河马。

---

## 十二、快速开始

```bash
# 方式 1:克隆仓库(推荐,带 lib/ IOC 库)
git clone https://github.com/A4n9g7e2l/Xway.git
cd Xway
sudo bash xway_ir.sh

# 方式 2:远程一行执行(不带 lib/,部分模块会跳过)
curl -fsSL https://raw.githubusercontent.com/A4n9g7e2l/Xway/main/xway_ir.sh | sudo bash

# 方式 3:拷贝到目标机
scp -r Xway root@<target>:/tmp/
ssh root@<target> "cd /tmp/Xway && bash xway_ir.sh"
```

GitHub 仓库:**https://github.com/A4n9g7e2l/Xway**

---

## 十三、最后

这个工具的起点是 2026 年 7 月一次半夜的应急响应。客户给了台 CentOS 6 跳板机,Python 装不上,YUM 源过期,只能用 Bash 凑合写了个 13 模块的脚本。

后来发现这个"凑合"的形态恰好是最实用的:**零依赖 + 单文件 + 纯只读**。于是慢慢迭代到 v3.1,45 模块,1064 行,集成 NOP Team 手册 + 9 本公开应急手册的精华。

不为替代谁,只是填补"**现场 5 分钟出结论**"这个特定场景的工具空白。

如果你也是蓝队/应急响应工程师,欢迎试用、提 Issue、贡献 IOC。

---

> **GitHub**:https://github.com/A4n9g7e2l/Xway
> **License**:MIT
> **版本**:v3.1 (2026-07-19)
> **致谢**:NOP Team、grayddq/GScan、stamparm/maltrail、奇安信安服、深信服、以及所有公开应急手册的作者

<p align="center">
  🛡️ <b>XWAY 蓝队</b> · 攻防不息,守护不止
</p>
