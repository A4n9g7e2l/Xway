# XWAY IR — Linux 失陷主机一键应急排查

> 🛡️ **蓝队应急响应 / Incident Response / Linux 主机取证**
> v2.0 — 18 个排查模块 + 攻击路径时间线 + JSON-lines 日志 + IOC 外置 + Maltrail 数据源
> 架构借鉴自 [grayddq/GScan](https://github.com/grayddq/GScan) (MIT)

![Language](https://img.shields.io/badge/language-Bash-4EAA25)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-v2.0-blueviolet)
![Status](https://img.shields.io/badge/status-stable-success)
![Tests](https://img.shields.io/badge/tests-bats-4EAA25)
![CI](https://github.com/A4n9g7e2l/Xway/actions/workflows/ci.yml/badge.svg)

---

## 目录

1. [项目简介](#1-项目简介)
2. [核心特性](#2-核心特性)
3. [适用场景](#3-适用场景)
4. [快速开始](#4-快速开始)
5. [使用方法](#5-使用方法)
6. [排查项详解](#6-排查项详解)
7. [风险评分体系](#7-风险评分体系)
8. [横向移动分析](#8-横向移动分析)
9. [已知限制](#9-已知限制)
10. [配合工具](#10-配合工具)
11. [应急响应 SOP](#11-应急响应-sop)
12. [贡献与反馈](#12-贡献与反馈)
13. [免责声明](#13-免责声明)
14. [版权](#14-版权)

---

## 1. 项目简介

**XWAY IR** 是一款面向 **Linux 蓝队 / 应急响应工程师** 的一键排查脚本,用于在疑似失陷的主机上**快速评估入侵痕迹**。

- ✅ **零外部依赖** — 只用 `ps` `ss` `find` `grep` `crontab` `last` 等系统自带命令
- ✅ **纯命令行可视化** — ANSI 颜色 + 分段横幅,SSH 终端直接读
- ✅ **13 个排查模块** — 覆盖挖矿、Webshell、Rootkit、横向移动、Java 内存马、容器逃逸等主流场景
- ✅ **风险评分 + 横向移动证据链** — 不只是"列出来",而是"打分"和"判断是不是跳板"
- ✅ **不改主机** — 完全只读,跑完不留下任何文件(可选 `tee` 留日志)

> 适用版本:Linux 2.6+ / 主流发行版(CentOS / RHEL / Ubuntu / Debian / Kylin / UOS)
> 不适用:Windows、AIX、HP-UX(可以参考思路自行移植)

---

## 2. 核心特性

### 2.1 18 个排查模块

| 编号 | 模块 | 关注点 | 关键检测 |
|---|---|---|---|
| 1/18 | 进程排查 | 挖矿/僵尸/Web 进程派生 Shell | `xmrig` `minerd` `eval()` `www-data` 起 bash |
| 2/18 | 网络外联 | 可疑 C2 端口/异常已建立连接 | `:4444` `:1080` `:31337` |
| 3/18 | 启动项 | Crontab/systemd 服务持久化 | `wget` `/tmp/` 在 crontab |
| 4/18 | **内核 Rootkit (v2.0 增强)** | LKM 模块 + **84 文件/目录签名** + **/proc/kallsyms 比对** + 已知 LKM 黑名 | `diamorphine` `suterusu` `reptile` |
| 5/18 | SUID/SGID | 30 天内新增的高权限二进制 | `find / -perm /4000 -mtime -30` |
| 6/18 | 敏感文件 | 7 天内被改动的 `/etc` `/usr/local` `/root` | 异常配置篡改 |
| 7/18 | Webshell | 数字命名 + 一句话 + **已知 Webshell 家族** | `b374k.php` `c99.php` `eval($_POST` |
| 8/18 | 挖矿特征 | 高 CPU + 矿池配置 + **Maltrail 矿池域名** | `stratum` `xmrig` `pool.minexmr.com` |
| 9/18 | 可疑文件位置 | `/tmp` `/dev/shm` 可执行文件 + 银狐特征 | `[0-9][0-9].so` |
| 10/18 | **横向移动 (v2.0 增强)** | SSH 公钥 + **爆破成功后入侵关联** + 隧道 + 扫描工具 | 10 类证据 |
| 11/18 | Java 内存马 | 可疑 JAR + Tomcat 近期 JSP | `memshell` `agent` |
| 12/18 | 提权痕迹 | Sudoers 异常配置 | 非默认授权 |
| 13/18 | 容器环境 | 是否在 Docker / k8s 中 | `/.dockerenv` `cgroup` |
| 14/18 | **Shell 环境劫持 (v2.0 新增)** | 5 种 LD_* + PROMPT_COMMAND 注入 | `LD_PRELOAD=` `LD_AOUT_PRELOAD=` ... |
| 15/18 | **命令别名劫持 (v2.0 新增)** | `.bashrc` 替换 `ps/netstat/...` | `alias ps=` `alias netstat=` |
| 16/18 | **SSH 后门 (v2.0 新增)** | sshd 非 ELF / 非标准端口监听 | `file /usr/sbin/sshd` |
| 17/18 | **账号合规 (v2.0 新增)** | `/etc/shadow` 权限 + 空密码账号 | `chmod 000 /etc/shadow` |
| 18/18 | **bash_history 反 shell (v2.0 新增)** | 每行匹配反 shell 模式 | `/dev/tcp/` `nc -e` `python -c` |

### 2.2 v2.0 新能力 (借鉴自 GScan)

| 能力 | 说明 |
|---|---|
| **数据-逻辑分离** | 所有 IOC 抽出到 `lib/`,用户改文本即可扩展 |
| **攻击路径时间线** | 把所有发现按 mtime 排序,叙事化输出事故链条 |
| **JSON-lines 日志** | 同时输出 `.log` (人读) + `.jsonl` (SIEM 接入) |
| **5 个 GScan 检查** | SSH 爆破关联 / 84 Rootkit 签名 / alias 劫持 / 5 种 LD 劫持 / sshd 完整性 |
| **Maltrail IOC 库** | 精选 ~500 条高信号 IOC,保留 MIT attribution |

### 2.1 真实运行效果预览

> 以下是脚本在 **1 台被植入 SSH 公钥的云主机**上跑出来的**真实报告**(已打码)。
> 完整的 13 模块输出 + 风险评分 + 横向移动分析结论:

<p align="center">
  <img src="docs/sample-report.png" alt="XWAY IR 真实运行报告" width="900">
</p>

> 📌 **打码说明**:截图里所有 IP、主机名、用户名、SSH 公钥、攻击者 IP、来源 IP、SSH 指纹都已替换为占位符,真实信息仅保留在本地运行时的控制台上,不会泄露。
> 这台主机的真实结论是: 🔴 **风险评分 76 分 / CRITICAL 高危失陷 / 横向移动证据 4 条** — 已作为跳板机被攻击者使用。

---

## 3. 适用场景

| 场景 | 是否适用 | 备注 |
|---|---|---|
| 主机被挖矿,溯源感染路径 | ✅ | 模块 1/2/6/8/9 |
| Web 服务器疑似被入侵 | ✅ | 模块 1/7/11 |
| 内网横向移动,找跳板机 | ✅✅ | **模块 10 是核心** |
| 服务器响应缓慢,排查原因 | ✅ | 模块 1/2/8 |
| 主机被植入 Rootkit | ✅ | 模块 4 |
| 容器/云原生环境应急 | ✅ | 模块 13 + 其他模块在容器中也能跑 |
| Windows 主机排查 | ❌ | 请用 [PowerForensics](https://github.com/Invoke-IR/PowerForensics) / [Sysmon](https://docs.microsoft.com/sysinternals/downloads/sysmon) |
| 取证级深度分析 | ⚠️ | 本工具是"快速排查",深度分析请配合 chkrootkit/rkhunter/avml |

---

## 4. 快速开始

### 4.1 远程一行执行(最简)

```bash
curl -fsSL https://raw.githubusercontent.com/A4n9g7e2l/Xway/main/xway_ir.sh | sudo bash
```

> **强烈建议先保存再执行**,这样可以先看一眼再跑:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/A4n9g7e2l/Xway/main/xway_ir.sh -o xway_ir.sh
> less xway_ir.sh          # 浏览一下
> chmod +x xway_ir.sh
> sudo ./xway_ir.sh        # 确认无误后运行
> ```

### 4.2 克隆仓库

```bash
git clone https://github.com/A4n9g7e2l/Xway.git
cd Xway
chmod +x xway_ir.sh
sudo ./xway_ir.sh
```

### 4.3 拷贝到目标机

```bash
# 从本机(攻击者主机或跳板)把脚本传过去
scp xway_ir.sh root@<target>:/tmp/
ssh root@<target> "chmod +x /tmp/xway_ir.sh && bash /tmp/xway_ir.sh"
```

---

## 5. 使用方法

### 5.1 基础运行

```bash
sudo bash xway_ir.sh
```

> 推荐 `sudo`,因为模块 1(进程)和模块 10(SSH 公钥、`/etc/hosts`)需要 root 权限才能看全。

### 5.2 保留日志(推荐)

```bash
sudo bash xway_ir.sh 2>&1 | tee -a ir_report_$(hostname)_$(date +%Y%m%d_%H%M%S).log
```

> 这样屏幕能看到颜色输出,同时日志文件保留原始 ANSI 字符(后续用 `cat -v` 或 less -R 还原颜色)。

如果日志里**不想要 ANSI 颜色**,改成:

```bash
sudo bash xway_ir.sh 2>&1 | sed -r "s/\x1B\[[0-9;]*[A-Za-z]//g" > ir_report_$(hostname)_$(date +%Y%m%d_%H%M%S).log
```

### 5.3 在 Docker 容器中运行

```bash
docker exec -it <container> bash -c "wget -qO- https://raw.githubusercontent.com/A4n9g7e2l/Xway/main/xway_ir.sh | bash"
```

> 容器里没有 systemd,模块 3/12 会自动空过;模块 13 会提示"在容器内"。

### 5.4 离线环境(无外网)

```bash
# 在有网的机器上
wget https://raw.githubusercontent.com/A4n9g7e2l/Xway/main/xway_ir.sh

# 拷贝到离线机器后
sudo bash xway_ir.sh
```

> 脚本本身不联网,**完全离线**可跑。

### 5.5 最小权限运行(无 sudo)

```bash
bash xway_ir.sh
```

> 没有 root 时,模块 5(全盘 SUID 扫描)和模块 10(其他用户 home)会有大量权限拒绝错误,但**不影响主体功能**。

---

## 6. 排查项详解

### 模块 1/13 — 进程排查
- **检测项**:
  - 已知矿池进程名(`xmrig` `minerd` `cpuminer` `kinsing` `monero` `stratum` 等)
  - Web 服务进程(nginx/apache)派生 bash/sh/python — **RCE 特征**
  - `eval()` `exec()` `base64 -d` `wget http` `chmod +x` — 可疑执行
- **误报控制**:
  - 关键字 `grep -v grep` 排除自身
  - Web 进程派生 Shell 高优
- **风险等级**:挖矿 = 🔴 Critical,Web RCE = 🟠 Critical

### 模块 2/13 — 网络外联
- **检测项**:
  - 已知 C2/矿池端口(`4444` `5555` `6666` `1337` `8888` `31337` `1080/1081` `8443`)
  - 排除常见业务端口的 ESTAB 连接
- **工具依赖**:`ss -antp`(`netstat` 已不推荐)
- **误报控制**:只看 `ESTAB` 状态,排除 `:22 :80 :443 :53`

### 模块 3/13 — 启动项
- **检测项**:
  - 用户 crontab
  - `/etc/crontab` 中含 `wget` `curl` `base64` `/tmp/` — 高危
  - `systemctl list-unit-files --state=enabled` 名字含 `miner` `backdoor` 等
- **覆盖范围**:crontab + anacron + systemd + 部分 init.d

### 模块 4/13 — 内核 Rootkit
- **检测项**:
  - `lsmod` 中的 LKM Rootkit(`diamorphine` `reptile` `suterusu` `adore`)
  - `/etc/ld.so.preload` — **100% 失陷特征**
- **局限**:
  - 高级 Rootkit 会隐藏自己的模块,`lsmod` 看不到
  - **配合 chkrootkit / rkhunter / unhide** 才靠谱

### 模块 5/13 — SUID/SGID
- **检测项**:`find / -perm /4000 -mtime -30` — 30 天内新增的 SUID
- **误报控制**:只看 mtime,不看全盘(全盘太多)
- **常见正常 SUID**:`/usr/bin/passwd` `/usr/bin/sudo` `/usr/bin/mount` 等

### 模块 6/13 — 敏感文件
- **检测项**:`/etc` `/usr/local` `/opt` `/root` `/tmp` 下 7 天内修改的文件
- **误报控制**:排除 `.log` `.sock`
- **典型发现**:`/etc/passwd` `/etc/shadow` `/etc/sudoers` 被改

### 模块 7/13 — Webshell
- **检测项**:
  - 数字命名 PHP/JSP(`1.php` `9999.jsp` 等)
  - 一句话木马特征(`eval($_POST` `assert($_POST` `system($_POST`)
- **局限**:
  - 编码型 / 加密型 / 无特征马 — 查不到
  - **配合河马 / D盾 / 阿里伏羲 / 百度 WEBDIR+**

### 模块 8/13 — 挖矿特征
- **检测项**:
  - CPU > 30% 的进程(可能是挖矿)
  - 全盘搜含 `stratum` `xmrig` `pool.` `wallet` 的配置文件
- **配合**:wmic / perfmon / Prometheus 告警

### 模块 9/13 — 可疑文件位置
- **检测项**:
  - `/tmp` `/dev/shm` `/var/tmp` 下的可执行文件 — **攻陷后最爱落点**
  - 数字命名 `.so` / `.dll` — **银狐家族特征**
- **Linux 内存盘**:`/dev/shm` 是 tmpfs,**重启清空**但运行时不重启就一直在

### 模块 10/13 — 横向移动 ⭐核心模块
详见 [第 8 节](#8-横向移动分析)。

### 模块 11/13 — Java 内存马
- **检测项**:
  - 文件名含 `memshell` `agent` `evil` `hack` 的 JAR
  - Tomcat `webapps` 下 30 天内的 JSP
- **局限**:**纯内存马**(无文件)查不到,需要 `jcmd` `arthas` `java -jar` 工具抓运行时类

### 模块 12/13 — 提权痕迹
- **检测项**:`/etc/sudoers` 中非 root 全授权
- **配合**:`sudo -l` 输出、`/var/log/auth.log` 提权记录

### 模块 13/13 — 容器环境
- **检测项**:`/.dockerenv` / `cgroup` 中 `docker` 字符串
- **仅做标记**,不影响其他模块运行

---

## 7. 风险评分体系

每条发现都有 **分值** + **等级**,累加得到总分。

| 等级 | 颜色 | 典型分值 | 典型项 |
|---|---|---|---|
| 🔴 Critical | 红底白字 | 8–10 | 挖矿进程、LD_PRELOAD、SSH 公钥植入、横向移动 |
| 🟠 High | 黄字 | 7–9 | 异常连接、扫描工具、Web 进程派生 Shell |
| 🟡 Medium | 黄字 | 3–5 | Crontab 配置、SSH 失败登录、Sudoers 异常 |
| 🟢 Low | 绿字 | 1–3 | 7 天内改动的文件 |
| ⚪ Info | 青字 | 0 | 容器标记、最近登录 |

**总分阈值**:

| 总分 | 等级 | 结论 |
|---|---|---|
| ≥ 50 | 🔴 **CRITICAL — 高危失陷** | 立即隔离 + 全量取证 |
| 30–49 | 🟠 **HIGH — 中危失陷** | 24h 内处置 |
| 15–29 | 🟡 **MEDIUM — 可疑** | 72h 内复盘 |
| 5–14 | 🟢 **LOW — 低危** | 例行巡检级别 |
| < 5 | ⚪ **INFO** | 暂未发现失陷 |

> ⚠️ **分数是参考,不是判决**。**横向移动证据链** 的权重高于纯分数。

---

## 8. 横向移动分析

> 这是本脚本**最有价值**的部分。共采集 **9 类证据**,分 3 档判定。

### 8.1 9 类证据

| # | 证据 | 检测命令 |
|---|---|---|
| 1 | `authorized_keys` 含可疑公钥 | `cat /root\|/home/*/.ssh/authorized_keys` 过滤已知合法 key |
| 2 | `known_hosts` 列出连过的内网主机 | `cat /root/.ssh/known_hosts` |
| 3 | SSH 失败登录 ≥ 20 次(爆破痕迹) | `grep "Failed password" /var/log/auth.log` |
| 4 | SSH 成功登录(列时间和来源 IP) | `grep "Accepted" /var/log/auth.log` |
| 5 | `/etc/hosts` 含可疑 TLD 劫持 | `cat /etc/hosts \| grep ".tk/.top/.xyz/..."` |
| 6 | 横向扫描工具残留 | `find / -name "nmap/masscan/hydra/medusa"` 排除系统包 |
| 7 | SSH 隧道 / nc 反向进程运行中 | `ps \| grep "ssh -R\|nc -l\|socat"` |
| 8 | 异常账号(UID < 1000 但无家目录) | `awk '$3 < 1000 && $3 != 0' /etc/passwd` |
| 9 | 最近 20 条 SSH 登录(`last -i`) | `last -n 20 -i` |

### 8.2 三档判定

#### 情形 A:无证据(0 条)
```
✅ 未发现横向移动痕迹
检测项目:OK × 5
结论:这台主机 大概率是初始入侵点 或 孤立失陷端,
    尚未对其他内网主机发起攻击。
```

#### 情形 B:少量证据(1–2 条)
```
⚠️ 横向移动证据有限(N 条)
- 列出所有证据
结论:发现少量可疑痕迹,但不足以判断成熟横向移动。
建议:
  1. 拉取 auth.log / secure 完整记录
  2. 检查 /root/.bash_history 找命令轨迹
  3. 对同网段主机跑 SSH 登录日志比对
```

#### 情形 C:大量证据(≥ 3 条)
```
🔴 高度怀疑已发生横向移动(N 条证据)
证据链:[!] ... × N
横向目标(本机连过/被植入):→ 主机列表
结论:这台主机 已被攻击者用作跳板,已对内网其他主机发起攻击。

立即行动:
  1. 立即隔离本机(拔网线或 iptables -I INPUT 1 -j DROP)
  2. 拉内存 dump(avml / LiME),再磁盘镜像(dd)
  3. 对所有 authorized_keys 含公钥的主机全部排查
  4. 对 known_hosts 列表中的目标主机排查
  5. 对 SSH 失败登录源 IP 排查
  6. 全网段 SSH 公钥 / 计划任务 / crontab 批量审计
```

---

## 9. 已知限制

1. **`set +e` 不中断** — 任一命令失败不影响后续(这是为了最大化输出),但可能在某些环境下产生大量 permission denied。
2. **部分命令需要 root** — 模块 5(全盘 SUID)和模块 10(其他用户 home)需要 sudo,普通用户跑会缺数据。
3. **不替代专业工具** — 高级 Rootkit / 内存马 / 加密流量需要 chkrootkit / rkhunter / 河马 / D盾 / 流量分析设备。
4. **关键字检测有漏报** — 攻击者只要稍作变形(用 `ev al` / `ba se64 -d` 加空格)就能绕过。建议配合 yara + 行为检测。
5. **不具备修复能力** — 脚本只"看",不"动"。处置请人工执行。
6. **不修改任何文件** — 跑完除了可选的 tee 日志,不留下任何痕迹。

### 9.1 v1.0.1 修复的已知误报

| 误报 | 原因 | 修复 |
|---|---|---|
| `/etc/chrony/chrony.conf` 误判为挖矿配置 | grep 的 `pool\.` 关键词在 NTP 池域名 `pool.ntp.org` 上误报 | 改为只搜 `stratum+tcp / xmrig / c3pool` 等**矿池专用**关键词 |
| `/home/<USER>/.hermes/skills/` 误判为 Webshell | 蓝队/红队安全研究人员的资料库,本身就是合法 POC 资料 | 扫描时显式排除 `nuclei-templates` `.hermes/skills` `htb` `thm` `oscp` 等 |
| `/home/<USER>/WhatWeb-0.5.5/` 提示为可疑文件 | WhatWeb 是合法的 Web 指纹识别工具 | **不修复** — 仍提示,但脚本下方说明文字标注"在授权测试机器上为正常" |

---

## 10. 配合工具

| 工具 | 用途 | 链接 |
|---|---|---|
| **chkrootkit** | Rootkit 扫描 | http://www.chkrootkit.org/ |
| **rkhunter** | Rootkit + 后门扫描 | http://rkhunter.sourceforge.net/ |
| **ClamAV** | 恶意文件扫描 | https://www.clamav.net/ |
| **unhide** | 隐藏进程/端口发现 | http://www.unhide-forensics.info/ |
| **avml** | Linux 内存 dump(在线版) | https://github.com/microsoft/avml |
| **LiME** | Linux 内存 dump(内核模块) | https://github.com/504ensicsLabs/LiME |
| **dd / dc3dd** | 磁盘镜像 | (系统自带) |
| **volatility** | 内存取证分析 | https://www.volatilityfoundation.org/ |
| **河马 / D盾** | Webshell 扫描(在线) | (第三方) |

---

## 11. 应急响应 SOP

> 推荐的标准流程,与本工具结合使用。

```
┌────────────────────────────────────────────────────────────┐
│ 步骤 1:隔离                                                 │
│   拔网线 / iptables -I INPUT 1 -j DROP / 云上安全组断网        │
│   (注: 断网前先准备好取信用工具)                                │
├────────────────────────────────────────────────────────────┤
│ 步骤 2:取证 (主机仍在线)                                     │
│   · 内存: avml > mem.dump  或  insmod lime.ko               │
│   · 进程: ps auxwwf > proc.txt                               │
│   · 网络: ss -antp > net.txt; iptables-save > fw.txt        │
│   · 文件: tar czf etc.tgz /etc; tar czf var.tgz /var        │
├────────────────────────────────────────────────────────────┤
│ 步骤 3:排查 ← ← ← 本工具在这里                              │
│   sudo bash xway_ir.sh 2>&1 | tee ir.log                    │
├────────────────────────────────────────────────────────────┤
│ 步骤 4:评估 + 决策                                            │
│   · 看总分 + 横向证据 → 决定是否上溯/扩大范围                    │
│   · 通知相关方(法务、上级、监管?)                              │
├────────────────────────────────────────────────────────────┤
│ 步骤 5:修复                                                  │
│   · kill -9 恶意进程                                          │
│   · 清除 crontab / systemd 持久化                             │
│   · 删除 Webshell / 挖矿 binary                               │
│   · 改所有相关密码 + SSH key                                  │
│   · 必要时重装系统                                             │
├────────────────────────────────────────────────────────────┤
│ 步骤 6:加固 + 复盘                                             │
│   · 关闭密码登录,改公私钥                                     │
│   · 加 fail2ban / 异地登录告警                                │
│   · 写事件复盘报告(PDF/PPT 交给管理层)                         │
└────────────────────────────────────────────────────────────┘
```

---

## 12. 贡献与反馈

- **Issue**: https://github.com/A4n9g7e2l/Xway/issues
- **PR**: 欢迎!请保持 shellcheck 通过、函数化、不引入新依赖。
- **新检测规则建议**:在 Issue 里贴出"你想检测的 IOC 关键字 + 误报控制方法"。

---

## 13. 免责声明

⚠️ **本工具仅限用于已获授权的安全测试 / 自有主机应急响应 / 教育研究用途。**

- 未经授权对他人主机运行此工具,可能违反《网络安全法》《刑法》第 285/286 条等法律法规。
- 脚本**不做任何修改动作**,但**会读取大量敏感文件**(`/etc/shadow`、`authorized_keys`、日志等),请妥善保管运行产生的输出。
- 作者**不对使用本工具造成的任何直接或间接后果负责**。

---

## 14. 版权

```
MIT License

Copyright (c) 2026 A4n9g7e2l
```

详见 [LICENSE](LICENSE) 文件。

---

<p align="center">
  🛡️ <b>XWAY 蓝队</b> · 攻防不息,守护不止
</p>
