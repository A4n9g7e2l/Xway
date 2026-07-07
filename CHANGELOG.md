# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [v2.0] — 2026-07-07 — "GScan-Inspired Architecture"

### ⭐ Major Changes

#### 数据-逻辑分离 (Data-Logic Separation)
- 所有 IOC 数据从脚本中抽出到 `lib/` 目录
- `lib/iocs/` 下 4 个分类 IOC 文件 (miners / c2 / backdoors / rshell),~500 条精选
- `lib/rootkit_signatures.txt` 60+ 已知 Rootkit 文件/目录签名
- `lib/bad_lkm.txt` 80+ 已知恶意 LKM 模块名
- 用户**无需改脚本**即可扩展 IOC — 直接编辑文本文件即可
- `lib/iocs/LICENSE.notice` 保留 Maltrail MIT attribution

#### 攻击路径时间线 (Attack Path Timeline) — GScan 借鉴
- 新增末尾"攻击路径时间线"章节
- 把所有 CRIT/HIGH/MED 发现按 mtime 排序,叙事化输出
- 输出格式:[序号] [时间] [等级] [标题] → 文件路径 ↪ 处置建议
- **这是事故报告的"杀手锏"** — 直接复制到 IR 工单

#### JSON-lines 结构化日志
- 每次扫描同时输出 `${OUT_DIR}/xway_ir-<host>-<ts>.jsonl`
- 每条 finding 一行 JSON:`{"ts":"...","level":"...","module":"...","title":"...","file":"...","hint":"...","score":N}`
- 可用 `jq` 查询 / SIEM 接入 / ELK 摄取

### 🚀 New Checks (5 GScan-Inspired)

| # | 检查 | GScan 借鉴来源 |
|---|---|---|
| 4 | Rootkit 84 文件/目录签名扫描 | `Rootkit_Analysis.check_rootkit_rules` |
| 4 | `/proc/kallsyms` 内核符号比对 | `Rootkit_Analysis.check_rootkit_rules` |
| 4 | 已知恶意 LKM 模块名扫描 | `Rootkit_Analysis.check_bad_LKM` |
| 10 | SSH 爆破成功后入侵关联 (50+ 失败 + 1 成功) | `SSHAnalysis.attack_detect` |
| 14 | Shell 环境劫持 5 种 (LD_PRELOAD/LD_AOUT/LD_ELF/LD_LIBRARY_PATH/PROMPT_COMMAND) | `Backdoor_Analysis.check_tag` |
| 15 | `.bashrc` 命令别名劫持 (alias ps/netstat/...) | `Sys_Init.check_alias_conf` |
| 16 | `/usr/sbin/sshd` 非 ELF (SSH wrapper 后门) | `Backdoor_Analysis.check_SSHwrapper` |
| 16 | sshd 非标准端口监听 | `Backdoor_Analysis.check_SSH` |
| 17 | `/etc/shadow` / `/etc/passwd` 权限异常 | `User_Analysis.passwd_file_analysis` |
| 17 | 空密码账号 | `User_Analysis.check_empty` |
| 18 | `bash_history` 反 shell 模式扫描 | `History_Analysis.get_all_history` |

### 🧪 Tests & CI
- 新增 `bats/test_ioc_match.bats` (12 个测试,IOC 正/负样本)
- 新增 `bats/test_score_thresholds.bats` (9 个测试,评分边界 5/15/30/50)
- 新增 `bats/test_banner.bats` (20 个测试,18 模块 banner / 颜色变量 / 旧 bug 回归)
- 新增 `.github/workflows/ci.yml` (4 jobs: shellcheck / bats / python lint / bash syntax)

### 🛠️ Script Refactor
- 13 模块 → **18 模块**
- 全部统一走 `section_header "n" "title"` 函数,消除 13 处 banner 重复
- `log_finding` 统一函数,同时写 stdout + log + JSONL
- `--no-color` / `--out-dir` 新 CLI flags
- TTY 检测 — `[[ -t 1 ]]` 自动启用 ANSI,日志/管道自动关
- 修复 v1.x `${CYAN}` 拼写 bug (变量名是 `CYN`)
- 修复 v1.x `FINAL_COLOR` 半残 — 现 5 个风险等级全分支都设色

### 📊 IOC Data Sources
- 从 [Maltrail](https://github.com/stamparm/maltrail) (MIT) 精选 ~500 条高信号 IOC
- 4 个分类:挖矿 / C2 / 后门 / 反 shell
- 保留完整 Maltrail MIT attribution

### 📦 Stats
- 脚本:357 → 651 行 (+82%)
- 总仓库:30KB → ~70KB (+130%)
- 测试覆盖:0 → 41 个 bats 测试

### ❌ What was NOT ported
- YARA 扫描 (Bash 不友好,需 Python egg)
- 17mon IP 地理库 (二进制 2.8MB,Bash 难处理)
- MD5 二进制基线 (慢,有 chkrootkit 替代)
- 类/插件体系 (单文件 Bash 不需要)
- `--job` 自安装 cron (操作员反模式)
- 全量 74k Maltrail (精选 500 已够)

---

## [v1.0.1] — 2026-07-02

### Fixed
- 挖矿配置 grep 误报: 排除 `/etc/chrony/chrony.conf` 等 NTP 池配置
- Webshell 一句话 grep 误报: 排除安全研究人员资料库 (`nuclei-templates` / `.hermes/skills` / `htb` / `thm` / `oscp`)
- 挖矿配置扫描范围缩小到 `/tmp /var/tmp /opt /root /home`

---

## [v1.0.0] — 2026-07-02

### 🎉 Initial Release

- 13 个排查模块
- 风险评分体系 (5/15/30/50 四档)
- 横向移动证据链聚合 (9 类证据 / 3 档判定)
- 纯命令行 ANSI 颜色可视化
- 中文 README 详尽使用教程
- MIT 协议