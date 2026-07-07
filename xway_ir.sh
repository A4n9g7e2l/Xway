#!/bin/bash
# ============================================================
# xway_ir.sh v2.0 — Linux 失陷主机一键应急排查
#
# 架构借鉴:grayddq/GScan (MIT) — 数据-逻辑分离、IOC 外置、
#          JSON-lines 日志、攻击路径时间线
#
# 输出:
#   1. 彩色 stdout (操作员直接读)
#   2. ${REPORT_DIR}/xway_ir-<host>-<ts>.log  (含 ANSI,可 less -R)
#   3. ${REPORT_DIR}/xway_ir-<host>-<ts>.jsonl (结构化日志,可 jq / SIEM)
#
# 用法:
#   sudo bash xway_ir.sh                            # 全量扫描
#   sudo bash xway_ir.sh --no-color                 # 关颜色
#   sudo bash xway_ir.sh --out-dir /tmp/ir          # 指定输出目录
#
# ============================================================
set +e

# -------- 路径常量 --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
IOC_DIR="${LIB_DIR}/iocs"
OUT_DIR="${OUT_DIR:-/tmp}"

# -------- 颜色(ANSI) — 默认开启,可 --no-color 关 --------
if [[ -t 1 && -z "${NO_COLOR:-}" && "${1:-}" != "--no-color" ]]; then
    RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'
    BLU='\033[1;34m'; CYN='\033[1;36m'; NC='\033[0m'
    BRED='\033[41;97m'; BYEL='\033[43;30m'; BGRN='\033[42;30m'
    BBLU='\033[44;97m'; BGRAY='\033[100;97m'
else
    RED=''; YEL=''; GRN=''; BLU=''; CYN=''; NC=''
    BRED=''; BYEL=''; BGRN=''; BBLU=''; BGRAY=''
fi

# 解析 --no-color / --out-dir
[[ "${1:-}" == "--no-color" ]] && shift
[[ "${1:-}" == "--out-dir" && -n "${2:-}" ]] && OUT_DIR="$2" && shift 2

# -------- 主机信息 --------
HOST=$(hostname 2>/dev/null || echo unknown)
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo unknown)
KERNEL=$(uname -r 2>/dev/null || echo unknown)
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
TS_TAG=$(date '+%Y%m%d_%H%M%S')

# -------- 输出文件 --------
mkdir -p "$OUT_DIR"
REPORT_LOG="$OUT_DIR/xway_ir-${HOST}-${TS_TAG}.log"
REPORT_JSONL="$OUT_DIR/xway_ir-${HOST}-${TS_TAG}.jsonl"
: > "$REPORT_LOG"
: > "$REPORT_JSONL"

# -------- 全局状态 --------
TOTAL_SCORE=0
declare -a FINDINGS          # "ts|level|module|title|file|hint"  — 攻击时间线源
declare -a LATERAL_EVIDENCE  # 横向移动证据
declare -a LATERAL_TARGETS   # 横向目标

# -------- log_finding: 统一写入 stdout + log + jsonl --------
# 用法: log_finding <level> <module> <title> [file] [hint]
# level: CRIT / HIGH / MED / LOW / INFO
log_finding() {
    local level="$1" mod="$2" title="$3" file="${4:-}" hint="${5:-}"
    local ts; ts=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')
    local color

    # 评分
    case "$level" in
        CRIT) score=10; color="$RED" ;;
        HIGH) score=8;  color="$YEL" ;;
        MED)  score=5;  color="$YEL" ;;
        LOW)  score=3;  color="$GRN" ;;
        INFO) score=0;  color="$CYN" ;;
        *)    score=1;  color="$NC" ;;
    esac
    TOTAL_SCORE=$((TOTAL_SCORE + score))

    # 屏幕输出
    local tag="[$level]"
    case "$level" in
        CRIT) tag="[!] CRIT" ;;
        HIGH) tag="[!] HIGH" ;;
        MED)  tag="[i] MED " ;;
        LOW)  tag="[i] LOW " ;;
        INFO) tag="[i] INFO" ;;
    esac
    printf '%b  %b%s%b %s\n' "$color" "$color" "$tag" "$NC" "$title" >&2
    [[ -n "$file" ]] && printf '         %b→%b %s\n' "$CYN" "$NC" "$file" >&2
    [[ -n "$hint" ]] && printf '         %b↪%b %s\n' "$CYN" "$NC" "$hint" >&2

    # 写入 log(全 ANSI 字符,可用 less -R 还原)
    {
        printf '%s  %s  %s\n' "$tag" "$title" "$file"
        [[ -n "$hint" ]] && printf '         ↪ %s\n' "$hint"
    } >> "$REPORT_LOG"

    # 写入 JSONL(机器可读)
    # 注意:JSON 字段需要 escape 双引号
    local title_esc="${title//\"/\\\"}"
    local file_esc="${file//\"/\\\"}"
    local hint_esc="${hint//\"/\\\"}"
    printf '{"ts":"%s","level":"%s","module":"%s","title":"%s","file":"%s","hint":"%s","score":%d}\n' \
        "$ts" "$level" "$mod" "$title_esc" "$file_esc" "$hint_esc" "$score" >> "$REPORT_JSONL"

    # 加入时间线池(只有 CRIT/HIGH/MED)
    if [[ "$level" == "CRIT" || "$level" == "HIGH" || "$level" == "MED" ]]; then
        local mtime=""
        [[ -n "$file" && -e "$file" ]] && mtime=$(stat -c %y -- "$file" 2>/dev/null)
        FINDINGS+=("${mtime:-$ts}|$level|$mod|$title|$file|$hint")
    fi
}

# -------- section_header: 统一 18 个模块 banner --------
section_header() {
    local n="$1" title="$2"
    echo -e "\n${BLU}[$n/18]${NC} ${YEL}${title}${NC}" >&2
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    {
        printf '\n[%s/18] %s\n' "$n" "$title"
        printf '──────────────────────────────────────────────────────────────────────\n'
    } >> "$REPORT_LOG"
}

# -------- bar: 通用分隔线 --------
bar() {
    local ch="${1:-─}" n="${2:-70}"
    local s=""
    for ((i=0; i<n; i++)); do s+="$ch"; done
    printf '%s\n' "$s"
}

# ============================================================
# 顶部 Banner
# ============================================================
clear 2>/dev/null
cat <<EOF >&2
${RED}╔══════════════════════════════════════════════════════════════════╗${NC}
${RED}║${NC}        ${RED}🛡️  XWAY 蓝队应急响应 — Linux 失陷主机排查 v2.0${NC}             ${RED}║${NC}
${RED}╚══════════════════════════════════════════════════════════════════╝${NC}
EOF
echo -e "  ${CYN}主机:${NC} ${YEL}$HOST${NC} ${CYN}($IP)${NC}    ${CYN}内核:${NC} ${YEL}$KERNEL${NC}" >&2
echo -e "  ${CYN}扫描时间:${NC} ${YEL}$SCAN_TIME${NC}" >&2
echo -e "  ${CYN}报告输出:${NC} ${YEL}$REPORT_LOG${NC}" >&2
echo -e "  ${CYN}结构化日志:${NC} ${YEL}$REPORT_JSONL${NC}" >&2
bar "─" 70 >&2
{
    printf '╔══════════════════════════════════════════════════════════════════╗\n'
    printf '║   XWAY 蓝队应急响应 — Linux 失陷主机排查 v2.0                      ║\n'
    printf '╚══════════════════════════════════════════════════════════════════╝\n'
    printf '主机: %s (%s)    内核: %s\n' "$HOST" "$IP" "$KERNEL"
    printf '扫描时间: %s\n' "$SCAN_TIME"
} >> "$REPORT_LOG"

# ============================================================
# 检查 1/18 — 进程排查
# ============================================================
section_header "1" "排查可疑进程..."
SUSP_PROCS=$(ps auxww 2>/dev/null | grep -iE "xmrig|minerd|cpuminer|kinsing|ddg|xor|monero|minergate|stratum|hashvault|nicehash|ksoftirdfs|c3pool|cryptonight" | grep -v grep | head -5)
[[ -n "$SUSP_PROCS" ]] && log_finding "CRIT" "process" "挖矿/僵尸进程" "" "kill -9 <PID>;ps auxww复查"

SUSP_PARENT=$(ps auxww 2>/dev/null | awk '$11 ~ /(bash|sh|python|perl|php)$/ {print}' | grep -E "www-data|apache|nobody|nginx|httpd|mysql" | head -3)
[[ -n "$SUSP_PARENT" ]] && log_finding "CRIT" "process" "Web 进程派生 Shell (RCE)" "" "查 Web 访问日志定位漏洞点"

EVAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "eval\(|exec\(|base64 -d|wget http|curl http|chmod \+x" | grep -v grep | head -3)
[[ -n "$EVAL_PROCS" ]] && log_finding "HIGH" "process" "可疑执行命令" "" "strings /proc/<PID>/exe 看二进制内容"

# ============================================================
# 检查 2/18 — 网络外联
# ============================================================
section_header "2" "排查网络外联..."
EXT_CONN=$(ss -antp 2>/dev/null | grep -v "LISTEN" | grep -E ":4444|:5555|:6666|:1337|:8888|:31337|:1080|:1081|:8443" | head -5)
[[ -n "$EXT_CONN" ]] && log_finding "HIGH" "network" "可疑端口外联" "" "ss -antp 复查来源 PID"

ESTAB=$(ss -antp 2>/dev/null | awk '$1=="ESTAB" {print}' | grep -v ":22\|:80\|:443\|:53" | head -10)
[[ -n "$ESTAB" ]] && log_finding "HIGH" "network" "异常已建立连接" "" "lsof -i 检查进程文件"

# ============================================================
# 检查 3/18 — 启动项 / 计划任务
# ============================================================
section_header "3" "排查启动项/计划任务..."
CRON=$(crontab -l 2>/dev/null | grep -vE "^#|^$" | head -5)
[[ -n "$CRON" ]] && log_finding "MED" "persistence" "Crontab 配置" "" "crontab -l 复查每条含义"

SUSP_CRON=$(cat /etc/crontab 2>/dev/null | grep -vE "^#|^$" | grep -iE "wget|curl|base64|nc |/tmp/" | head -3)
[[ -n "$SUSP_CRON" ]] && log_finding "CRIT" "persistence" "可疑系统 crontab" "" "cat /etc/crontab 完整审计"

SUSP_SVC=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -iE "miner|backdoor|update|cron|shell" | head -5)
[[ -n "$SUSP_SVC" ]] && log_finding "HIGH" "persistence" "可疑 systemd 服务" "" "systemctl status <name>"

# ============================================================
# 检查 4/18 — 内核 Rootkit (v2.0: 84 签名 + kallsyms)
# ============================================================
section_header "4" "检测内核 Rootkit..."
MODULES=$(lsmod 2>/dev/null | grep -iE "diamorphine|reptile|suterusu|adore" | head -3)
[[ -n "$MODULES" ]] && log_finding "CRIT" "rootkit" "Rootkit 内核模块" "" "lsmod 完整列表 + rmmod"

LD_PRELOAD=$(cat /etc/ld.so.preload 2>/dev/null)
[[ -n "$LD_PRELOAD" ]] && log_finding "CRIT" "rootkit" "LD_PRELOAD 劫持 (/etc/ld.so.preload)" "" "echo '' > /etc/ld.so.preload"

# v2.0 新增 — 84 个 Rootkit 文件/目录签名扫描
if [[ -f "$LIB_DIR/rootkit_signatures.txt" ]]; then
    RK_HITS=""
    while IFS= read -r p; do
        [[ -z "$p" || "$p" =~ ^[[:space:]]*# ]] && continue
        [[ -e "$p" ]] && RK_HITS+="$p"$'\n'
    done < "$LIB_DIR/rootkit_signatures.txt"
    if [[ -n "$RK_HITS" ]]; then
        log_finding "HIGH" "rootkit" "已知 Rootkit 文件/目录签名 (${#RK_HITS} 条命中)" "$(echo "$RK_HITS" | head -1)" "chkrootkit / rkhunter 复核"
    fi
fi

# v2.0 新增 — /proc/kallsyms 内核符号比对
if [[ -r /proc/kallsyms ]]; then
    KSYMS=$(awk '{print $3}' /proc/kallsyms 2>/dev/null | grep -wE "diamorphine|reptile|suterusu|adore|hide_module|unhide_module|sys_getdents64" | head -5)
    [[ -n "$KSYMS" ]] && log_finding "CRIT" "rootkit" "Rootkit 内核符号残留" "" "模块已卸载但符号未清"
fi

# v2.0 新增 — 恶意 LKM 模块名扫描
if [[ -f "$LIB_DIR/bad_lkm.txt" ]]; then
    LKM_BAD_HITS=$(find /lib/modules -type f \( -name '*.ko' -o -name '*.ko.xz' \) 2>/dev/null \
        | while read -r f; do
            bn=$(basename "$f" .xz)
            bn="${bn%.ko}"
            grep -qx "$bn" "$LIB_DIR/bad_lkm.txt" 2>/dev/null && echo "$f"
        done | head -3)
    [[ -n "$LKM_BAD_HITS" ]] && log_finding "CRIT" "rootkit" "已知恶意 LKM 模块" "$(echo "$LKM_BAD_HITS" | head -1)" "rmmod + 删除 .ko"
fi

# ============================================================
# 检查 5/18 — SUID/SGID
# ============================================================
section_header "5" "排查 SUID/SGID..."
SUID_RECENT=$(find / -perm /4000 -mtime -30 -type f 2>/dev/null | head -5)
[[ -n "$SUID_RECENT" ]] && log_finding "CRIT" "suid" "30 天内新增 SUID" "$(echo "$SUID_RECENT" | head -1)" "chmod u-s <path>"

# ============================================================
# 检查 6/18 — 敏感文件变化
# ============================================================
section_header "6" "排查敏感文件变化..."
RECENT=$(find /etc /usr/local /opt /root /tmp -mtime -7 -type f 2>/dev/null | grep -vE "/proc|/sys|\.log$|\.sock$" | head -10)
[[ -n "$RECENT" ]] && log_finding "LOW" "file" "7天内修改文件" "$(echo "$RECENT" | head -1)" "diff 与备份对比"

# ============================================================
# 检查 7/18 — Webshell
# ============================================================
section_header "7" "排查 Webshell..."
WS=$(find /var/www /usr/share/nginx /home /root -type f \( -name "*.php" -o -name "*.jsp" \) 2>/dev/null | grep -iE "[0-9]{1,4}\.(php|jsp)$|[a-z]{1,3}[0-9]{4,}\.(php|jsp)$" | head -5)
[[ -n "$WS" ]] && log_finding "CRIT" "webshell" "数字命名 PHP/JSP" "$(echo "$WS" | head -1)" "cat 看内容 + 删"

# v1.0.1 修复: 排除安全研究人员的资料库
WSHELL=$(grep -rE "eval\(\\\$_POST|eval\(\\\$_GET|assert\(\\\$_POST|system\(\\\$_POST|passthru\(\\\$_POST" /var/www /root 2>/dev/null \
    | grep -viE "/(nuclei-templates|nuclei-templates-2)\.|\.hermes/skills/|/training/ctf/|/htb/|/thm/|/oscp/" \
    | head -5)
[[ -n "$WSHELL" ]] && log_finding "CRIT" "webshell" "PHP 一句话后门" "" "cat 文件内容定位攻击者"

# v2.0 新增 — 用 lib/iocs/backdoors.txt 扫常见 webshell 文件名
if [[ -f "$IOC_DIR/backdoors.txt" ]]; then
    WS_KNOWN=$(find /var/www /usr/share/nginx /home /root -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) 2>/dev/null \
        | grep -F -f "$IOC_DIR/backdoors.txt" | head -5)
    [[ -n "$WS_KNOWN" ]] && log_finding "CRIT" "webshell" "已知 Webshell 文件名" "$(echo "$WS_KNOWN" | head -1)" "查威胁情报家族 + 删"
fi

# ============================================================
# 检查 8/18 — 挖矿特征 (v2.0: 用 lib/iocs/miners.txt)
# ============================================================
section_header "8" "排查挖矿特征..."
HIGH_CPU=$(ps auxww 2>/dev/null | sort -k3 -nr | head -5 | awk '$3+0 > 30 {print}')
[[ -n "$HIGH_CPU" ]] && log_finding "HIGH" "miner" "高 CPU 进程(挖矿)" "$(echo "$HIGH_CPU" | head -1)" "kill + strings"

# v1.0.1 修复: 排除 NTP 池 + 用 lib/iocs/miners.txt 精确匹配
MINER_CFG=$(find /tmp /var/tmp /opt /root /home -type f \( -name "config.json" -o -name "*.conf" -o -name "config.txt" -o -name "pools.txt" \) 2>/dev/null \
    | xargs grep -lE "stratum\+tcp|xmrig|c3pool|moneroocean|nicehash|hashvault|miningrigrentals|cryptonight" 2>/dev/null \
    | head -3)
[[ -n "$MINER_CFG" ]] && log_finding "CRIT" "miner" "挖矿配置文件" "$(echo "$MINER_CFG" | head -1)" "rm + 找落点进程"

# v2.0 新增 — Maltrail 精选 miner IOC 扫描
if [[ -f "$IOC_DIR/miners.txt" ]]; then
    MINER_IO=$(find /tmp /var/tmp /opt /root /home -type f 2>/dev/null \
        | head -5000 \
        | xargs grep -lE "$(grep -vE '^\s*$|^\s*#' "$IOC_DIR/miners.txt" | head -50 | tr '\n' '|' | sed 's/|$//')" 2>/dev/null \
        | head -3)
    [[ -n "$MINER_IO" ]] && log_finding "HIGH" "miner" "Maltrail 矿池/IOC 命中" "$(echo "$MINER_IO" | head -1)" "溯源 + 删"
fi

# ============================================================
# 检查 9/18 — 可疑文件位置
# ============================================================
section_header "9" "排查可疑文件位置..."
TMP_EXEC=$(find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null | head -10)
[[ -n "$TMP_EXEC" ]] && log_finding "HIGH" "file" "临时目录可执行文件" "$(echo "$TMP_EXEC" | head -1)" "strings + chmod -x"

DIGIT_LIB=$(find / -type f \( -name "[0-9][0-9].so" -o -name "[0-9][0-9].dll" \) 2>/dev/null | head -5)
[[ -n "$DIGIT_LIB" ]] && log_finding "CRIT" "file" "数字命名 so/dll (银狐)" "$(echo "$DIGIT_LIB" | head -1)" "溯源家族 + 删"

# ============================================================
# 检查 10/18 — 横向移动 (核心)
# ============================================================
section_header "10" "排查横向移动(关键)..."

# 10.1 SSH 公钥
for home in /root /home/*; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        KEYS=$(cat "$home/.ssh/authorized_keys" 2>/dev/null)
        SUSP=$(echo "$KEYS" | grep -vE "^#|^$|@$|company|backup" | head -3)
        if [ -n "$SUSP" ]; then
            LATERAL_EVIDENCE+=("[!] authorized_keys 含可疑公钥 ($home)")
            LATERAL_TARGETS+=("$home")
            log_finding "CRIT" "lateral" "SSH 公钥植入 ($home)" "$home/.ssh/authorized_keys" "查公钥 fingerprint + 删"
        fi
    fi
done

# 10.2 known_hosts
KNOWN=$(cat /root/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | head -10)
[[ -n "$KNOWN" ]] && LATERAL_TARGETS+=("$KNOWN")

# 10.3 SSH 失败登录
SSH_BRUTE=""
for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [ -f "$f" ] && SSH_BRUTE=$(grep -E "Failed password|Invalid user|authentication failure" "$f" 2>/dev/null | tail -50)
done
SSH_FAILED_COUNT=$(echo "$SSH_BRUTE" | grep -c . 2>/dev/null || echo 0)
if [ "$SSH_FAILED_COUNT" -gt 0 ]; then
    LATERAL_EVIDENCE+=("[!] SSH 失败登录 $SSH_FAILED_COUNT 次")
    SCORE=3; [[ "$SSH_FAILED_COUNT" -gt 20 ]] && SCORE=7
    log_finding "MED" "lateral" "SSH 失败登录 ($SSH_FAILED_COUNT 次)" "" "封禁爆破源 IP"
fi

# 10.4 SSH 成功登录
SSH_SUCCESS=""
for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && SSH_SUCCESS=$(grep -E "Accepted password|Accepted publickey" "$f" 2>/dev/null | tail -20)
done
[[ -n "$SSH_SUCCESS" ]] && log_finding "MED" "lateral" "SSH 成功登录 (近 20 条)" "" "复查每条来源 IP 是否可信"

# v2.0 新增 10.5 — SSH 爆破成功后入侵关联 (GScan 借鉴)
if [[ -n "$SSH_BRUTE" && -n "$SSH_SUCCESS" ]]; then
    BRUTE_IPS=$(echo "$SSH_BRUTE" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | awk '$1>=20 {print $2}')
    for ip in $BRUTE_IPS; do
        if echo "$SSH_SUCCESS" | grep -q "$ip"; then
            LATERAL_EVIDENCE+=("[!] SSH 爆破成功后入侵关联: $ip (50+ 失败 + 1 成功)")
            log_finding "CRIT" "lateral" "SSH 爆破成功后入侵 ($ip)" "" "立即封禁 IP + 改密码"
            break  # 只报最严重的一条
        fi
    done
fi

# 10.6 /etc/hosts 篡改
HOSTS=$(cat /etc/hosts 2>/dev/null | grep -vE "^#|^$|localhost|ip6-")
SUSP_HOSTS=$(echo "$HOSTS" | grep -iE "\.(tk|top|xyz|gq|cyou|onion)")
if [ -n "$SUSP_HOSTS" ]; then
    LATERAL_EVIDENCE+=("[!] /etc/hosts 含可疑域名劫持")
    log_finding "HIGH" "lateral" "/etc/hosts 可疑劫持" "/etc/hosts" "vi /etc/hosts 复核"
fi

# 10.7 横向扫描工具
SCAN_TOOLS=$(find / -type f \( -name "nmap" -o -name "masscan" -o -name "hydra" -o -name "medusa" \) 2>/dev/null | grep -vE "/usr/bin|/usr/share|/snap" | head -3)
[[ -n "$SCAN_TOOLS" ]] && {
    LATERAL_EVIDENCE+=("[!] 发现横向扫描工具: $SCAN_TOOLS")
    log_finding "HIGH" "lateral" "横向扫描工具" "$(echo "$SCAN_TOOLS" | head -1)" "溯源使用记录"
}

# 10.8 横向移动进程
LATERAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "ssh -R|ssh -D|ssh -L|nc -l|socat.*exec" | grep -v grep | head -3)
[[ -n "$LATERAL_PROCS" ]] && {
    LATERAL_EVIDENCE+=("[!] 横向移动进程运行中")
    log_finding "CRIT" "lateral" "SSH 隧道 / nc 反向" "" "kill + 查 .bash_history"
}

# 10.9 异常账号
WEIRD=$(awk -F: '$3 < 1000 && $3 != 0 {print}' /etc/passwd 2>/dev/null)
[[ -n "$WEIRD" ]] && {
    LATERAL_EVIDENCE+=("[!] 异常 UID < 1000 账号: $(echo "$WEIRD" | wc -l) 个")
    log_finding "MED" "lateral" "异常账号 (UID<1000)" "" "查可疑 UID 是否有家目录"
}

# 10.10 最近 SSH 登录 (信息)
LAST=$(last -n 20 -i 2>/dev/null | head -20)
[[ -n "$LAST" ]] && printf '%b         [i] 最近 SSH 登录:%b\n' "$CYN" "$NC" "$LAST" >&2

# ============================================================
# 检查 11/18 — Java 内存马
# ============================================================
section_header "11" "排查 Java 内存马..."
SUSP_JAR=$(find / -name "*.jar" -mtime -30 2>/dev/null | grep -iE "memshell|agent|evil|hack" | head -3)
[[ -n "$SUSP_JAR" ]] && log_finding "CRIT" "java" "可疑 Java JAR (内存马)" "$(echo "$SUSP_JAR" | head -1)" "arthas 抓运行时类"

TOMCAT_WEB=$(find / -path "*/webapps/*" -name "*.jsp" -mtime -30 2>/dev/null | head -3)
[[ -n "$TOMCAT_WEB" ]] && log_finding "MED" "java" "Tomcat 近期 JSP" "$(echo "$TOMCAT_WEB" | head -1)" "cat + 删"

# ============================================================
# 检查 12/18 — 提权痕迹
# ============================================================
section_header "12" "排查提权痕迹..."
SUDOERS=$(grep -vE "^#|^$|root\s+ALL" /etc/sudoers 2>/dev/null | head -5)
[[ -n "$SUDOERS" ]] && log_finding "MED" "privesc" "Sudoers 异常配置" "/etc/sudoers" "visudo 复核"

# ============================================================
# 检查 13/18 — 容器环境
# ============================================================
section_header "13" "容器环境检测..."
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    log_finding "INFO" "container" "当前在 Docker 容器内" "" ""
fi

# ============================================================
# 检查 14/18 — Shell 环境劫持 (v2.0: 5 种劫持)
# ============================================================
section_header "14" "排查 Shell 环境劫持..."
ENV_TAGS="LD_PRELOAD LD_AOUT_PRELOAD LD_ELF_PRELOAD LD_LIBRARY_PATH PROMPT_COMMAND"
for tag in $ENV_TAGS; do
    HIT=$(grep -rhE "^[^#]*export[[:space:]]+${tag}=" /root/.bashrc /root/.bash_profile /etc/bashrc /etc/profile /etc/profile.d/ /home/*/.bashrc /home/*/.bash_profile 2>/dev/null \
        | grep -v "^#" | head -3)
    if [[ -n "$HIT" ]]; then
        log_finding "CRIT" "env-hijack" "Shell 环境劫持 ($tag)" "" "vi .bashrc 删 export $tag=..."
    fi
done

# ============================================================
# 检查 15/18 — Alias 劫持 (v2.0: GScan 借鉴)
# ============================================================
section_header "15" "排查命令别名劫持..."
SENSITIVE_ALIAS="ps|netstat|strings|find|echo|iptables|lastlog|who|ifconfig|ssh|lsof|ls|cat"
ALIAS_HITS=$(grep -rhE "^[[:space:]]*alias[[:space:]]+(${SENSITIVE_ALIAS})=" /root/.bashrc /root/.bash_profile /etc/bashrc /etc/profile /home/*/.bashrc 2>/dev/null \
    | grep -v "^#" | head -5)
if [[ -n "$ALIAS_HITS" ]]; then
    log_finding "CRIT" "env-hijack" "命令别名劫持 (alias ps/netstat/...)" "" "vi .bashrc 删可疑 alias"
fi

# ============================================================
# 检查 16/18 — SSH wrapper / 替代 sshd (v2.0)
# ============================================================
section_header "16" "排查 SSH 二进制完整性..."
if [ -f /usr/sbin/sshd ]; then
    FILE_TYPE=$(file /usr/sbin/sshd 2>/dev/null)
    if ! echo "$FILE_TYPE" | grep -qE "ELF|executable"; then
        log_finding "CRIT" "backdoor" "sshd 非 ELF (可能 SSH wrapper 后门)" "/usr/sbin/sshd" "用 dpkg -V 或 rpm -V 校验"
    fi
fi
# 非标准端口的 sshd
ALT_SSHD=$(ss -ntlp 2>/dev/null | grep sshd | grep -v ":22[[:space:]]" | head -3)
[[ -n "$ALT_SSHD" ]] && log_finding "HIGH" "backdoor" "sshd 监听非标准端口" "" "vi /etc/ssh/sshd_config"

# ============================================================
# 检查 17/18 — /etc/passwd + /etc/shadow 权限 (v2.0)
# ============================================================
section_header "17" "排查账号文件权限..."
SHADOW_PERM=$(stat -c %a /etc/shadow 2>/dev/null)
PASSWD_PERM=$(stat -c %a /etc/passwd 2>/dev/null)
[[ "$SHADOW_PERM" != "0" && -n "$SHADOW_PERM" ]] && log_finding "HIGH" "compliance" "/etc/shadow 权限异常 ($SHADOW_PERM)" "/etc/shadow" "chmod 000 /etc/shadow"
[[ "$PASSWD_PERM" != "644" && -n "$PASSWD_PERM" ]] && log_finding "MED" "compliance" "/etc/passwd 权限异常 ($PASSWD_PERM)" "/etc/passwd" "chmod 644 /etc/passwd"

# 空密码账号
EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") && $1 != "root" && $1 != "sync" && $1 != "halt" && $1 != "shutdown" {print $1}' /etc/passwd 2>/dev/null | head -5)
[[ -n "$EMPTY_PW" ]] && log_finding "HIGH" "compliance" "空密码账号" "/etc/passwd" "passwd <user> 设密"

# ============================================================
# 检查 18/18 — Bash History 反 shell 扫描 (v2.0)
# ============================================================
section_header "18" "排查 bash_history 反 shell..."
HIST_HITS=""
for h in /root/.bash_history /home/*/.bash_history; do
    [ -f "$h" ] || continue
    if [[ -f "$IOC_DIR/rshell.txt" ]]; then
        H=$(grep -nE "$(grep -vE '^\s*$|^\s*#' "$IOC_DIR/rshell.txt" | head -20 | tr '\n' '|' | sed 's/|$//')" "$h" 2>/dev/null | head -3)
        [[ -n "$H" ]] && HIST_HITS+="${h}: ${H}"$'\n'
    fi
done
[[ -n "$HIST_HITS" ]] && log_finding "CRIT" "history" "bash_history 含反 shell 命令" "" "cat .bash_history 完整审计"

# ============================================================
# 综合结论
# ============================================================
echo "" >&2
bar "═" 70 >&2
printf '%b                📊 综合分析结论%b\n' "$RED" "$NC" >&2
bar "═" 70 >&2

if [ $TOTAL_SCORE -ge 50 ]; then
    FINAL="🔴 CRITICAL — 高危失陷"; FINAL_COLOR="$BRED"
elif [ $TOTAL_SCORE -ge 30 ]; then
    FINAL="🟠 HIGH — 中危失陷"; FINAL_COLOR="$BYEL"
elif [ $TOTAL_SCORE -ge 15 ]; then
    FINAL="🟡 MEDIUM — 可疑"; FINAL_COLOR="$YEL"
elif [ $TOTAL_SCORE -ge 5 ]; then
    FINAL="🟢 LOW — 低危"; FINAL_COLOR="$GRN"
else
    FINAL="⚪ INFO — 暂未发现失陷"; FINAL_COLOR="$CYN"
fi

printf '%b\n' "" >&2
printf '  主机:        %b%s%b %b(%s)%b\n' "$YEL" "$HOST" "$NC" "$CYN" "$IP" "$NC" >&2
printf '  风险评分:    %b%s%b 分\n' "$RED" "$TOTAL_SCORE" "$NC" >&2
printf '  风险等级:    %b%s%b\n' "$FINAL_COLOR" "$FINAL" "$NC" >&2
printf '  发现数量:    %b%s%b 条\n' "$YEL" "${#FINDINGS[@]}" "$NC" >&2
printf '  JSONL 日志:  %b%s%b\n' "$CYN" "$REPORT_JSONL" "$NC" >&2

{
    printf '\n风险评分: %d 分\n' "$TOTAL_SCORE"
    printf '风险等级: %s\n' "$FINAL"
    printf '发现数量: %d 条\n' "${#FINDINGS[@]}"
    printf 'JSONL 日志: %s\n' "$REPORT_JSONL"
} >> "$REPORT_LOG"

# ============================================================
# 横向移动结论
# ============================================================
EVIDENCE_COUNT=${#LATERAL_EVIDENCE[@]}
echo "" >&2
bar "─" 70 >&2
printf '%b            🎯 横向移动分析结论(必读)%b\n' "$RED" "$NC" >&2
bar "─" 70 >&2

if [ $EVIDENCE_COUNT -eq 0 ]; then
    printf '  %b✅ 未发现横向移动痕迹%b\n' "$GRN" "$NC" >&2
    echo "" >&2
    printf '  检测项目:\n' >&2
    printf '    %b[OK]%b authorized_keys 干净\n' "$GRN" "$NC" >&2
    printf '    %b[OK]%b SSH 失败登录 < 20 次(无爆破)\n' "$GRN" "$NC" >&2
    printf '    %b[OK]%b /etc/hosts 无劫持\n' "$GRN" "$NC" >&2
    printf '    %b[OK]%b 无横向扫描工具残留\n' "$GRN" "$NC" >&2
    printf '    %b[OK]%b 无 SSH 隧道/nc 反向进程\n' "$GRN" "$NC" >&2
    echo "" >&2
    printf '  %b结论:%b 这台主机 %b大概率是初始入侵点%b 或 %b孤立失陷端%b,\n' "$YEL" "$NC" "$RED" "$NC" "$RED" "$NC" >&2
    printf '        尚未对其他内网主机发起攻击。\n' >&2
elif [ $EVIDENCE_COUNT -le 2 ]; then
    printf '  %b⚠️  横向移动证据有限(%d 条)%b\n' "$YEL" "$EVIDENCE_COUNT" "$NC" >&2
    echo "" >&2
    for ev in "${LATERAL_EVIDENCE[@]}"; do
        printf '    %b%s%b\n' "$YEL" "$ev" "$NC" >&2
    done
    echo "" >&2
    printf '  %b结论:%b 发现少量可疑痕迹,但不足以判断成熟横向移动。\n' "$YEL" "$NC" >&2
    printf '  %b建议:%b\n' "$YEL" "$NC" >&2
    printf '    1. 拉取 auth.log / secure 完整记录\n' >&2
    printf '    2. 检查 /root/.bash_history 找命令轨迹\n' >&2
    printf '    3. 对同网段主机跑 SSH 登录日志比对\n' >&2
else
    printf '  %b🔴 高度怀疑已发生横向移动(%d 条证据)%b\n' "$RED" "$EVIDENCE_COUNT" "$NC" >&2
    echo "" >&2
    printf '  %b证据链:%b\n' "$RED" "$NC" >&2
    for ev in "${LATERAL_EVIDENCE[@]}"; do
        printf '    %b%s%b\n' "$RED" "$ev" "$NC" >&2
    done
    echo "" >&2
    if [ ${#LATERAL_TARGETS[@]} -gt 0 ]; then
        printf '  %b横向目标(本机连过/被植入):%b\n' "$RED" "$NC" >&2
        for t in "${LATERAL_TARGETS[@]}"; do
            printf '    %b→ %s%b\n' "$RED" "$t" "$NC" >&2
        done
        echo "" >&2
    fi
    printf '  %b结论:%b 这台主机 %b已被攻击者用作跳板%b%b,已对内网其他主机发起攻击。%b\n' "$RED" "$NC" "$BRED" "$NC" "$RED" "$NC" >&2
    echo "" >&2
    printf '  %b立即行动:%b\n' "$RED" "$NC" >&2
    printf '    %b1.%b 立即隔离本机(拔网线或 iptables -I INPUT 1 -j DROP)\n' "$RED" "$NC" >&2
    printf '    %b2.%b 拉内存 dump(avml / LiME),再磁盘镜像(dd)\n' "$RED" "$NC" >&2
    printf '    %b3.%b 对所有 authorized_keys 含公钥的主机全部排查\n' "$RED" "$NC" >&2
    printf '    %b4.%b 对 known_hosts 列表中的目标主机排查\n' "$RED" "$NC" >&2
    printf '    %b5.%b 对 SSH 失败登录源 IP 排查\n' "$RED" "$NC" >&2
    printf '    %b6.%b 全网段 SSH 公钥 / 计划任务 / crontab 批量审计\n' "$RED" "$NC" >&2
fi

# ============================================================
# v2.0 新增 — 攻击路径时间线 (GScan 借鉴)
# ============================================================
echo "" >&2
bar "═" 70 >&2
printf '%b          🛡️  攻击路径时间线 (v2.0 New) %b\n' "$RED" "$NC" >&2
bar "═" 70 >&2
echo "" >&2

if [ ${#FINDINGS[@]} -eq 0 ]; then
    printf '  %b✅ 无 CRIT/HIGH/MED 发现,无可构建时间线%b\n' "$GRN" "$NC" >&2
else
    # 按 mtime 排序,有 mtime 的优先
    printf '%b  发现 %d 条事件,按时间排序:%b\n\n' "$YEL" "${#FINDINGS[@]}" "$NC" >&2

    # 用 sort 把有时间戳的排前面,空时间戳的排后面
    TIMELINE=$(printf '%s\n' "${FINDINGS[@]}" | grep -v '^|' | sort)
    NO_TS=$(printf '%s\n' "${FINDINGS[@]}" | grep '^|')
    SORTED=$(printf '%s\n%s' "$TIMELINE" "$NO_TS" | grep -v '^$')

    i=0
    while IFS='|' read -r ts level mod title file hint; do
        i=$((i+1))
        [[ -z "$ts" ]] && ts="未知时间"
        # 截短时间戳到分钟
        ts_short=$(echo "$ts" | cut -c1-16)
        case "$level" in
            CRIT) color="$RED"; tag="🔴" ;;
            HIGH) color="$YEL"; tag="🟠" ;;
            MED)  color="$YEL"; tag="🟡" ;;
            *)    color="$CYN"; tag="⚪" ;;
        esac
        printf '  %b[%d]%b %b%s%b %b%s%b\n' "$CYN" "$i" "$NC" "$color" "$ts_short" "$NC" "$color" "$level" "$NC" >&2
        printf '      %s\n' "$title" >&2
        [[ -n "$file" ]] && printf '      %b→%b %s\n' "$CYN" "$NC" "$file" >&2
        [[ -n "$hint" ]] && printf '      %b↪%b %s\n' "$CYN" "$NC" "$hint" >&2
    done <<< "$SORTED"

    {
        printf '\n攻击路径时间线 (共 %d 条事件):\n' "$i"
        printf '%s\n' "$SORTED"
    } >> "$REPORT_LOG"
fi

# ============================================================
# 完整 findings 列表
# ============================================================
echo "" >&2
bar "─" 70 >&2
printf '%b               📋 全部发现项%b\n' "$CYN" "$NC" >&2
bar "─" 70 >&2

# 从 JSONL 重新读一遍,这样颜色和最终得分都对得上
i=0
while IFS= read -r line; do
    i=$((i+1))
    # 解析 JSONL(简化版)
    level=$(echo "$line" | python -c "import json,sys; print(json.loads(sys.stdin.read()).get('level',''))" 2>/dev/null)
    title=$(echo "$line" | python -c "import json,sys; print(json.loads(sys.stdin.read()).get('title',''))" 2>/dev/null)
    score=$(echo "$line" | python -c "import json,sys; print(json.loads(sys.stdin.read()).get('score',0))" 2>/dev/null)

    case "$level" in
        CRIT) COLOR="$RED" ;;
        HIGH) COLOR="$YEL" ;;
        MED)  COLOR="$YEL" ;;
        LOW)  COLOR="$GRN" ;;
        INFO) COLOR="$CYN" ;;
        *)    COLOR="$NC" ;;
    esac
    printf '%b[%d] [%s +%s] %s%b\n' "$COLOR" "$i" "$level" "$score" "$title" "$NC" >&2
done < "$REPORT_JSONL"

echo "" >&2
printf '  %b报告完成:%b %s\n' "$CYN" "$NC" "$SCAN_TIME" >&2
printf '  %bLog:%b   %s\n' "$CYN" "$NC" "$REPORT_LOG" >&2
printf '  %bJSONL:%b %s\n' "$CYN" "$NC" "$REPORT_JSONL" >&2
echo "" >&2

{
    printf '\n报告完成: %s\n' "$SCAN_TIME"
    printf '日志文件: %s\n' "$REPORT_LOG"
    printf 'JSONL:   %s\n' "$REPORT_JSONL"
} >> "$REPORT_LOG"

# 退出
exit 0