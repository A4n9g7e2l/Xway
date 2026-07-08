#!/bin/bash
# ============================================================
# xway_ir.sh v3.0 — Linux 失陷主机一键应急排查
# 基于 NOP Team《Linux 应急响应手册 v2.0.2》全量集成
# 架构借鉴:grayddq/GScan (MIT) — 数据-逻辑分离、IOC 外置、
#          JSON-lines 日志、攻击路径时间线
#
# 37 个检查模块 + 7 类隧道检测 + 6 类暴力破解日志分析
#
# 用法:
#   sudo bash xway_ir.sh                            # 全量扫描
#   sudo bash xway_ir.sh --module 1,3,10            # 只跑指定模块
#   sudo bash xway_ir.sh --severity crit,high       # 只看高危
#   sudo bash xway_ir.sh --timeout 30               # 每检查限时 30s
#   sudo bash xway_ir.sh --no-color                 # 关颜色
#   sudo bash xway_ir.sh --out-dir /tmp/ir          # 指定输出目录
#   sudo bash xway_ir.sh --json-only                # 只输出 JSONL
# ============================================================
set +e

VERSION="3.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
IOC_DIR="${LIB_DIR}/iocs"
OUT_DIR="${OUT_DIR:-/tmp}"
RUN_MODULES=""
SEVERITY_FILTER=""
CHECK_TIMEOUT=0
NO_COLOR=0
JSON_ONLY=0

# -------- CLI 解析 --------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --module) RUN_MODULES="$2"; shift 2 ;;
        --severity) SEVERITY_FILTER="$2"; shift 2 ;;
        --timeout) CHECK_TIMEOUT="$2"; shift 2 ;;
        --no-color) NO_COLOR=1; shift ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --json-only) JSON_ONLY=1; shift ;;
        --help|-h)
            echo "xway_ir.sh v${VERSION} — Linux 应急响应排查"
            echo "用法: sudo bash xway_ir.sh [OPTIONS]"
            echo "  --module 1,3,10     只跑指定模块"
            echo "  --severity crit,high 只显示指定级别"
            echo "  --timeout 30        每检查限时秒数"
            echo "  --no-color          关闭 ANSI 颜色"
            echo "  --out-dir /tmp/ir   输出目录"
            echo "  --json-only         只输出 JSONL"
            exit 0 ;;
        *) shift ;;
    esac
done

# -------- 颜色 --------
if [[ $NO_COLOR -eq 0 && -t 1 ]]; then
    RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'
    BLU='\033[1;34m'; CYN='\033[1;36m'; NC='\033[0m'
    BRED='\033[41;97m'; BYEL='\033[43;30m'; BGRN='\033[42;30m'
else
    RED=''; YEL=''; GRN=''; BLU=''; CYN=''; NC=''
    BRED=''; BYEL=''; BGRN=''
fi

# -------- 主机信息 --------
HOST=$(hostname 2>/dev/null || echo unknown)
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo unknown)
KERNEL=$(uname -r 2>/dev/null || echo unknown)
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')
TS_TAG=$(date '+%Y%m%d_%H%M%S')

# -------- 输出文件 --------
mkdir -p "$OUT_DIR" 2>/dev/null
REPORT_LOG="$OUT_DIR/xway_ir-${HOST}-${TS_TAG}.log"
REPORT_JSONL="$OUT_DIR/xway_ir-${HOST}-${TS_TAG}.jsonl"
: > "$REPORT_LOG" 2>/dev/null
: > "$REPORT_JSONL" 2>/dev/null

# -------- 全局状态 --------
TOTAL_SCORE=0
declare -a FINDINGS
declare -a LATERAL_EVIDENCE
declare -a LATERAL_TARGETS

# -------- 评分/颜色统一函数 --------
score_for_level() {
    case "$1" in
        CRIT) echo 10 ;; HIGH) echo 8 ;; MED) echo 5 ;;
        LOW) echo 3 ;; INFO) echo 0 ;; *) echo 1 ;;
    esac
}
level_to_color() {
    case "$1" in
        CRIT) echo "$RED" ;; HIGH) echo "$YEL" ;;
        MED) echo "$YEL" ;; LOW) echo "$GRN" ;;
        INFO) echo "$CYN" ;; *) echo "" ;;
    esac
}
level_meets_filter() {
    [[ -z "$SEVERITY_FILTER" ]] && return 0
    local lvl="$1"
    case "$lvl" in
        CRIT) [[ "$SEVERITY_FILTER" == *crit* ]] ;;
        HIGH) [[ "$SEVERITY_FILTER" == *high* ]] ;;
        MED) [[ "$SEVERITY_FILTER" == *med* ]] ;;
        LOW) [[ "$SEVERITY_FILTER" == *low* ]] ;;
        INFO) [[ "$SEVERITY_FILTER" == *info* ]] ;;
        *) return 0 ;;
    esac
}

# -------- log_finding --------
log_finding() {
    local level="$1" mod="$2" title="$3" file="${4:-}" hint="${5:-}"
    local ts; ts=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')
    local score; score=$(score_for_level "$level")
    TOTAL_SCORE=$((TOTAL_SCORE + score))

    if [[ $JSON_ONLY -eq 0 ]] && level_meets_filter "$level"; then
        local color; color=$(level_to_color "$level")
        local tag="[$level]"
        case "$level" in
            CRIT) tag="[!] CRIT" ;; HIGH) tag="[!] HIGH" ;;
            MED) tag="[i] MED " ;; LOW) tag="[i] LOW " ;;
            INFO) tag="[i] INFO" ;;
        esac
        printf '%b  %b%s%b %s\n' "$color" "$color" "$tag" "$NC" "$title" >&2
        [[ -n "$file" ]] && printf '         %b→%b %s\n' "$CYN" "$NC" "$file" >&2
        [[ -n "$hint" ]] && printf '         %b↪%b %s\n' "$CYN" "$NC" "$hint" >&2
    fi

    # 写 log
    { printf '%s  %s  %s\n' "[$level]" "$title" "$file"
      [[ -n "$hint" ]] && printf '         ↪ %s\n' "$hint"
    } >> "$REPORT_LOG" 2>/dev/null

    # 写 JSONL
    local title_esc="${title//\"/\\\"}" file_esc="${file//\"/\\\"}" hint_esc="${hint//\"/\\\"}"
    printf '{"ts":"%s","level":"%s","module":"%s","title":"%s","file":"%s","hint":"%s","score":%d}\n' \
        "$ts" "$level" "$mod" "$title_esc" "$file_esc" "$hint_esc" "$score" >> "$REPORT_JSONL" 2>/dev/null

    # 时间线池
    if [[ "$level" == "CRIT" || "$level" == "HIGH" || "$level" == "MED" ]]; then
        local mtime=""
        [[ -n "$file" && -e "$file" ]] && mtime=$(stat -c %y -- "$file" 2>/dev/null)
        FINDINGS+=("${mtime:-$ts}|$level|$mod|$title|$file|$hint")
    fi
}

# -------- section_header --------
section_header() {
    local n="$1" title="$2"
    if [[ $JSON_ONLY -eq 0 ]]; then
        echo -e "\n${BLU}[$n/37]${NC} ${YEL}${title}${NC}" >&2
        echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" >&2
    fi
    { printf '\n[%s/37] %s\n' "$n" "$title"
      printf '──────────────────────────────────────────────────────────────────────\n'
    } >> "$REPORT_LOG" 2>/dev/null
}

bar() {
    local ch="${1:-─}" n="${2:-70}" s="" i
    for ((i=0; i<n; i++)); do s+="$ch"; done
    printf '%s\n' "$s"
}

# -------- IOC 文件加载辅助 --------
load_ioc_pattern() {
    local f="$1" max="${2:-100}"
    [[ -f "$f" ]] || return 1
    grep -vE '^\s*$|^\s*#' "$f" 2>/dev/null | head -"$max" | tr '\n' '|' | sed 's/|$//'
}

# ============================================================
# Banner
# ============================================================
if [[ $JSON_ONLY -eq 0 ]]; then
    clear 2>/dev/null
    cat <<EOF >&2
${RED}╔══════════════════════════════════════════════════════════════════╗${NC}
${RED}║${NC}     ${RED}🛡️  XWAY 蓝队应急响应 — Linux 失陷主机排查 v${VERSION}${NC}            ${RED}║${NC}
${RED}║${NC}     ${CYN}基于 NOP Team 应急响应手册 v2.0.2 全量集成${NC}                  ${RED}║${NC}
${RED}╚══════════════════════════════════════════════════════════════════╝${NC}
EOF
    echo -e "  ${CYN}主机:${NC} ${YEL}$HOST${NC} ${CYN}($IP)${NC}    ${CYN}内核:${NC} ${YEL}$KERNEL${NC}" >&2
    echo -e "  ${CYN}扫描时间:${NC} ${YEL}$SCAN_TIME${NC}" >&2
    echo -e "  ${CYN}报告:${NC} ${YEL}$REPORT_LOG${NC}" >&2
    echo -e "  ${CYN}JSONL:${NC} ${YEL}$REPORT_JSONL${NC}" >&2
    bar "─" 70 >&2
fi
{ printf '╔══════════════════════════════════════════════════════════════════╗\n'
  printf '║   XWAY 蓝队应急响应 v%s — 37 模块\n' "$VERSION"
  printf '╚══════════════════════════════════════════════════════════════════╝\n'
  printf '主机: %s (%s) 内核: %s\n' "$HOST" "$IP" "$KERNEL"
  printf '扫描时间: %s\n' "$SCAN_TIME"
} >> "$REPORT_LOG" 2>/dev/null


# ============================================================
# 模块 1-6: 进程/网络/启动项/Rootkit/SUID/敏感文件
# ============================================================
check_01() {
    section_header "01" "排查可疑进程..."
    local SUSP_PROCS; SUSP_PROCS=$(ps auxww 2>/dev/null | grep -iE "xmrig|minerd|cpuminer|kinsing|ddg|xor|monero|minergate|stratum|hashvault|nicehash|ksoftirdfs|c3pool|cryptonight" | grep -v grep | head -5)
    [[ -n "$SUSP_PROCS" ]] && log_finding "CRIT" "process" "挖矿/僵尸进程" "" "kill -9 <PID>"
    local SUSP_PARENT; SUSP_PARENT=$(ps auxww 2>/dev/null | awk '$11 ~ /(bash|sh|python|perl|php)$/ {print}' | grep -E "www-data|apache|nobody|nginx|httpd|mysql" | head -3)
    [[ -n "$SUSP_PARENT" ]] && log_finding "CRIT" "process" "Web 进程派生 Shell (RCE)" "" "查 Web 访问日志"
    local EVAL_PROCS; EVAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "eval\(|exec\(|base64 -d|wget http|curl http|chmod \+x" | grep -v grep | head -3)
    [[ -n "$EVAL_PROCS" ]] && log_finding "HIGH" "process" "可疑执行命令" "" "strings /proc/<PID>/exe"
}

check_02() {
    section_header "02" "排查网络外联..."
    local EXT_CONN; EXT_CONN=$(ss -antp 2>/dev/null | grep -v "LISTEN" | grep -E ":4444|:5555|:6666|:1337|:8888|:31337|:1080|:1081|:8443" | head -5)
    [[ -n "$EXT_CONN" ]] && log_finding "HIGH" "network" "可疑端口外联" "" "ss -antp 复查"
    local ESTAB; ESTAB=$(ss -antp 2>/dev/null | awk '$1=="ESTAB" {print}' | grep -v ":22\|:80\|:443\|:53" | head -10)
    [[ -n "$ESTAB" ]] && log_finding "HIGH" "network" "异常已建立连接" "" "lsof -i 检查"
    if [[ -f "$IOC_DIR/c2.txt" ]]; then
        local C2_HIT; C2_HIT=$(echo "$ESTAB" | grep -F -f "$IOC_DIR/c2.txt" 2>/dev/null | head -3)
        [[ -n "$C2_HIT" ]] && log_finding "CRIT" "network" "C2 IOC 命中 (Maltrail)" "" "立即隔离 + 封禁 IP"
    fi
}

check_03() {
    section_header "03" "排查启动项/计划任务..."
    local CRON; CRON=$(crontab -l 2>/dev/null | grep -vE "^#|^$" | head -5)
    [[ -n "$CRON" ]] && log_finding "MED" "persistence" "Crontab 配置" "" "crontab -l 复查"
    local SUSP_CRON; SUSP_CRON=$(cat /etc/crontab 2>/dev/null | grep -vE "^#|^$" | grep -iE "wget|curl|base64|nc |/tmp/" | head -3)
    [[ -n "$SUSP_CRON" ]] && log_finding "CRIT" "persistence" "可疑系统 crontab" "" "cat /etc/crontab 审计"
    local CRON_D; CRON_D=$(ls /etc/cron.d/ 2>/dev/null | head -10)
    [[ -n "$CRON_D" ]] && log_finding "LOW" "persistence" "/etc/cron.d/ 内容" "/etc/cron.d/" "逐个 cat 查看"
    local AT_JOBS; AT_JOBS=$(ls /var/spool/at/ /var/spool/cron/atjobs/ 2>/dev/null | head -5)
    [[ -n "$AT_JOBS" ]] && log_finding "HIGH" "persistence" "at/batch 计划任务" "" "atq 查看队列"
    local SUSP_SVC; SUSP_SVC=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -iE "miner|backdoor|update|cron|shell" | head -5)
    [[ -n "$SUSP_SVC" ]] && log_finding "HIGH" "persistence" "可疑 systemd 服务" "" "systemctl status <name>"
    local CRON_LOG; CRON_LOG=$(journalctl -u crond.service --no-pager -n 20 2>/dev/null | grep -vE "^--|No journal" | head -5)
    [[ -n "$CRON_LOG" ]] && log_finding "LOW" "persistence" "cron 执行日志" "" "journalctl -u crond 复查"
}

check_04() {
    section_header "04" "检测内核 Rootkit..."
    local MODULES; MODULES=$(lsmod 2>/dev/null | grep -iE "diamorphine|reptile|suterusu|adore" | head -3)
    [[ -n "$MODULES" ]] && log_finding "CRIT" "rootkit" "Rootkit 内核模块" "" "lsmod + rmmod"
    local LD_PRELOAD_FILE; LD_PRELOAD_FILE=$(cat /etc/ld.so.preload 2>/dev/null)
    [[ -n "$LD_PRELOAD_FILE" ]] && log_finding "CRIT" "rootkit" "LD_PRELOAD 劫持" "/etc/ld.so.preload" "echo '' > /etc/ld.so.preload"
    if [[ -f "$LIB_DIR/rootkit_signatures.txt" ]]; then
        local RK_HITS=""; while IFS= read -r p; do [[ -z "$p" || "$p" =~ ^[[:space:]]*# ]] && continue; [[ -e "$p" ]] && RK_HITS+="$p"$'\n'; done < "$LIB_DIR/rootkit_signatures.txt"
        [[ -n "$RK_HITS" ]] && log_finding "HIGH" "rootkit" "已知 Rootkit 文件/目录签名" "$(echo "$RK_HITS" | head -1)" "chkrootkit / rkhunter"
    fi
    local KSYMS; KSYMS=$(awk '{print $3}' /proc/kallsyms 2>/dev/null | grep -wE "diamorphine|reptile|suterusu|adore|hide_module|unhide_module|sys_getdents64" | head -5)
    [[ -n "$KSYMS" ]] && log_finding "CRIT" "rootkit" "Rootkit 内核符号残留" "" "模块已卸载但符号未清"
    if [[ -f "$LIB_DIR/bad_lkm.txt" ]]; then
        local LKM_HITS; LKM_HITS=$(find /lib/modules -type f \( -name '*.ko' -o -name '*.ko.xz' \) 2>/dev/null | while read -r f; do bn=$(basename "$f" .xz); bn="${bn%.ko}"; grep -qx "$bn" "$LIB_DIR/bad_lkm.txt" 2>/dev/null && echo "$f"; done | head -3)
        [[ -n "$LKM_HITS" ]] && log_finding "CRIT" "rootkit" "已知恶意 LKM 模块" "$(echo "$LKM_HITS" | head -1)" "rmmod + 删除 .ko"
    fi
    local DMESG_TAINT; DMESG_TAINT=$(dmesg 2>/dev/null | grep -i "taint" | head -3)
    [[ -n "$DMESG_TAINT" ]] && log_finding "HIGH" "rootkit" "内核 taint (未签名模块)" "" "dmesg | grep taint"
}

check_05() {
    section_header "05" "排查 SUID/SGID..."
    local SUID_RECENT; SUID_RECENT=$(find / -perm /4000 -mtime -30 -type f 2>/dev/null | head -5)
    [[ -n "$SUID_RECENT" ]] && log_finding "CRIT" "suid" "30 天内新增 SUID" "$(echo "$SUID_RECENT" | head -1)" "chmod u-s <path>"
    if [[ -f "$LIB_DIR/suid_whitelist.txt" ]]; then
        local SUID_ALL; SUID_ALL=$(find / -perm /4000 -type f 2>/dev/null)
        local SUID_SUSP; SUID_SUSP=$(echo "$SUID_ALL" | while read -r f; do grep -qxF "$f" "$LIB_DIR/suid_whitelist.txt" 2>/dev/null || echo "$f"; done | head -5)
        [[ -n "$SUID_SUSP" ]] && log_finding "HIGH" "suid" "非白名单 SUID 文件" "$(echo "$SUID_SUSP" | head -1)" "与同版本干净系统对照"
    fi
}

check_06() {
    section_header "06" "排查敏感文件变化..."
    local RECENT; RECENT=$(find /etc /usr/local /opt /root /tmp -mtime -7 -type f 2>/dev/null | grep -vE "/proc|/sys|\.log$|\.sock$" | head -10)
    [[ -n "$RECENT" ]] && log_finding "LOW" "file" "7天内修改文件" "$(echo "$RECENT" | head -1)" "diff 与备份对比"
}

check_07() {
    section_header "07" "排查 Webshell..."
    local WS; WS=$(find /var/www /usr/share/nginx /home /root -type f \( -name "*.php" -o -name "*.jsp" \) 2>/dev/null | grep -iE "[0-9]{1,4}\.(php|jsp)$|[a-z]{1,3}[0-9]{4,}\.(php|jsp)$" | head -5)
    [[ -n "$WS" ]] && log_finding "CRIT" "webshell" "数字命名 PHP/JSP" "$(echo "$WS" | head -1)" "cat 看内容 + 删"
    local WSHELL; WSHELL=$(grep -rE "eval\(\\$_POST|eval\(\\$_GET|assert\(\\$_POST|system\(\\$_POST|passthru\(\\$_POST" /var/www /root 2>/dev/null | grep -viE "/(nuclei-templates|nuclei-templates-2)\.|\.hermes/skills/|/training/ctf/|/htb/|/thm/|/oscp/" | head -5)
    [[ -n "$WSHELL" ]] && log_finding "CRIT" "webshell" "PHP 一句话后门" "" "cat 文件内容"
    if [[ -f "$IOC_DIR/backdoors.txt" ]]; then
        local WS_KNOWN; WS_KNOWN=$(find /var/www /usr/share/nginx /home /root -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) 2>/dev/null | grep -F -f "$IOC_DIR/backdoors.txt" | head -5)
        [[ -n "$WS_KNOWN" ]] && log_finding "CRIT" "webshell" "已知 Webshell 文件名" "$(echo "$WS_KNOWN" | head -1)" "查威胁情报 + 删"
    fi
}

check_08() {
    section_header "08" "排查挖矿特征..."
    local HIGH_CPU; HIGH_CPU=$(ps auxww 2>/dev/null | sort -k3 -nr | head -5 | awk '$3+0 > 30 {print}')
    [[ -n "$HIGH_CPU" ]] && log_finding "HIGH" "miner" "高 CPU 进程(挖矿)" "$(echo "$HIGH_CPU" | head -1)" "kill + strings"
    local MINER_CFG; MINER_CFG=$(find /tmp /var/tmp /opt /root /home -type f \( -name "config.json" -o -name "*.conf" -o -name "pools.txt" \) 2>/dev/null | xargs grep -lE "stratum\+tcp|xmrig|c3pool|moneroocean|nicehash|hashvault|cryptonight" 2>/dev/null | head -3)
    [[ -n "$MINER_CFG" ]] && log_finding "CRIT" "miner" "挖矿配置文件" "$(echo "$MINER_CFG" | head -1)" "rm + 找落点"
}

check_09() {
    section_header "09" "排查可疑文件位置..."
    local TMP_EXEC; TMP_EXEC=$(find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null | head -10)
    [[ -n "$TMP_EXEC" ]] && log_finding "HIGH" "file" "临时目录可执行文件" "$(echo "$TMP_EXEC" | head -1)" "strings + chmod -x"
    local DIGIT_LIB; DIGIT_LIB=$(find / -type f \( -name "[0-9][0-9].so" -o -name "[0-9][0-9].dll" \) 2>/dev/null | head -5)
    [[ -n "$DIGIT_LIB" ]] && log_finding "CRIT" "file" "数字命名 so/dll (银狐)" "$(echo "$DIGIT_LIB" | head -1)" "溯源 + 删"
    local HIDDEN_DIRS; HIDDEN_DIRS=$(ls -d /root/.*[0-9] /home/*/.*[0-9] 2>/dev/null | grep -vE '^\.$|^\.\.$|\.ssh$|\.cache$|\.config$|\.local$' | head -5)
    [[ -n "$HIDDEN_DIRS" ]] && log_finding "MED" "file" "可疑隐藏目录 (~/.xxxxxx)" "$(echo "$HIDDEN_DIRS" | head -1)" "ls -la 查内容"
}

check_10() {
    section_header "10" "排查横向移动(关键)..."
    for home in /root /home/*; do
        if [ -f "$home/.ssh/authorized_keys" ]; then
            local KEYS; KEYS=$(cat "$home/.ssh/authorized_keys" 2>/dev/null)
            local SUSP; SUSP=$(echo "$KEYS" | grep -vE "^#|^$|@$|company|backup" | head -3)
            if [ -n "$SUSP" ]; then
                LATERAL_EVIDENCE+=("[!] authorized_keys 含可疑公钥 ($home)")
                LATERAL_TARGETS+=("$home")
                log_finding "CRIT" "lateral" "SSH 公钥植入 ($home)" "$home/.ssh/authorized_keys" "查 fingerprint + 删"
            fi
        fi
    done
    local KNOWN; KNOWN=$(cat /root/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | head -10)
    [[ -n "$KNOWN" ]] && LATERAL_TARGETS+=("$KNOWN")
    local SSH_BRUTE=""; for f in /var/log/auth.log /var/log/secure /var/log/messages; do [ -f "$f" ] && SSH_BRUTE=$(grep -E "Failed password|Invalid user|authentication failure" "$f" 2>/dev/null | tail -50); done
    local SSH_FAILED_COUNT; SSH_FAILED_COUNT=$(echo "$SSH_BRUTE" | grep -c . 2>/dev/null || echo 0)
    if [ "$SSH_FAILED_COUNT" -gt 0 ]; then
        LATERAL_EVIDENCE+=("[!] SSH 失败登录 $SSH_FAILED_COUNT 次")
        log_finding "MED" "lateral" "SSH 失败登录 ($SSH_FAILED_COUNT 次)" "" "封禁爆破源 IP"
    fi
    local SSH_SUCCESS=""; for f in /var/log/auth.log /var/log/secure; do [ -f "$f" ] && SSH_SUCCESS=$(grep -E "Accepted password|Accepted publickey" "$f" 2>/dev/null | tail -20); done
    [[ -n "$SSH_SUCCESS" ]] && log_finding "MED" "lateral" "SSH 成功登录" "" "复查来源 IP"
    if [[ -n "$SSH_BRUTE" && -n "$SSH_SUCCESS" ]]; then
        local BRUTE_IPS; BRUTE_IPS=$(echo "$SSH_BRUTE" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | awk '$1>=20 {print $2}')
        for ip in $BRUTE_IPS; do
            if echo "$SSH_SUCCESS" | grep -q "$ip"; then
                LATERAL_EVIDENCE+=("[!] SSH 爆破成功后入侵关联: $ip")
                log_finding "CRIT" "lateral" "SSH 爆破成功后入侵 ($ip)" "" "封禁 IP + 改密码"
                break
            fi
        done
    fi
    local HOSTS; HOSTS=$(cat /etc/hosts 2>/dev/null | grep -vE "^#|^$|localhost|ip6-")
    local SUSP_HOSTS; SUSP_HOSTS=$(echo "$HOSTS" | grep -iE "\.(tk|top|xyz|gq|cyou|onion)")
    if [ -n "$SUSP_HOSTS" ]; then
        LATERAL_EVIDENCE+=("[!] /etc/hosts 含可疑域名劫持")
        log_finding "HIGH" "lateral" "/etc/hosts 可疑劫持" "/etc/hosts" "vi /etc/hosts 复核"
    fi
    local SCAN_TOOLS; SCAN_TOOLS=$(find / -type f \( -name "nmap" -o -name "masscan" -o -name "hydra" -o -name "medusa" \) 2>/dev/null | grep -vE "/usr/bin|/usr/share|/snap" | head -3)
    [[ -n "$SCAN_TOOLS" ]] && { LATERAL_EVIDENCE+=("[!] 发现横向扫描工具"); log_finding "HIGH" "lateral" "横向扫描工具" "$(echo "$SCAN_TOOLS" | head -1)" "溯源使用记录"; }
    local LATERAL_PROCS; LATERAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "ssh -R|ssh -D|ssh -L|nc -l|socat.*exec" | grep -v grep | head -3)
    [[ -n "$LATERAL_PROCS" ]] && { LATERAL_EVIDENCE+=("[!] 横向移动进程运行中"); log_finding "CRIT" "lateral" "SSH 隧道 / nc 反向" "" "kill + 查 .bash_history"; }
    local WEIRD; WEIRD=$(awk -F: '$3 < 1000 && $3 != 0 {print}' /etc/passwd 2>/dev/null)
    [[ -n "$WEIRD" ]] && { LATERAL_EVIDENCE+=("[!] 异常 UID<1000 账号"); log_finding "MED" "lateral" "异常账号 (UID<1000)" "" "查可疑 UID"; }
}

check_11() {
    section_header "11" "排查 Java 内存马..."
    local SUSP_JAR; SUSP_JAR=$(find / -name "*.jar" -mtime -30 2>/dev/null | grep -iE "memshell|agent|evil|hack" | head -3)
    [[ -n "$SUSP_JAR" ]] && log_finding "CRIT" "java" "可疑 Java JAR (内存马)" "$(echo "$SUSP_JAR" | head -1)" "arthas 抓运行时类"
    local TOMCAT_WEB; TOMCAT_WEB=$(find / -path "*/webapps/*" -name "*.jsp" -mtime -30 2>/dev/null | head -3)
    [[ -n "$TOMCAT_WEB" ]] && log_finding "MED" "java" "Tomcat 近期 JSP" "$(echo "$TOMCAT_WEB" | head -1)" "cat + 删"
}

check_12() {
    section_header "12" "排查提权痕迹..."
    local SUDOERS; SUDOERS=$(grep -vE "^#|^$|root\s+ALL" /etc/sudoers 2>/dev/null | head -5)
    [[ -n "$SUDOERS" ]] && log_finding "MED" "privesc" "Sudoers 异常配置" "/etc/sudoers" "visudo 复核"
    local SUDOERS_D; SUDOERS_D=$(ls /etc/sudoers.d/ 2>/dev/null | grep -vE "^README" | head -5)
    [[ -n "$SUDOERS_D" ]] && log_finding "HIGH" "privesc" "/etc/sudoers.d/ 新增文件" "/etc/sudoers.d/" "逐个 cat 查看"
    local SUDOERS_PERM; SUDOERS_PERM=$(stat -c %a /etc/sudoers 2>/dev/null)
    [[ -n "$SUDOERS_PERM" && "$SUDOERS_PERM" != "440" ]] && log_finding "MED" "privesc" "/etc/sudoers 权限异常 ($SUDOERS_PERM)" "/etc/sudoers" "chmod 440 /etc/sudoers"
    local CAPS; CAPS=$(getcap -r / 2>/dev/null | head -5)
    [[ -n "$CAPS" ]] && log_finding "MED" "privesc" "文件 capabilities" "" "与默认清单对照"
}

check_13() {
    section_header "13" "容器环境检测..."
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        log_finding "INFO" "container" "当前在 Docker 容器内" "" ""
    fi
}

check_14() {
    section_header "14" "排查 Shell 环境劫持..."
    local ENV_TAGS="LD_PRELOAD LD_AOUT_PRELOAD LD_ELF_PRELOAD LD_LIBRARY_PATH PROMPT_COMMAND"
    for tag in $ENV_TAGS; do
        local HIT; HIT=$(grep -rhE "^[^#]*export[[:space:]]+${tag}=" /root/.bashrc /root/.bash_profile /etc/bashrc /etc/profile /etc/profile.d/ /home/*/.bashrc /home/*/.bash_profile 2>/dev/null | grep -v "^#" | head -3)
        [[ -n "$HIT" ]] && log_finding "CRIT" "env-hijack" "Shell 环境劫持 ($tag)" "" "vi .bashrc 删 export $tag=..."
    done
    local LD_CONF; LD_CONF=$(cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -vE "^#|^$" | grep -vE "^/usr/lib|^/lib" | head -3)
    [[ -n "$LD_CONF" ]] && log_finding "HIGH" "env-hijack" "ld.so.conf.d 可疑路径" "/etc/ld.so.conf.d/" "逐个 cat 查看"
}

check_15() {
    section_header "15" "排查命令别名劫持..."
    local ALIAS_HITS; ALIAS_HITS=$(grep -rhE "^[[:space:]]*alias[[:space:]]+(ps|netstat|strings|find|echo|iptables|lastlog|who|ifconfig|ssh|lsof|ls|cat)=" /root/.bashrc /root/.bash_profile /etc/bashrc /etc/profile /home/*/.bashrc 2>/dev/null | grep -v "^#" | head -5)
    [[ -n "$ALIAS_HITS" ]] && log_finding "CRIT" "env-hijack" "命令别名劫持" "" "vi .bashrc 删可疑 alias"
}

check_16() {
    section_header "16" "排查 SSH 后门..."
    if [ -f /usr/sbin/sshd ]; then
        local FILE_TYPE; FILE_TYPE=$(file /usr/sbin/sshd 2>/dev/null)
        if ! echo "$FILE_TYPE" | grep -qE "ELF|executable"; then
            log_finding "CRIT" "backdoor" "sshd 非 ELF (SSH wrapper 后门)" "/usr/sbin/sshd" "dpkg -V / rpm -V 校验"
        fi
    fi
    local ALT_SSHD; ALT_SSHD=$(ss -ntlp 2>/dev/null | grep sshd | grep -v ":22[[:space:]]" | head -3)
    [[ -n "$ALT_SSHD" ]] && log_finding "HIGH" "backdoor" "sshd 监听非标准端口" "" "vi /etc/ssh/sshd_config"
    local SSH_CFG; SSH_CFG=$(grep -rhE "^[[:space:]]*(LocalCommand|ProxyCommand)[[:space:]]*=" /etc/ssh/ssh_config /root/.ssh/config /home/*/.ssh/config 2>/dev/null | head -3)
    [[ -n "$SSH_CFG" ]] && log_finding "CRIT" "backdoor" "ssh config 后门 (LocalCommand/ProxyCommand)" "" "vi ssh_config 删可疑行"
}

check_17() {
    section_header "17" "排查账号安全..."
    local SHADOW_PERM; SHADOW_PERM=$(stat -c %a /etc/shadow 2>/dev/null)
    [[ -n "$SHADOW_PERM" && "$SHADOW_PERM" != "0" && "$SHADOW_PERM" != "640" ]] && log_finding "HIGH" "compliance" "/etc/shadow 权限异常 ($SHADOW_PERM)" "/etc/shadow" "chmod 640 /etc/shadow"
    local PASSWD_PERM; PASSWD_PERM=$(stat -c %a /etc/passwd 2>/dev/null)
    [[ -n "$PASSWD_PERM" && "$PASSWD_PERM" != "644" ]] && log_finding "MED" "compliance" "/etc/passwd 权限异常 ($PASSWD_PERM)" "/etc/passwd" "chmod 644 /etc/passwd"
    local EMPTY_PW; EMPTY_PW=$(awk -F: '($2 == "" || $2 == "!" || $2 == "*") && $1 != "root" && $1 != "sync" && $1 != "halt" && $1 != "shutdown" {print $1}' /etc/passwd 2>/dev/null | head -5)
    [[ -n "$EMPTY_PW" ]] && log_finding "HIGH" "compliance" "空密码账号" "/etc/passwd" "passwd <user> 设密"
    local PW_PADDING; PW_PADDING=$(awk -F: '$2 != "x" && $2 != "" && $2 != "*" && $2 != "!" {print $1, $2}' /etc/passwd 2>/dev/null | head -5)
    [[ -n "$PW_PADDING" ]] && log_finding "CRIT" "compliance" "密码填充 (/etc/passwd 密码字段非 x)" "/etc/passwd" "检查 /etc/shadow 一致性"
    local UID0; UID0=$(awk -F: '$3==0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
    [[ -n "$UID0" ]] && log_finding "CRIT" "compliance" "非 root 的 UID=0 特权账户" "/etc/passwd" "usermod -u 1001 <user>"
}

check_18() {
    section_header "18" "排查 bash_history 反 shell..."
    local HIST_HITS=""
    for h in /root/.bash_history /home/*/.bash_history; do
        [ -f "$h" ] || continue
        if [[ -f "$IOC_DIR/rshell.txt" ]]; then
            local PAT; PAT=$(load_ioc_pattern "$IOC_DIR/rshell.txt" 20)
            local H; H=$(grep -nE "$PAT" "$h" 2>/dev/null | head -3)
            [[ -n "$H" ]] && HIST_HITS+="${h}: ${H}"$'\n'
        fi
    done
    [[ -n "$HIST_HITS" ]] && log_finding "CRIT" "history" "bash_history 含反 shell 命令" "" "cat .bash_history 完整审计"
    local HIST_TAMPER=""
    for h in /root/.bash_history /home/*/.bash_history; do
        [ -f "$h" ] || continue
        local TAMPER; TAMPER=$(grep -nE "history -c|HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0|unset HIST" "$h" 2>/dev/null | head -2)
        [[ -n "$TAMPER" ]] && HIST_TAMPER+="${h}: ${TAMPER}"$'\n'
    done
    [[ -n "$HIST_TAMPER" ]] && log_finding "HIGH" "history" "bash_history 篡改痕迹 (history -c / HISTFILE=/dev/null)" "" "查篡改时间 + 前后命令"
}

# ============================================================
# 模块 19-37: 手册新增检查 (NOP Team 应急响应手册 v2.0.2)
# ============================================================
check_19() {
    section_header "19" "排查 SSH key 后门 (command=)..."
    for home in /root /home/*; do
        for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [ -f "$ak" ] || continue
            local CMD_HIT; CMD_HIT=$(grep -nE '^[[:space:]]*command=' "$ak" 2>/dev/null | head -3)
            [[ -n "$CMD_HIT" ]] && log_finding "CRIT" "backdoor" "authorized_keys command= 后门 ($ak)" "$ak" "删除 command= 行"
        done
    done
    local AK_FILE; AK_FILE=$(grep -E "^AuthorizedKeysFile" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -n "$AK_FILE" && "$AK_FILE" != ".ssh/authorized_keys" ]] && log_finding "MED" "backdoor" "AuthorizedKeysFile 路径异常 ($AK_FILE)" "/etc/ssh/sshd_config" "确认是否被篡改"
}

check_20() {
    section_header "20" "排查 BASH 后门 (内置同名/函数/trap)..."
    local BUILTIN_HITS; BUILTIN_HITS=$(compgen -b 2>/dev/null | grep -v -E "\.|\:" | while read -r line; do
        local f="/usr/bin/$line"
        if [ -f "$f" ]; then
            local ft; ft=$(file "$f" 2>/dev/null)
            [[ "$ft" == *"script"* ]] && echo "$f: $ft"
        fi
    done | head -5)
    [[ -n "$BUILTIN_HITS" ]] && log_finding "HIGH" "backdoor" "BASH 内置同名脚本文件" "$(echo "$BUILTIN_HITS" | head -1)" "cat 查看内容"
    local FUNC_HITS; FUNC_HITS=$(declare -f 2>/dev/null | grep -E "^[a-zA-Z_]+\s*\(\)" | grep -vE "^(_|declare|compgen)" | head -5)
    [[ -n "$FUNC_HITS" ]] && log_finding "MED" "backdoor" "非默认 BASH 函数" "" "declare -f <name> 查看"
    local TRAP_HITS; TRAP_HITS=$(trap -p 2>/dev/null | grep -vE "EXIT|ERR|RETURN|DEBUG" | head -3)
    [[ -n "$TRAP_HITS" ]] && log_finding "HIGH" "backdoor" "非默认 trap 设置" "" "trap -p 复查"
}

check_21() {
    section_header "21" "排查 motd 后门..."
    local MOTD_DIR="/etc/update-motd.d"
    if [ -d "$MOTD_DIR" ]; then
        local MOTD_FILES; MOTD_FILES=$(ls -la "$MOTD_DIR" 2>/dev/null | grep -vE "^total|^d" | head -10)
        [[ -n "$MOTD_FILES" ]] && log_finding "LOW" "backdoor" "motd 脚本存在" "$MOTD_DIR/" "逐个 cat 查看内容"
        local MOTD_SUSP; MOTD_SUSP=$(grep -rlE "wget|curl|nc |bash -c|python" "$MOTD_DIR" 2>/dev/null | head -3)
        [[ -n "$MOTD_SUSP" ]] && log_finding "CRIT" "backdoor" "motd 脚本含可疑命令" "$(echo "$MOTD_SUSP" | head -1)" "删除可疑脚本"
    fi
}

check_22() {
    section_header "22" "排查 TCP Wrappers 后门..."
    local HOSTS_ALLOW; HOSTS_ALLOW=$(cat /etc/hosts.allow 2>/dev/null | grep -vE "^#|^$" | head -10)
    [[ -n "$HOSTS_ALLOW" ]] && log_finding "LOW" "backdoor" "/etc/hosts.allow 配置" "/etc/hosts.allow" "检查 spawn/twist"
    local HOSTS_DENY; HOSTS_DENY=$(cat /etc/hosts.deny 2>/dev/null | grep -vE "^#|^$" | head -10)
    [[ -n "$HOSTS_DENY" ]] && log_finding "LOW" "backdoor" "/etc/hosts.deny 配置" "/etc/hosts.deny" "检查 spawn/twist"
    local SPAWN_HIT; SPAWN_HIT=$(grep -riE "spawn|twist" /etc/hosts.allow /etc/hosts.deny 2>/dev/null | head -3)
    [[ -n "$SPAWN_HIT" ]] && log_finding "CRIT" "backdoor" "TCP Wrappers spawn/twist 后门" "" "删除 spawn/twist 行"
}

check_23() {
    section_header "23" "排查 udev 规则后门..."
    local UDEV_HITS; UDEV_HITS=$(grep -riI 'RUN\|PROGRAM\|IMPORT' /etc/udev/rules.d/ /usr/lib/udev/rules.d/ /run/udev/rules.d/ 2>/dev/null | grep -vE "^#|^[[:space:]]*$" | head -10)
    [[ -n "$UDEV_HITS" ]] && log_finding "LOW" "backdoor" "udev 规则含 RUN/PROGRAM/IMPORT" "/etc/udev/rules.d/" "与默认规则对照"
    local UDEV_SUSP; UDEV_SUSP=$(grep -riE 'RUN\+?=.*(/tmp/|/dev/shm|wget|curl|nc |bash|python)' /etc/udev/rules.d/ 2>/dev/null | head -3)
    [[ -n "$UDEV_SUSP" ]] && log_finding "CRIT" "backdoor" "udev 规则指向可疑路径" "" "删除可疑规则文件"
}

check_24() {
    section_header "24" "排查 Python .pth 后门..."
    local PTH_FILES; PTH_FILES=$(locate .pth 2>/dev/null | head -20)
    if [[ -n "$PTH_FILES" ]]; then
        local PTH_SUSP=""
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            local HIT; HIT=$(grep -nE "^import " "$f" 2>/dev/null | head -2)
            [[ -n "$HIT" ]] && PTH_SUSP+="${f}: ${HIT}"$'\n'
        done <<< "$PTH_FILES"
        [[ -n "$PTH_SUSP" ]] && log_finding "CRIT" "backdoor" "Python .pth 文件含 import 后门" "$(echo "$PTH_SUSP" | head -1)" "删除 import 行"
    fi
    local PY_PATH; PY_PATH=$(echo "$PYTHONPATH" 2>/dev/null)
    [[ -n "$PY_PATH" ]] && log_finding "MED" "backdoor" "PYTHONPATH 被设置 ($PY_PATH)" "" "检查是否注入恶意路径"
}

check_25() {
    section_header "25" "排查 PAM 后门..."
    local PAM_DIR; PAM_DIR=$(ls /usr/lib/x86_64-linux-gnu/security/ /usr/lib64/security/ 2>/dev/null | head -20)
    [[ -n "$PAM_DIR" ]] && log_finding "LOW" "backdoor" "PAM 模块目录" "" "与默认清单对照"
    local PAM_CFG; PAM_CFG=$(ls /etc/pam.d/ 2>/dev/null | head -20)
    [[ -n "$PAM_CFG" ]] && log_finding "LOW" "backdoor" "PAM 配置目录" "/etc/pam.d/" "检查非默认配置"
    local PAM_SUSP; PAM_SUSP=$(grep -rlE "pam_exec|pam_permit" /etc/pam.d/ 2>/dev/null | head -3)
    [[ -n "$PAM_SUSP" ]] && log_finding "HIGH" "backdoor" "PAM 配置含 pam_exec/pam_permit" "$(echo "$PAM_SUSP" | head -1)" "检查是否被篡改"
    if command -v debsums &>/dev/null; then
        local PAM_INTEG; PAM_INTEG=$(debsums -a -c 2>/dev/null | grep -i "pam" | head -3)
        [[ -n "$PAM_INTEG" ]] && log_finding "CRIT" "backdoor" "PAM 模块完整性失败 (debsums)" "$(echo "$PAM_INTEG" | head -1)" "重新安装 libpam"
    fi
}

check_26() {
    section_header "26" "排查家目录模板投毒..."
    if [ -d /etc/skel ]; then
        local SKEL_FILES; SKEL_FILES=$(ls -la /etc/skel/ 2>/dev/null | grep -vE "^total|^d" | head -10)
        [[ -n "$SKEL_FILES" ]] && log_finding "LOW" "backdoor" "/etc/skel/ 模板文件" "/etc/skel/" "逐个 cat 检查"
        local SKEL_SUSP; SKEL_SUSP=$(grep -rlE "wget|curl|nc |bash -c|python|alias (ps|netstat|ssh)=" /etc/skel/ 2>/dev/null | head -3)
        [[ -n "$SKEL_SUSP" ]] && log_finding "CRIT" "backdoor" "/etc/skel/ 含可疑命令" "$(echo "$SKEL_SUSP" | head -1)" "删除可疑行"
    fi
}

check_27() {
    section_header "27" "排查系统安全配置..."
    local PTRACE; PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    [[ -n "$PTRACE" && "$PTRACE" == "0" ]] && log_finding "MED" "config" "ptrace_scope = 0 (完全允许注入)" "/proc/sys/kernel/yama/ptrace_scope" "echo 1 > /proc/sys/kernel/yama/ptrace_scope"
    local ASLR; ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    [[ -n "$ASLR" && "$ASLR" == "0" ]] && log_finding "MED" "config" "ASLR 已关闭 (randomize_va_space=0)" "" "echo 2 > /proc/sys/kernel/randomize_va_space"
    local IPTABLES; IPTABLES=$(iptables -L -n 2>/dev/null | grep -iE "REDIRECT|DNAT|端口复用" | head -5)
    [[ -n "$IPTABLES" ]] && log_finding "HIGH" "config" "iptables 端口复用/重定向规则" "" "iptables -L -n 复查"
}

check_28() {
    section_header "28" "排查软件完整性..."
    if command -v rpm &>/dev/null; then
        local RPM_VA; RPM_VA=$(rpm -Va 2>/dev/null | grep -E "^..5" | head -10)
        [[ -n "$RPM_VA" ]] && log_finding "HIGH" "integrity" "rpm -Va 校验失败 (被篡改)" "$(echo "$RPM_VA" | head -1)" "rpm -V <package> 复查"
    elif command -v debsums &>/dev/null; then
        local DEB; DEB=$(debsums --all --changed 2>/dev/null | head -10)
        [[ -n "$DEB" ]] && log_finding "HIGH" "integrity" "debsums 校验失败 (被篡改)" "$(echo "$DEB" | head -1)" "apt install --reinstall <pkg>"
    else
        log_finding "INFO" "integrity" "无 rpm/debsums 工具,跳过软件完整性检查" "" "apt install debsums / yum install rpm"
    fi
}

check_29() {
    section_header "29" "排查内核模块签名..."
    local MOD_SIG; MOD_SIG=$(zgrep CONFIG_MODULE_SIG /boot/config-$(uname -r 2>/dev/null) 2>/dev/null | grep -v "^#")
    if [[ -n "$MOD_SIG" ]]; then
        echo "$MOD_SIG" | grep -q "CONFIG_MODULE_SIG=y" || log_finding "MED" "kernel" "内核模块签名未启用" "/boot/config-$(uname -r)" "更新内核配置"
        echo "$MOD_SIG" | grep -q "CONFIG_MODULE_SIG_FORCE=y" || log_finding "LOW" "kernel" "内核模块签名非强制" "" "建议启用 SIG_FORCE"
    fi
    local DMESG_TAINT; DMESG_TAINT=$(dmesg 2>/dev/null | grep -i "module verification failed" | head -3)
    [[ -n "$DMESG_TAINT" ]] && log_finding "HIGH" "kernel" "内核加载了未签名模块" "" "dmesg | grep taint 复查"
}

check_30() {
    section_header "30" "排查 GPG 密钥..."
    if command -v apt-key &>/dev/null; then
        local APT_KEYS; APT_KEYS=$(apt-key list 2>/dev/null | grep -E "^pub|^uid" | head -10)
        [[ -n "$APT_KEYS" ]] && log_finding "LOW" "config" "APT GPG 密钥列表" "" "检查非官方密钥"
    elif [ -d /etc/pki/rpm-gpg ]; then
        local RPM_KEYS; RPM_KEYS=$(ls /etc/pki/rpm-gpg/ 2>/dev/null | head -10)
        [[ -n "$RPM_KEYS" ]] && log_finding "LOW" "config" "RPM GPG 密钥列表" "/etc/pki/rpm-gpg/" "检查非官方密钥"
    fi
}

check_31() {
    section_header "31" "排查 deleted 进程文件..."
    local DELETED; DELETED=$(ls -al /proc/*/exe 2>/dev/null | grep "deleted" | head -5)
    [[ -n "$DELETED" ]] && log_finding "CRIT" "process" "进程加载已删除文件 (/proc/*/exe deleted)" "$(echo "$DELETED" | head -1)" "kill PID + 查原始文件路径"
    local DELETED_LSOF; DELETED_LSOF=$(lsof 2>/dev/null | grep "deleted" | head -5)
    [[ -n "$DELETED_LSOF" ]] && log_finding "HIGH" "process" "lsof 发现已删除文件被占用" "" "kill PID + 取证"
}

check_32() {
    section_header "32" "排查隐藏进程 (proc vs ps)..."
    local PROC_PIDS; PROC_PIDS=$(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
    local PS_PIDS; PS_PIDS=$(ps -e --no-headers -o pid 2>/dev/null | tr -d ' ' | sort -n)
    local HIDDEN=""
    for pid in $PROC_PIDS; do
        if ! echo "$PS_PIDS" | grep -qx "$pid" 2>/dev/null; then
            local COMM; COMM=$(cat /proc/$pid/comm 2>/dev/null)
            [[ -n "$COMM" ]] && HIDDEN+="PID $pid ($COMM) "$'\n'
        fi
    done
    if [[ -n "$HIDDEN" ]]; then
        local COUNT; COUNT=$(echo "$HIDDEN" | grep -c . 2>/dev/null)
        log_finding "CRIT" "process" "隐藏进程 (proc 有但 ps 无): $COUNT 个" "$(echo "$HIDDEN" | head -1)" "busybox ps 复查 + kill"
    fi
}

check_33() {
    section_header "33" "排查运行服务异常..."
    local RUNNING; RUNNING=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -vE "UNIT|LOAD|ACTIVE|SUB|loaded units|To show all" | head -20)
    [[ -n "$RUNNING" ]] && log_finding "LOW" "service" "运行中的服务列表" "" "检查非默认运行的服务"
    local SUSP_SVC_CFG; SUSP_SVC_CFG=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | awk '{print $1}' | while read -r svc; do
        local cfg; cfg=$(systemctl cat "$svc" 2>/dev/null | grep -E "ExecStart=.*(/tmp/|/dev/shm|/var/tmp)" 2>/dev/null)
        [[ -n "$cfg" ]] && echo "$svc: $cfg"
    done | head -3)
    [[ -n "$SUSP_SVC_CFG" ]] && log_finding "CRIT" "service" "服务配置指向 /tmp /dev/shm" "$(echo "$SUSP_SVC_CFG" | head -1)" "systemctl cat <name> 复查"
}

check_34() {
    section_header "34" "排查 DNS 配置 + 环境变量..."
    local DNS; DNS=$(cat /etc/resolv.conf 2>/dev/null | grep "^nameserver" | head -5)
    [[ -n "$DNS" ]] && log_finding "LOW" "config" "DNS 配置" "/etc/resolv.conf" "检查非内网 DNS"
    local DNS_SUSP; DNS_SUSP=$(echo "$DNS" | grep -vE "127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|1\.1\.1\.1|8\.8\.")
    [[ -n "$DNS_SUSP" ]] && log_finding "MED" "config" "DNS 指向非标准地址" "/etc/resolv.conf" "确认 DNS 是否被篡改"
    local ENV_SUSP; ENV_SUSP=$(env 2>/dev/null | grep -iE "^(LD_PRELOAD|LD_LIBRARY_PATH|PROMPT_COMMAND|PYTHONPATH|PATH=.*(/tmp|/dev/shm))" | head -5)
    [[ -n "$ENV_SUSP" ]] && log_finding "HIGH" "config" "环境变量含可疑值" "" "env 复查 + unset"
}

check_35() {
    section_header "35" "排查隧道检测..."
    local SSH_TUNNEL; SSH_TUNNEL=$(ps auxww 2>/dev/null | grep -E "ssh.*(-L|-R|-D|-fCNg)" | grep -v grep | head -3)
    [[ -n "$SSH_TUNNEL" ]] && log_finding "HIGH" "tunnel" "SSH 隧道进程 (-L/-R/-D)" "" "kill + 查 .bash_history"
    local SOCKS_PROC; SOCKS_PROC=$(ps auxww 2>/dev/null | grep -iE "frpc|frps|earthworm|ew_for|shadowsocks|ss-server|chisel|ligolo|ngrok" | grep -v grep | head -3)
    [[ -n "$SOCKS_PROC" ]] && log_finding "CRIT" "tunnel" "Socks/代理隧道进程" "" "kill + 删除配置"
    local DNS_TUNNEL; DNS_TUNNEL=$(ps auxww 2>/dev/null | grep -iE "dns2tcp|dnscat|iodine|ptunnel|icmpsh|icmptunnel" | grep -v grep | head -3)
    [[ -n "$DNS_TUNNEL" ]] && log_finding "CRIT" "tunnel" "DNS/ICMP 隧道进程" "" "kill + 删除配置"
    local HTTP_TUNNEL; HTTP_TUNNEL=$(ps auxww 2>/dev/null | grep -iE "proxytunnel|httptunnel|htc|hts|reGeorg|neo-regeorg|tunna|abptts|stunnel" | grep -v grep | head -3)
    [[ -n "$HTTP_TUNNEL" ]] && log_finding "CRIT" "tunnel" "HTTP/SSL 隧道进程" "" "kill + 删除配置"
    if command -v bpftrace &>/dev/null; then
        log_finding "INFO" "tunnel" "检测到 bpftrace 可用 — 可用 lib/bpftrace_monitor.bt 做深度隧道定位" "" "sudo bpftrace lib/bpftrace_monitor.bt <target_ip>"
    fi
}

check_36() {
    section_header "36" "排查暴力破解 - SSH..."
    local LOG_FILE=""
    for f in /var/log/auth.log /var/log/secure; do [ -f "$f" ] && LOG_FILE="$f" && break; done
    [[ -z "$LOG_FILE" ]] && return
    local FAIL_COUNT; FAIL_COUNT=$(grep -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
    [[ "$FAIL_COUNT" -gt 20 ]] && log_finding "MED" "brute" "SSH 暴力破解 ($FAIL_COUNT 次失败)" "$LOG_FILE" "fail2ban + 封禁 IP"
    local BRUTE_IPS; BRUTE_IPS=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' | sort | uniq -c | sort -nr | head -5)
    [[ -n "$BRUTE_IPS" ]] && log_finding "LOW" "brute" "SSH 爆破源 IP 排行" "" "封禁 Top IP"
    local INVALID_USERS; INVALID_USERS=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | grep "invalid" | awk '{print $11}' | sort | uniq -c | sort -nr | head -5)
    [[ -n "$INVALID_USERS" ]] && log_finding "LOW" "brute" "被爆破的不存在用户名" "" "确认非合法用户"
    local SUCCESS_AFTER_BRUTE; SUCCESS_AFTER_BRUTE=$(grep "Failed password" "$LOG_FILE" 2>/dev/null | grep -Po '(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}' | sort | uniq -c | awk '$1>=20 {print $2}' | while read -r ip; do grep "Accepted" "$LOG_FILE" 2>/dev/null | grep -q "$ip" && echo "$ip"; done | head -1)
    [[ -n "$SUCCESS_AFTER_BRUTE" ]] && log_finding "CRIT" "brute" "SSH 爆破成功后入侵 ($SUCCESS_AFTER_BRUTE)" "" "立即封禁 + 改密码"
}

check_37() {
    section_header "37" "排查暴力破解 - 其他服务..."
    local MYSQL_LOG="/var/log/mysql/error.log"
    if [ -f "$MYSQL_LOG" ]; then
        local MYSQL_FAIL; MYSQL_FAIL=$(grep "Access denied" "$MYSQL_LOG" 2>/dev/null | wc -l)
        [[ "$MYSQL_FAIL" -gt 10 ]] && log_finding "MED" "brute" "MySQL 暴力破解 ($MYSQL_FAIL 次)" "$MYSQL_LOG" "检查 MySQL 密码策略"
    fi
    local FTP_LOG="/var/log/vsftpd.log"
    if [ -f "$FTP_LOG" ]; then
        local FTP_FAIL; FTP_FAIL=$(grep "FAIL" "$FTP_LOG" 2>/dev/null | wc -l)
        [[ "$FTP_FAIL" -gt 10 ]] && log_finding "MED" "brute" "FTP 暴力破解 ($FTP_FAIL 次)" "$FTP_LOG" "禁用 anonymous + fail2ban"
    fi
    local MONGO_LOG="/var/log/mongodb/mongodb.log"
    if [ -f "$MONGO_LOG" ]; then
        local MONGO_FAIL; MONGO_FAIL=$(grep -c "failed" "$MONGO_LOG" 2>/dev/null || echo 0)
        [[ "$MONGO_FAIL" -gt 10 ]] && log_finding "MED" "brute" "MongoDB 认证失败 ($MONGO_FAIL 次)" "$MONGO_LOG" "检查 MongoDB 认证配置"
    fi
    local MAIL_LOG="/var/log/mail.log"
    if [ -f "$MAIL_LOG" ]; then
        local MAIL_FAIL; MAIL_FAIL=$(grep -c "authentication failed" "$MAIL_LOG" 2>/dev/null || echo 0)
        [[ "$MAIL_FAIL" -gt 10 ]] && log_finding "MED" "brute" "SMTP 暴力破解 ($MAIL_FAIL 次)" "$MAIL_LOG" "检查 SMTP 认证配置"
    fi
    local REDIS_CHECK; REDIS_CHECK=$(ss -tlnp 2>/dev/null | grep ":6379" | head -1)
    if [[ -n "$REDIS_CHECK" ]] && echo "$REDIS_CHECK" | grep -q "0.0.0.0\|::"; then
        log_finding "HIGH" "brute" "Redis 对外开放 (可能未授权)" "" "bind 127.0.0.1 + requirepass"
    fi
}

# ============================================================
# 综合结论
# ============================================================
print_summary() {
    echo "" >&2
    bar "═" 70 >&2
    printf '%b                📊 综合分析结论%b\n' "$RED" "$NC" >&2
    bar "═" 70 >&2

    local FINAL FINAL_COLOR
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

    printf '\n' >&2
    printf '  主机:        %b%s%b %b(%s)%b\n' "$YEL" "$HOST" "$NC" "$CYN" "$IP" "$NC" >&2
    printf '  风险评分:    %b%s%b 分\n' "$RED" "$TOTAL_SCORE" "$NC" >&2
    printf '  风险等级:    %b%s%b\n' "$FINAL_COLOR" "$FINAL" "$NC" >&2
    printf '  发现数量:    %b%s%b 条\n' "$YEL" "${#FINDINGS[@]}" "$NC" >&2
    printf '  JSONL 日志:  %b%s%b\n' "$CYN" "$REPORT_JSONL" "$NC" >&2
    { printf '\n风险评分: %d\n风险等级: %s\n发现数量: %d\nJSONL: %s\n' "$TOTAL_SCORE" "$FINAL" "${#FINDINGS[@]}" "$REPORT_JSONL"; } >> "$REPORT_LOG" 2>/dev/null

    # 横向移动结论
    local EVIDENCE_COUNT; EVIDENCE_COUNT=${#LATERAL_EVIDENCE[@]}
    echo "" >&2
    bar "─" 70 >&2
    printf '%b            🎯 横向移动分析结论(必读)%b\n' "$RED" "$NC" >&2
    bar "─" 70 >&2

    if [ $EVIDENCE_COUNT -eq 0 ]; then
        printf '  %b✅ 未发现横向移动痕迹%b\n' "$GRN" "$NC" >&2
        echo "" >&2
        printf '  %b结论:%b 这台主机 %b大概率是初始入侵点%b 或 %b孤立失陷端%b。\n' "$YEL" "$NC" "$RED" "$NC" "$RED" "$NC" >&2
    elif [ $EVIDENCE_COUNT -le 2 ]; then
        printf '  %b⚠️  横向移动证据有限(%d 条)%b\n' "$YEL" "$EVIDENCE_COUNT" "$NC" >&2
        echo "" >&2
        for ev in "${LATERAL_EVIDENCE[@]}"; do printf '    %b%s%b\n' "$YEL" "$ev" "$NC" >&2; done
        echo "" >&2
        printf '  %b建议:%b 拉取 auth.log / .bash_history / 对同网段比对\n' "$YEL" "$NC" >&2
    else
        printf '  %b🔴 高度怀疑已发生横向移动(%d 条证据)%b\n' "$RED" "$EVIDENCE_COUNT" "$NC" >&2
        echo "" >&2
        printf '  %b证据链:%b\n' "$RED" "$NC" >&2
        for ev in "${LATERAL_EVIDENCE[@]}"; do printf '    %b%s%b\n' "$RED" "$ev" "$NC" >&2; done
        echo "" >&2
        if [ ${#LATERAL_TARGETS[@]} -gt 0 ]; then
            printf '  %b横向目标:%b\n' "$RED" "$NC" >&2
            for t in "${LATERAL_TARGETS[@]}"; do printf '    %b→ %s%b\n' "$RED" "$t" "$NC" >&2; done
            echo "" >&2
        fi
        printf '  %b结论: 这台主机已被攻击者用作跳板。%b\n' "$BRED" "$NC" >&2
        echo "" >&2
        printf '  %b立即行动:%b\n' "$RED" "$NC" >&2
        printf '    %b1.%b 立即隔离(iptables -I INPUT 1 -j DROP)\n' "$RED" "$NC" >&2
        printf '    %b2.%b 拉内存 dump (avml/LiME) + 磁盘镜像 (dd)\n' "$RED" "$NC" >&2
        printf '    %b3.%b 排查所有 authorized_keys 主机\n' "$RED" "$NC" >&2
        printf '    %b4.%b 排查 known_hosts 目标主机\n' "$RED" "$NC" >&2
        printf '    %b5.%b 排查 SSH 失败登录源 IP\n' "$RED" "$NC" >&2
        printf '    %b6.%b 全网段 SSH/计划任务/crontab 审计\n' "$RED" "$NC" >&2
    fi

    # 攻击路径时间线
    echo "" >&2
    bar "═" 70 >&2
    printf '%b          🛡️  攻击路径时间线 (v3.0)%b\n' "$RED" "$NC" >&2
    bar "═" 70 >&2
    echo "" >&2
    if [ ${#FINDINGS[@]} -eq 0 ]; then
        printf '  %b✅ 无 CRIT/HIGH/MED 发现,无可构建时间线%b\n' "$GRN" "$NC" >&2
    else
        printf '%b  发现 %d 条事件,按时间排序:%b\n\n' "$YEL" "${#FINDINGS[@]}" "$NC" >&2
        local TIMELINE; TIMELINE=$(printf '%s\n' "${FINDINGS[@]}" | grep -v '^|' | sort)
        local NO_TS; NO_TS=$(printf '%s\n' "${FINDINGS[@]}" | grep '^|')
        local SORTED; SORTED=$(printf '%s\n%s' "$TIMELINE" "$NO_TS" | grep -v '^$')
        local i=0
        while IFS='|' read -r ts level mod title file hint; do
            i=$((i+1))
            [[ -z "$ts" ]] && ts="未知时间"
            local ts_short; ts_short=$(echo "$ts" | cut -c1-16)
            local color tag
            color=$(level_to_color "$level")
            case "$level" in CRIT) tag="🔴" ;; HIGH) tag="🟠" ;; MED) tag="🟡" ;; *) tag="⚪" ;; esac
            printf '  %b[%d]%b %b%s%b %b%s%b\n' "$CYN" "$i" "$NC" "$color" "$ts_short" "$NC" "$color" "$level" "$NC" >&2
            printf '      %s\n' "$title" >&2
            [[ -n "$file" ]] && printf '      %b→%b %s\n' "$CYN" "$NC" "$file" >&2
            [[ -n "$hint" ]] && printf '      %b↪%b %s\n' "$CYN" "$NC" "$hint" >&2
        done <<< "$SORTED"
    fi

    # 全部发现项 (从 JSONL 读,用 awk 替代 python 消除隐藏依赖)
    echo "" >&2
    bar "─" 70 >&2
    printf '%b               📋 全部发现项%b\n' "$CYN" "$NC" >&2
    bar "─" 70 >&2
    local i=0
    while IFS= read -r line; do
        i=$((i+1))
        local level title score color
        level=$(echo "$line" | awk -F'"' '{for(j=1;j<=NF;j++) if($(j-1)=="level\":") {print $j; break}}')
        title=$(echo "$line" | awk -F'"' '{for(j=1;j<=NF;j++) if($(j-1)=="title\":") {print $j; break}}')
        score=$(echo "$line" | awk -F'"' '{for(j=1;j<=NF;j++) if($(j-1)=="score\":") {gsub(/[^0-9]/,"",$j); print $j; break}}')
        color=$(level_to_color "$level")
        printf '%b[%d] [%s +%s] %s%b\n' "$color" "$i" "$level" "$score" "$title" "$NC" >&2
    done < "$REPORT_JSONL" 2>/dev/null

    echo "" >&2
    printf '  %b报告完成:%b %s\n' "$CYN" "$NC" "$SCAN_TIME" >&2
    printf '  %bLog:%b   %s\n' "$CYN" "$NC" "$REPORT_LOG" >&2
    printf '  %bJSONL:%b %s\n' "$CYN" "$NC" "$REPORT_JSONL" >&2
    echo "" >&2
    { printf '\n报告完成: %s\nLog: %s\nJSONL: %s\n' "$SCAN_TIME" "$REPORT_LOG" "$REPORT_JSONL"; } >> "$REPORT_LOG" 2>/dev/null

    # 写 JSONL 汇总记录
    printf '{"ts":"%s","level":"SUMMARY","module":"conclusion","title":"风险评分=%d %s","file":"","hint":"发现%d条","score":%d}\n' \
        "$(date -Iseconds 2>/dev/null)" "$TOTAL_SCORE" "$FINAL" "${#FINDINGS[@]}" "$TOTAL_SCORE" >> "$REPORT_JSONL" 2>/dev/null
}

# ============================================================
# Main Dispatch
# ============================================================
ALL_CHECKS=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37)

if [[ -n "$RUN_MODULES" ]]; then
    RUN_CHECKS=()
    IFS=',' read -ra MODS <<< "$RUN_MODULES"
    for m in "${MODS[@]}"; do
        m=$(printf "%02d" "$m" 2>/dev/null)
        for c in "${ALL_CHECKS[@]}"; do
            [[ "$c" == "$m" ]] && RUN_CHECKS+=("$c")
        done
    done
else
    RUN_CHECKS=("${ALL_CHECKS[@]}")
fi

for c in "${RUN_CHECKS[@]}"; do
    if [[ $CHECK_TIMEOUT -gt 0 ]] && command -v timeout &>/dev/null; then
        timeout "$CHECK_TIMEOUT" "check_$c" 2>/dev/null
    else
        "check_$c"
    fi
done

print_summary
exit 0
