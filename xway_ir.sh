#!/bin/bash
# ============================================================
# xway_ir.sh - Linux 失陷主机一键应急排查
# 输出:纯命令行可视化(无 HTML/TXT 文件)
# ============================================================
set +e

# 颜色
RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'; BLU='\033[1;34m'; CYN='\033[1;36m'; NC='\033[0m'; BRED='\033[41;97m'; BYEL='\033[43;30m'

HOST=$(hostname 2>/dev/null || echo unknown)
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo unknown)
KERNEL=$(uname -r 2>/dev/null || echo unknown)
SCAN_TIME=$(date '+%Y-%m-%d %H:%M:%S')

TOTAL_SCORE=0
declare -a FINDINGS

add_finding() {  # title|detail|score|level
    TOTAL_SCORE=$((TOTAL_SCORE + $3))
    FINDINGS+=("$1|$2|$3|$4")
}

bar() {
    local char="$1"; local len=$2
    local s=""
    for ((i=0; i<len; i++)); do s+="$char"; done
    echo "$s"
}

# 顶部 Banner
clear 2>/dev/null
echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}        ${RED}🛡️  XWAY 蓝队应急响应 — Linux 失陷主机排查${NC}                  ${RED}║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYN}主机:${NC} ${YEL}$HOST${NC} ${CYN}($IP)${NC}    ${CYN}内核:${NC} ${YEL}$KERNEL${NC}"
echo -e "  ${CYN}扫描时间:${NC} ${YEL}$SCAN_TIME${NC}"
echo ""
bar "─" 70

# ============================================================
echo -e "\n${BLU}[1/13]${NC} ${YEL}排查可疑进程...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
SUSP_PROCS=$(ps auxww 2>/dev/null | grep -iE "xmrig|minerd|cpuminer|kinsing|ddg|xor|monero|minergate|stratum|hashvault|nicehash|ksoftirdfs|c3pool|cryptonight" | grep -v grep | head -5)
[ -n "$SUSP_PROCS" ] && add_finding "🔴 挖矿/僵尸进程" "$SUSP_PROCS" 10 "Critical" && echo -e "${RED}  [!] 发现挖矿进程:${NC}\n${RED}$SUSP_PROCS${NC}"

SUSP_PARENT=$(ps auxww 2>/dev/null | awk '$11 ~ /(bash|sh|python|perl|php)$/ {print}' | grep -E "www-data|apache|nobody|nginx|httpd|mysql" | head -3)
[ -n "$SUSP_PARENT" ] && add_finding "🟠 Web 进程派生 Shell(RCE)" "$SUSP_PARENT" 9 "Critical" && echo -e "${RED}  [!] Web 进程衍生 Shell:${NC}\n${RED}$SUSP_PARENT${NC}"

EVAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "eval\(|exec\(|base64 -d|wget http|curl http|chmod \+x" | grep -v grep | head -3)
[ -n "$EVAL_PROCS" ] && add_finding "🟠 可疑执行命令" "$EVAL_PROCS" 8 "High" && echo -e "${YEL}  [!] 可疑执行命令:${NC}\n${YEL}$EVAL_PROCS${NC}"

# ============================================================
echo -e "\n${BLU}[2/13]${NC} ${YEL}排查网络外联...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
EXT_CONN=$(ss -antp 2>/dev/null | grep -v "LISTEN" | grep -E ":4444|:5555|:6666|:1337|:8888|:31337|:1080|:1081|:8443" | head -5)
[ -n "$EXT_CONN" ] && add_finding "🟠 可疑端口外联" "$EXT_CONN" 8 "High" && echo -e "${YEL}  [!] 可疑端口:${NC}\n${YEL}$EXT_CONN${NC}"

ESTAB=$(ss -antp 2>/dev/null | awk '$1=="ESTAB" {print}' | grep -v ":22\|:80\|:443\|:53" | head -10)
[ -n "$ESTAB" ] && add_finding "🟠 异常已建立连接" "$ESTAB" 7 "High" && echo -e "${YEL}  [!] 异常连接:${NC}\n${YEL}$ESTAB${NC}"

# ============================================================
echo -e "\n${BLU}[3/13]${NC} ${YEL}排查启动项/计划任务...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
CRON=$(crontab -l 2>/dev/null | grep -vE "^#|^$" | head -5)
[ -n "$CRON" ] && add_finding "🟡 Crontab 配置" "$CRON" 5 "Medium" && echo -e "${YEL}  [i] Crontab 内容:${NC}\n${YEL}$CRON${NC}"

SUSP_CRON=$(cat /etc/crontab 2>/dev/null | grep -vE "^#|^$" | grep -iE "wget|curl|base64|nc |/tmp/" | head -3)
[ -n "$SUSP_CRON" ] && add_finding "🔴 可疑系统 crontab" "$SUSP_CRON" 9 "Critical" && echo -e "${RED}  [!] 系统 crontab 可疑:${NC}\n${RED}$SUSP_CRON${NC}"

SUSP_SVC=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -iE "miner|backdoor|update|cron|shell" | head -5)
[ -n "$SUSP_SVC" ] && add_finding "🟠 可疑 systemd 服务" "$SUSP_SVC" 7 "High" && echo -e "${YEL}  [!] 可疑服务:${NC}\n${YEL}$SUSP_SVC${NC}"

# ============================================================
echo -e "\n${BLU}[4/13]${NC} ${YEL}检测内核 Rootkit...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
MODULES=$(lsmod 2>/dev/null | grep -iE "diamorphine|reptile|suterusu|adore" | head -3)
[ -n "$MODULES" ] && add_finding "🔴 Rootkit 内核模块" "$MODULES" 10 "Critical" && echo -e "${RED}  [!] Rootkit 模块:${NC}\n${RED}$MODULES${NC}"

LD_PRELOAD=$(cat /etc/ld.so.preload 2>/dev/null)
[ -n "$LD_PRELOAD" ] && add_finding "🔴 LD_PRELOAD 劫持" "$LD_PRELOAD" 10 "Critical" && echo -e "${RED}  [!] /etc/ld.so.preload 被劫持:${NC}\n${RED}$LD_PRELOAD${NC}"

# ============================================================
echo -e "\n${BLU}[5/13]${NC} ${YEL}排查 SUID/SGID...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
SUID_RECENT=$(find / -perm /4000 -mtime -30 -type f 2>/dev/null | head -5)
[ -n "$SUID_RECENT" ] && add_finding "🔴 30 天内新增 SUID" "$SUID_RECENT" 9 "Critical" && echo -e "${RED}  [!] 新增 SUID:${NC}\n${RED}$SUID_RECENT${NC}"

# ============================================================
echo -e "\n${BLU}[6/13]${NC} ${YEL}排查敏感文件变化...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
RECENT=$(find /etc /usr/local /opt /root /tmp -mtime -7 -type f 2>/dev/null | grep -vE "/proc|/sys|\.log$|\.sock$" | head -10)
[ -n "$RECENT" ] && add_finding "🟢 7天内修改文件" "$RECENT" 3 "Low" && echo -e "${GRN}  [i] 近期修改(前10):${NC}\n${GRN}$RECENT${NC}"

# ============================================================
echo -e "\n${BLU}[7/13]${NC} ${YEL}排查 Webshell...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
WS=$(find /var/www /usr/share/nginx /home /root -type f \( -name "*.php" -o -name "*.jsp" \) 2>/dev/null | grep -iE "[0-9]{1,4}\.(php|jsp)$|[a-z]{1,3}[0-9]{4,}\.(php|jsp)$" | head -5)
[ -n "$WS" ] && add_finding "🔴 数字命名 PHP/JSP" "$WS" 9 "Critical" && echo -e "${RED}  [!] 可疑文件:${NC}\n${RED}$WS${NC}"

# 排除安全研究人员的资料库(POC/Templates/skills/training),这些是合法文件
# 实际生产环境的 Webshell 都在 /var/www /usr/share/nginx /root 等路径
WSHELL=$(grep -rE "eval\(\\\$_POST|eval\(\\\$_GET|assert\(\\\$_POST|system\(\\\$_POST|passthru\(\\\$_POST" /var/www /root 2>/dev/null \
    | grep -viE "/(nuclei-templates|nuclei-templates-2)\.|\.hermes/skills/|/training/ctf/|/htb/|/thm/|/oscp/" \
    | head -5)
[ -n "$WSHELL" ] && add_finding "🔴 PHP 一句话后门" "$WSHELL" 10 "Critical" && echo -e "${RED}  [!] 一句话特征:${NC}\n${RED}$WSHELL${NC}"

# ============================================================
echo -e "\n${BLU}[8/13]${NC} ${YEL}排查挖矿特征...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
HIGH_CPU=$(ps auxww 2>/dev/null | sort -k3 -nr | head -5 | awk '$3+0 > 30 {print}')
[ -n "$HIGH_CPU" ] && add_finding "🟠 高 CPU 进程(挖矿)" "$HIGH_CPU" 8 "High" && echo -e "${YEL}  [!] 高 CPU 进程:${NC}\n${YEL}$HIGH_CPU${NC}"

# 挖矿配置 grep 排除 NTP 池(chrony.conf / systemd-timesyncd 等)和常见系统配置
# 真实矿池配置通常在 /tmp /var/tmp /opt /root /home 下,文件名多含 miner/xmrig/c3pool
MINER_CFG=$(find /tmp /var/tmp /opt /root /home -type f \( -name "config.json" -o -name "*.conf" -o -name "config.txt" -o -name "pools.txt" \) 2>/dev/null \
    | xargs grep -lE "stratum\+tcp|xmrig|c3pool|moneroocean|nicehash|hashvault|miningrigrentals|cryptonight" 2>/dev/null \
    | head -3)
[ -n "$MINER_CFG" ] && add_finding "🔴 挖矿配置文件" "$MINER_CFG" 10 "Critical" && echo -e "${RED}  [!] 挖矿配置:${NC}\n${RED}$MINER_CFG${NC}"

# ============================================================
echo -e "\n${BLU}[9/13]${NC} ${YEL}排查可疑文件位置...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
TMP_EXEC=$(find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null | head -10)
[ -n "$TMP_EXEC" ] && add_finding "🟠 临时目录可执行文件" "$TMP_EXEC" 7 "High" && echo -e "${YEL}  [!] /tmp 可执行文件:${NC}\n${YEL}$TMP_EXEC${NC}"

DIGIT_LIB=$(find / -type f \( -name "[0-9][0-9].so" -o -name "[0-9][0-9].dll" \) 2>/dev/null | head -5)
[ -n "$DIGIT_LIB" ] && add_finding "🔴 数字命名 so/dll(银狐)" "$DIGIT_LIB" 9 "Critical" && echo -e "${RED}  [!] 银狐特征:${NC}\n${RED}$DIGIT_LIB${NC}"

# ============================================================
echo -e "\n${BLU}[10/13]${NC} ${YEL}排查横向移动(关键)...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
declare -a LATERAL_EVIDENCE
declare -a LATERAL_TARGETS

# 10.1 SSH 公钥
for home in /root /home/*; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        KEYS=$(cat "$home/.ssh/authorized_keys" 2>/dev/null)
        SUSP=$(echo "$KEYS" | grep -vE "^#|^$|@$|company|backup" | head -3)
        if [ -n "$SUSP" ]; then
            LATERAL_EVIDENCE+=("[!] authorized_keys 含可疑公钥($home)")
            LATERAL_TARGETS+=("$home")
            add_finding "🔴 SSH 公钥植入($home)" "$SUSP" 9 "Critical"
            echo -e "${RED}  [!] $home/.ssh/authorized_keys 异常:${NC}\n${RED}$SUSP${NC}"
        fi
    fi
done

# 10.2 known_hosts(连过的内网主机)
KNOWN=$(cat /root/.ssh/known_hosts 2>/dev/null | awk '{print $1}' | head -10)
[ -n "$KNOWN" ] && {
    LATERAL_TARGETS+=("$KNOWN")
    echo -e "${YEL}  [i] known_hosts(连过):${NC}\n${YEL}$KNOWN${NC}"
}

# 10.3 SSH 失败登录(爆破痕迹)
SSH_BRUTE=""
for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [ -f "$f" ] && SSH_BRUTE=$(grep -E "Failed password|Invalid user|authentication failure" "$f" 2>/dev/null | tail -20)
done
SSH_FAILED_COUNT=$(echo "$SSH_BRUTE" | grep -c . 2>/dev/null)
if [ "$SSH_FAILED_COUNT" -gt 0 ]; then
    LATERAL_EVIDENCE+=("[!] SSH 失败登录 $SSH_FAILED_COUNT 次")
    [ "$SSH_FAILED_COUNT" -gt 20 ] && SCORE=7 || SCORE=3
    add_finding "🟡 SSH 失败登录($SSH_FAILED_COUNT 次)" "$(echo "$SSH_BRUTE" | tail -10)" $SCORE "Medium"
    echo -e "${YEL}  [i] SSH 失败登录(近 10 条):${NC}\n${YEL}$(echo "$SSH_BRUTE" | tail -10)${NC}"
fi

# 10.4 SSH 成功登录
SSH_SUCCESS=""
for f in /var/log/auth.log /var/log/secure; do
    [ -f "$f" ] && SSH_SUCCESS=$(grep -E "Accepted password|Accepted publickey" "$f" 2>/dev/null | tail -10)
done
[ -n "$SSH_SUCCESS" ] && {
    LATERAL_EVIDENCE+=("[!] SSH 成功登录记录 $(echo "$SSH_SUCCESS" | wc -l) 条")
    add_finding "🟡 SSH 成功登录" "$SSH_SUCCESS" 5 "Medium"
    echo -e "${YEL}  [i] SSH 成功登录(近 10):${NC}\n${YEL}$SSH_SUCCESS${NC}"
}

# 10.5 /etc/hosts 篡改
HOSTS=$(cat /etc/hosts 2>/dev/null | grep -vE "^#|^$|localhost|ip6-")
SUSP_HOSTS=$(echo "$HOSTS" | grep -iE "\.(tk|top|xyz|gq|cyou|onion)")
if [ -n "$SUSP_HOSTS" ]; then
    LATERAL_EVIDENCE+=("[!] /etc/hosts 含可疑域名劫持")
    add_finding "🟠 /etc/hosts 可疑劫持" "$HOSTS" 8 "High"
    echo -e "${RED}  [!] /etc/hosts 异常:${NC}\n${RED}$HOSTS${NC}"
fi

# 10.6 横向扫描工具
SCAN_TOOLS=$(find / -type f \( -name "nmap" -o -name "masscan" -o -name "hydra" -o -name "medusa" \) 2>/dev/null | grep -vE "/usr/bin|/usr/share|/snap" | head -3)
[ -n "$SCAN_TOOLS" ] && {
    LATERAL_EVIDENCE+=("[!] 发现横向扫描工具: $SCAN_TOOLS")
    add_finding "🟠 横向扫描工具" "$SCAN_TOOLS" 8 "High"
    echo -e "${RED}  [!] 扫描工具:${NC}\n${RED}$SCAN_TOOLS${NC}"
}

# 10.7 横向移动进程
LATERAL_PROCS=$(ps auxww 2>/dev/null | grep -iE "ssh -R|ssh -D|ssh -L|nc -l|socat.*exec" | grep -v grep | head -3)
[ -n "$LATERAL_PROCS" ] && {
    LATERAL_EVIDENCE+=("[!] 横向移动进程运行中")
    add_finding "🔴 SSH 隧道 / nc 反向" "$LATERAL_PROCS" 9 "Critical"
    echo -e "${RED}  [!] 横向移动进程:${NC}\n${RED}$LATERAL_PROCS${NC}"
}

# 10.8 异常账号
WEIRD=$(awk -F: '$3 < 1000 && $3 != 0 {print}' /etc/passwd 2>/dev/null)
[ -n "$WEIRD" ] && {
    LATERAL_EVIDENCE+=("[!] 异常 UID < 1000 账号: $WEIRD")
    add_finding "🟡 异常账号(UID<1000)" "$WEIRD" 5 "Medium"
    echo -e "${YEL}  [!] 异常账号:${NC}\n${YEL}$WEIRD${NC}"
}

# 10.9 最近 SSH 登录用户
LAST=$(last -n 20 -i 2>/dev/null | head -20)
[ -n "$LAST" ] && {
    echo -e "${YEL}  [i] 最近 20 条 SSH 登录:${NC}\n${YEL}$LAST${NC}"
}

# ============================================================
echo -e "\n${BLU}[11/13]${NC} ${YEL}排查 Java 内存马...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
SUSP_JAR=$(find / -name "*.jar" -mtime -30 2>/dev/null | grep -iE "memshell|agent|evil|hack" | head -3)
[ -n "$SUSP_JAR" ] && add_finding "🔴 可疑 Java JAR(内存马)" "$SUSP_JAR" 9 "Critical" && echo -e "${RED}  [!] 可疑 JAR:${NC}\n${RED}$SUSP_JAR${NC}"

TOMCAT_WEB=$(find / -path "*/webapps/*" -name "*.jsp" -mtime -30 2>/dev/null | head -3)
[ -n "$TOMCAT_WEB" ] && {
    add_finding "🟡 Tomcat 近期 JSP" "$TOMCAT_WEB" 5 "Medium"
    echo -e "${YEL}  [!] 近期 JSP:${NC}\n${YEL}$TOMCAT_WEB${NC}"
}

# ============================================================
echo -e "\n${BLU}[12/13]${NC} ${YEL}排查提权痕迹...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
SUDOERS=$(grep -vE "^#|^$|root\s+ALL" /etc/sudoers 2>/dev/null | head -5)
[ -n "$SUDOERS" ] && {
    add_finding "🟡 Sudoers 异常" "$SUDOERS" 5 "Medium"
    echo -e "${YEL}  [!] Sudoers 异常配置:${NC}\n${YEL}$SUDOERS${NC}"
}

# ============================================================
echo -e "\n${BLU}[13/13]${NC} ${YEL}容器环境检测...${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    echo -e "  ${GRN}[i] 当前在 Docker 容器内${NC}"
fi

# ============================================================
# 综合结论(顶部风险 + 横向移动)
# ============================================================
echo ""
bar "═" 70
echo -e "${RED}                📊 综合分析结论${NC}"
bar "═" 70

# 风险等级
if [ $TOTAL_SCORE -ge 50 ]; then
    FINAL="🔴 CRITICAL — 高危失陷"
    FINAL_COLOR=$BRED
elif [ $TOTAL_SCORE -ge 30 ]; then
    FINAL="🟠 HIGH — 中危失陷"
    FINAL_COLOR=$BYEL
elif [ $TOTAL_SCORE -ge 15 ]; then
    FINAL="🟡 MEDIUM — 可疑"
elif [ $TOTAL_SCORE -ge 5 ]; then
    FINAL="🟢 LOW — 低危"
else
    FINAL="⚪ INFO — 暂未发现失陷"
fi

echo -e ""
echo -e "  主机:        ${YEL}$HOST${NC} ${CYN}($IP)${NC}"
echo -e "  风险评分:    ${RED}$TOTAL_SCORE${NC} 分"
echo -e "  风险等级:    ${FINAL_COLOR}$FINAL${NC}"
echo -e "  发现数量:    ${YEL}${#FINDINGS[@]}${NC} 条"

# 横向移动结论
EVIDENCE_COUNT=${#LATERAL_EVIDENCE[@]}
echo ""
bar "─" 70
echo -e "${RED}            🎯 横向移动分析结论(必读)${NC}"
bar "─" 70
echo ""

if [ $EVIDENCE_COUNT -eq 0 ]; then
    echo -e "  ${GRN}✅ 未发现横向移动痕迹${NC}"
    echo ""
    echo -e "  检测项目:"
    echo -e "    ${GRN}[OK]${NC} authorized_keys 干净"
    echo -e "    ${GRN}[OK]${NC} SSH 失败登录 < 20 次(无爆破)"
    echo -e "    ${GRN}[OK]${NC} /etc/hosts 无劫持"
    echo -e "    ${GRN}[OK]${NC} 无横向扫描工具残留"
    echo -e "    ${GRN}[OK]${NC} 无 SSH 隧道/nc 反向进程"
    echo ""
    echo -e "  ${YEL}结论:${NC} 这台主机 ${RED}大概率是初始入侵点${NC} 或 ${RED}孤立失陷端${NC},"
    echo -e "        尚未对其他内网主机发起攻击。"
elif [ $EVIDENCE_COUNT -le 2 ]; then
    echo -e "  ${YEL}⚠️ 横向移动证据有限($EVIDENCE_COUNT 条)${NC}"
    echo ""
    for ev in "${LATERAL_EVIDENCE[@]}"; do
        echo -e "    ${YEL}$ev${NC}"
    done
    echo ""
    echo -e "  ${YEL}结论:${NC} 发现少量可疑痕迹,但不足以判断成熟横向移动。"
    echo -e "  ${YEL}建议:${NC}"
    echo -e "    1. 拉取 auth.log / secure 完整记录"
    echo -e "    2. 检查 /root/.bash_history 找命令轨迹"
    echo -e "    3. 对同网段主机跑 SSH 登录日志比对"
else
    echo -e "  ${RED}🔴 高度怀疑已发生横向移动(${RED}$EVIDENCE_COUNT${NC}${RED} 条证据)${NC}"
    echo ""
    echo -e "  ${RED}证据链:${NC}"
    for ev in "${LATERAL_EVIDENCE[@]}"; do
        echo -e "    ${RED}$ev${NC}"
    done
    echo ""
    if [ ${#LATERAL_TARGETS[@]} -gt 0 ]; then
        echo -e "  ${RED}横向目标(本机连过/被植入):${NC}"
        for t in "${LATERAL_TARGETS[@]}"; do
            echo -e "    ${RED}→ $t${NC}"
        done
        echo ""
    fi
    echo -e "  ${RED}结论:${NC} 这台主机 ${BRED}已被攻击者用作跳板${NC}${RED},已对内网其他主机发起攻击。${NC}"
    echo ""
    echo -e "  ${RED}立即行动:${NC}"
    echo -e "    ${RED}1.${NC} 立即隔离本机(拔网线或 iptables -I INPUT 1 -j DROP)"
    echo -e "    ${RED}2.${NC} 拉内存 dump(avml / LiME),再磁盘镜像(dd)"
    echo -e "    ${RED}3.${NC} 对所有 authorized_keys 含公钥的主机全部排查"
    echo -e "    ${RED}4.${NC} 对 known_hosts 列表中的目标主机排查"
    echo -e "    ${RED}5.${NC} 对 SSH 失败登录源 IP 排查"
    echo -e "    ${RED}6.${NC} 全网段 SSH 公钥 / 计划任务 / crontab 批量审计"
fi

# 完整 findings 列表(末尾)
echo ""
bar "─" 70
echo -e "${CYN}               📋 全部发现项${NC}"
bar "─" 70
i=0
for f in "${FINDINGS[@]}"; do
    i=$((i+1))
    IFS='|' read -r title detail score level <<< "$f"
    case $level in
        Critical) COLOR=$RED ;;
        High) COLOR=$YEL ;;
        Medium) COLOR=$YEL ;;
        Low) COLOR=$GRN ;;
        Info) COLOR=$CYN ;;
        *) COLOR=$NC ;;
    esac
    echo -e "${COLOR}[$i] [$level +$score] $title${NC}"
done

echo ""
echo -e "  ${CYAN}报告完成: $SCAN_TIME${NC}"
echo ""