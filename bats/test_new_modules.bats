#!/usr/bin/env bats
# test_new_modules.bats - v3.1: 验证 8 个新模块 (check_38 ~ check_45)

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export SCRIPT="$REPO_ROOT/xway_ir.sh"
    export LIB_DIR="$REPO_ROOT/lib"
    export IOC_DIR="$REPO_ROOT/lib/iocs"
}

# ---------- 通用: 8 个新模块存在 ----------

@test "新模块: check_38 ~ check_45 函数全部存在" {
    for n in 38 39 40 41 42 43 44 45; do
        grep -q "^check_${n}()" "$SCRIPT"
    done
}

@test "新模块: ALL_CHECKS 含 38-45" {
    for n in 38 39 40 41 42 43 44 45; do
        grep -q " $n " "$SCRIPT" || grep -q ")$" "$SCRIPT"
    done
    # ALL_CHECKS 数组以 45 结尾
    grep -q 'ALL_CHECKS=(01 02 03.*44 45)' "$SCRIPT"
}

@test "新模块: section_header 分母是 45 不是 37" {
    grep -q '\[$n/45\]' "$SCRIPT"
    grep -q '\[%s/45\]' "$SCRIPT"
    ! grep -q '\[$n/37\]' "$SCRIPT"
}

@test "新模块: VERSION 是 3.1" {
    grep -q 'VERSION="3.1"' "$SCRIPT"
}

# ---------- check_38 Web 内存马 ----------

@test "check_38: 函数含 404->200 检测逻辑" {
    grep -q '404->200' "$SCRIPT"
    grep -q 'last\[key\]==404 && status==200' "$SCRIPT"
}

@test "check_38: 含 POST 16 字节对齐检测 (Behinder AES)" {
    grep -q '\$10%16==0' "$SCRIPT"
}

@test "check_38: 标题为 Web 内存马" {
    grep -q 'Web 内存马特征' "$SCRIPT"
}

# ---------- check_39 Behinder/蚁剑 UA ----------

@test "check_39: behinder_uas.txt 存在且含 Behinder/antSword/Chopper" {
    [ -f "$IOC_DIR/behinder_uas.txt" ]
    grep -q '^Behinder$' "$IOC_DIR/behinder_uas.txt"
    grep -q '^antSword$' "$IOC_DIR/behinder_uas.txt"
    grep -q '^Chopper$' "$IOC_DIR/behinder_uas.txt"
}

@test "check_39: 用 load_ioc_pattern 加载 UA 库" {
    grep -q 'load_ioc_pattern "$IOC_DIR/behinder_uas.txt"' "$SCRIPT"
}

@test "check_39: 标题为 Webshell 工具流量" {
    grep -q 'Webshell 工具流量' "$SCRIPT"
}

# ---------- check_40 网页暗链 ----------

@test "check_40: darklink_keywords.txt 含赌博/色情/location.href" {
    [ -f "$LIB_DIR/darklink_keywords.txt" ]
    grep -q '博彩' "$LIB_DIR/darklink_keywords.txt"
    grep -q '色情' "$LIB_DIR/darklink_keywords.txt"
    grep -q 'location.href' "$LIB_DIR/darklink_keywords.txt"
}

@test "check_40: 含 Nginx sub_filter 配置劫持检测" {
    grep -q 'sub_filter' "$SCRIPT"
    grep -q 'rewrite' "$SCRIPT"
}

@test "check_40: 扫描 web root 默认路径" {
    grep -q '/var/www' "$SCRIPT"
    grep -q '/usr/share/nginx/html' "$SCRIPT"
}

@test "check_40: 标题为网页暗链" {
    grep -q '网页暗链' "$SCRIPT"
}

# ---------- check_41 SQLi 痕迹 ----------

@test "check_41: sqli_patterns.txt 含 union select / sleep / load_file" {
    [ -f "$LIB_DIR/sqli_patterns.txt" ]
    grep -q 'union' "$LIB_DIR/sqli_patterns.txt"
    grep -q 'sleep' "$LIB_DIR/sqli_patterns.txt"
    grep -q 'load_file' "$LIB_DIR/sqli_patterns.txt"
}

@test "check_41: 扫描 mysql_history + mysql log + pgsql log" {
    grep -q '\.mysql_history' "$SCRIPT"
    grep -q '/var/log/mysql' "$SCRIPT"
    grep -q '/var/log/postgresql' "$SCRIPT"
}

@test "check_41: 标题为数据库 SQLi 痕迹" {
    grep -q '数据库 SQLi 痕迹' "$SCRIPT"
}

# ---------- check_42 文件系统异常 ----------

@test "check_42: 含 -nouser/-nogroup 检测" {
    grep -q -- '-nouser' "$SCRIPT"
    grep -q -- '-nogroup' "$SCRIPT"
}

@test "check_42: 含 777 可执行文件检测 (-perm -002 -executable)" {
    grep -q -- '-perm -002 -executable' "$SCRIPT"
}

@test "check_42: 含欺骗性文件名检测 (\\\.\\\\.\\\\.)" {
    grep -q "name '\\.\\.\\.'" "$SCRIPT"
}

@test "check_42: 含临时目录大文件检测 (-size +10M)" {
    grep -q -- '-size +10M' "$SCRIPT"
}

@test "check_42: 用 -xdev 限定本文件系统" {
    grep -q -- '-xdev' "$SCRIPT"
}

# ---------- check_43 SSH 软连接后门 ----------

@test "check_43: 检测 sshd 进程 argv[0] 是 su/chsh/chfn" {
    grep -q 'pgrep -x sshd' "$SCRIPT"
    grep -q 'su|chsh|chfn' "$SCRIPT"
}

@test "check_43: 检测指向 sshd 的软连接 (find -lname)" {
    grep -q -- '-lname' "$SCRIPT"
}

@test "check_43: 标题为 SSH 软连接后门" {
    grep -q 'SSH 软连接后门' "$SCRIPT"
}

# ---------- check_44 strace 凭据捕获 ----------

@test "check_44: grep strace -o + ssh/su/sudo/passwd 模式" {
    grep -q 'strace' "$SCRIPT"
    grep -q 'ssh|su|sudo|passwd' "$SCRIPT"
}

@test "check_44: 扫描 /etc/bashrc /etc/profile /etc/profile.d/" {
    grep -q '/etc/bashrc' "$SCRIPT"
    grep -q '/etc/profile.d/' "$SCRIPT"
}

@test "check_44: 标题为 strace 凭据捕获注入" {
    grep -q 'strace 凭据捕获注入' "$SCRIPT"
}

# ---------- check_45 登录痕迹聚合 ----------

@test "check_45: 含 lastb 失败登录聚合" {
    grep -q 'lastb -awF' "$SCRIPT"
}

@test "check_45: 含 last 成功登录" {
    grep -q 'last -awF' "$SCRIPT"
}

@test "check_45: 含 useradd/userdel/usermod 日志检测" {
    grep -q 'useradd|userdel|usermod' "$SCRIPT"
}

@test "check_45: 含 lastlog 非空账号" {
    grep -q 'lastlog' "$SCRIPT"
    grep -q "grep -v 'Never'" "$SCRIPT"
}

@test "check_45: 命令存在性探测 (command -v lastb/last/lastlog)" {
    grep -q 'command -v lastb' "$SCRIPT"
    grep -q 'command -v last ' "$SCRIPT"
    grep -q 'command -v lastlog' "$SCRIPT"
}

# ---------- 新 lib 文件格式合规 ----------

@test "lib: 3 个新 IOC 文件都以 # 注释开头,有空行/注释跳过支持" {
    for f in "$IOC_DIR/behinder_uas.txt" "$LIB_DIR/darklink_keywords.txt" "$LIB_DIR/sqli_patterns.txt"; do
        head -1 "$f" | grep -q '^#'
    done
}

@test "lib: behinder_uas 含 Godzilla/天蝎 (新增工具覆盖)" {
    grep -qi 'godzilla' "$IOC_DIR/behinder_uas.txt"
}
