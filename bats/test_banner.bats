#!/usr/bin/env bats
# test_banner.bats — v3.1: verify 45 modules, CLI flags, bug regressions

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export SCRIPT="$REPO_ROOT/xway_ir.sh"
}

@test "xway_ir.sh exists and has bash shebang" {
    [ -f "$SCRIPT" ]
    head -1 "$SCRIPT" | grep -q "^#!/bin/bash"
}

@test "xway_ir.sh has bash syntax (no -n errors)" {
    run bash -n "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "xway_ir.sh has 45 check functions" {
    count=$(grep -c '^check_[0-9]' "$SCRIPT")
    [ "$count" -eq 45 ]
}

@test "xway_ir.sh has 45 section_header calls" {
    count=$(grep -c 'section_header "[0-9]' "$SCRIPT")
    [ "$count" -eq 45 ]
}

@test "xway_ir.sh does NOT have CYAN typo" {
    ! grep -q '\${CYAN}' "$SCRIPT"
}

@test "xway_ir.sh supports --module flag" {
    grep -q -- '--module' "$SCRIPT"
}

@test "xway_ir.sh supports --severity flag" {
    grep -q -- '--severity' "$SCRIPT"
}

@test "xway_ir.sh supports --timeout flag" {
    grep -q -- '--timeout' "$SCRIPT"
}

@test "xway_ir.sh supports --no-color flag" {
    grep -q -- '--no-color' "$SCRIPT"
}

@test "xway_ir.sh supports --out-dir flag" {
    grep -q -- '--out-dir' "$SCRIPT"
}

@test "xway_ir.sh supports --json-only flag" {
    grep -q -- '--json-only' "$SCRIPT"
}

@test "xway_ir.sh has --help flag" {
    grep -q -- '--help' "$SCRIPT"
}

@test "xway_ir.sh writes REPORT_JSONL" {
    grep -q 'REPORT_JSONL=' "$SCRIPT"
}

@test "xway_ir.sh declares FINDINGS array" {
    grep -q 'declare -a FINDINGS' "$SCRIPT"
}

@test "xway_ir.sh has score_for_level function" {
    grep -q 'score_for_level()' "$SCRIPT"
}

@test "xway_ir.sh has level_to_color function" {
    grep -q 'level_to_color()' "$SCRIPT"
}

@test "xway_ir.sh has level_meets_filter function" {
    grep -q 'level_meets_filter()' "$SCRIPT"
}

@test "xway_ir.sh has ALL_CHECKS array with 45 entries" {
    grep -q 'ALL_CHECKS=' "$SCRIPT"
    count=$(grep 'ALL_CHECKS=' "$SCRIPT" | grep -o '[0-9][0-9]' | wc -l)
    [ "$count" -eq 45 ]
}

@test "xway_ir.sh has print_summary function" {
    grep -q 'print_summary()' "$SCRIPT"
}

@test "xway_ir.sh does NOT use python for JSONL parsing (bug fix)" {
    ! grep -q 'python -c.*json' "$SCRIPT"
}

@test "xway_ir.sh has attack path timeline" {
    grep -q '攻击路径时间线' "$SCRIPT"
}

@test "xway_ir.sh integrates SSH brute-force correlation" {
    grep -q 'SSH 爆破成功后入侵' "$SCRIPT"
}

@test "xway_ir.sh has tunnel detection module" {
    grep -q '隧道检测' "$SCRIPT"
}

@test "xway_ir.sh has PAM backdoor check" {
    grep -q 'PAM 后门' "$SCRIPT"
}

@test "xway_ir.sh has udev backdoor check" {
    grep -q 'udev 规则后门' "$SCRIPT"
}

@test "xway_ir.sh has Python .pth backdoor check" {
    grep -q 'Python .pth 后门' "$SCRIPT"
}

@test "xway_ir.sh has TCP Wrappers check" {
    grep -q 'TCP Wrappers' "$SCRIPT"
}

@test "xway_ir.sh has authorized_keys command= backdoor check" {
    grep -q 'command= 后门' "$SCRIPT"
}

@test "xway_ir.sh has hidden process check (proc vs ps)" {
    grep -q '隐藏进程' "$SCRIPT"
}

@test "xway_ir.sh has deleted process file check" {
    grep -q 'deleted 进程文件' "$SCRIPT"
}

@test "xway_ir.sh has password padding check" {
    grep -q '密码填充' "$SCRIPT"
}

@test "xway_ir.sh has UID=0 privilege check" {
    grep -q 'UID=0 特权账户' "$SCRIPT"
}

@test "xway_ir.sh has software integrity check" {
    grep -q '软件完整性' "$SCRIPT"
}

@test "xway_ir.sh has motd backdoor check" {
    grep -q 'motd 后门' "$SCRIPT"
}

@test "xway_ir.sh has capabilities check" {
    grep -q 'capabilities' "$SCRIPT"
}

@test "xway_ir.sh has ASLR/ptrace_scope check" {
    grep -q 'ptrace_scope' "$SCRIPT"
    grep -q 'ASLR' "$SCRIPT"
}

@test "xway_ir.sh references NOP Team cookbook" {
    grep -q 'NOP Team' "$SCRIPT"
}

@test "xway_ir.sh version is 3.1" {
    grep -q 'VERSION="3.1"' "$SCRIPT"
}

# ---------- v3.1 新增模块名 grep ----------

@test "xway_ir.sh has Web 内存马 check (v3.1)" {
    grep -q 'Web 内存马' "$SCRIPT"
}

@test "xway_ir.sh has Webshell 工具流量 check (v3.1)" {
    grep -q 'Webshell 工具流量' "$SCRIPT"
}

@test "xway_ir.sh has 网页暗链 check (v3.1)" {
    grep -q '网页暗链' "$SCRIPT"
}

@test "xway_ir.sh has 数据库 SQLi 痕迹 check (v3.1)" {
    grep -q '数据库 SQLi' "$SCRIPT"
}

@test "xway_ir.sh has 文件系统异常 check (v3.1)" {
    grep -q '文件系统异常' "$SCRIPT"
}

@test "xway_ir.sh has SSH 软连接后门 check (v3.1)" {
    grep -q 'SSH 软连接后门' "$SCRIPT"
}

@test "xway_ir.sh has strace 凭据捕获注入 check (v3.1)" {
    grep -q 'strace 凭据捕获注入' "$SCRIPT"
}

@test "xway_ir.sh has 登录痕迹聚合 check (v3.1)" {
    grep -q '登录痕迹聚合' "$SCRIPT"
}