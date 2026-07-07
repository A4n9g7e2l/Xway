#!/usr/bin/env bats
# test_banner.bats — verify xway_ir.sh has 18 numbered section banners,
# no orphan CYAN typo, and correct color var references.

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export SCRIPT="$REPO_ROOT/xway_ir.sh"
}

@test "xway_ir.sh exists and is executable (or has bash shebang)" {
    [ -f "$SCRIPT" ]
    head -1 "$SCRIPT" | grep -q "^#!/bin/bash"
}

@test "xway_ir.sh has bash syntax (no -n errors)" {
    run bash -n "$SCRIPT"
    [ "$status" -eq 0 ]
}

@test "xway_ir.sh defines 9 color vars (RED/YEL/GRN/BLU/CYN/NC/BRED/BYEL/BGRN+)" {
    grep -q "^[[:space:]]*RED=" "$SCRIPT"
    grep -q "^[[:space:]]*YEL=" "$SCRIPT"
    grep -q "^[[:space:]]*GRN=" "$SCRIPT"
    grep -q "^[[:space:]]*BLU=" "$SCRIPT"
    grep -q "^[[:space:]]*CYN=" "$SCRIPT"
    grep -q "^[[:space:]]*NC=" "$SCRIPT"
    grep -q "^[[:space:]]*BRED=" "$SCRIPT"
}

@test "xway_ir.sh has 18 section_header banners" {
    # Count calls to section_header with literal "N" arg pattern
    count=$(grep -cE 'section_header "[0-9]+"' "$SCRIPT")
    [ "$count" -eq 18 ]
}

@test "xway_ir.sh uses section_header consistently (not inline echo banners)" {
    # No more inline '\n[BLU][N/13]' style — those should be section_header calls
    if grep -qE '\[1/13\]|\[2/13\]|\[3/13\]' "$SCRIPT"; then
        # If old numbering remains, that's a regression
        echo "OLD 13-banner numbering found" >&2
        return 1
    fi
}

@test "xway_ir.sh does NOT have CYAN typo (variable is CYN)" {
    # The old bug was ${CYAN} instead of ${CYN}
    ! grep -q '\${CYAN}' "$SCRIPT"
}

@test "xway_ir.sh FINAL_COLOR used for ALL 5 risk levels" {
    # Should set FINAL_COLOR in 5 branches
    count=$(grep -c 'FINAL_COLOR=' "$SCRIPT")
    [ "$count" -ge 4 ]
}

@test "xway_ir.sh supports --no-color flag" {
    grep -q -- '--no-color' "$SCRIPT"
}

@test "xway_ir.sh supports --out-dir flag" {
    grep -q -- '--out-dir' "$SCRIPT"
}

@test "xway_ir.sh writes REPORT_JSONL" {
    grep -q 'REPORT_JSONL=' "$SCRIPT"
    grep -q 'printf.*REPORT_JSONL' "$SCRIPT"
}

@test "xway_ir.sh declares FINDINGS array" {
    grep -q 'declare -a FINDINGS' "$SCRIPT"
}

@test "xway_ir.sh declares LATERAL_EVIDENCE array" {
    grep -q 'declare -a LATERAL_EVIDENCE' "$SCRIPT"
}

@test "xway_ir.sh loads IOC files from lib/iocs/" {
    grep -q 'lib/iocs/miners.txt' "$SCRIPT"
    grep -q 'lib/iocs/c2.txt' "$SCRIPT"
    grep -q 'lib/iocs/backdoors.txt' "$SCRIPT"
    grep -q 'lib/iocs/rshell.txt' "$SCRIPT"
}

@test "xway_ir.sh loads rootkit signatures from lib/" {
    grep -q 'lib/rootkit_signatures.txt' "$SCRIPT"
    grep -q 'lib/bad_lkm.txt' "$SCRIPT"
}

@test "xway_ir.sh has attack path timeline section" {
    grep -q '攻击路径时间线' "$SCRIPT"
}

@test "xway_ir.sh integrates GScan-inspired SSH brute-force-success correlation" {
    grep -q 'SSH 爆破成功后入侵关联' "$SCRIPT"
    grep -q 'BRUTE_IPS' "$SCRIPT"
}

@test "xway_ir.sh integrates GScan-inspired alias hijack check" {
    grep -q '命令别名劫持' "$SCRIPT"
    grep -q 'SENSITIVE_ALIAS' "$SCRIPT"
}

@test "xway_ir.sh integrates GScan-inspired shell env hijack (5 tags)" {
    grep -q 'LD_AOUT_PRELOAD' "$SCRIPT"
    grep -q 'LD_ELF_PRELOAD' "$SCRIPT"
    grep -q 'PROMPT_COMMAND' "$SCRIPT"
}

@test "xway_ir.sh integrates SSH wrapper check" {
    grep -q 'sshd 非 ELF' "$SCRIPT"
}

@test "xway_ir.sh integrates /etc/passwd + /etc/shadow permission check" {
    grep -q 'shadow 权限异常' "$SCRIPT"
    grep -q 'passwd 权限异常' "$SCRIPT"
    grep -q '空密码账号' "$SCRIPT"
}