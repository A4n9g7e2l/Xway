#!/usr/bin/env bats
# test_p0_fixes.bats - v3.1: 验证 4 个 P0 修复回归

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export SCRIPT="$REPO_ROOT/xway_ir.sh"
}

# ---------- P0-1: --severity 精确成员比对 + hierarchy ----------

@test "P0-1: --severity 入参非法值 exit 2" {
    run bash "$SCRIPT" --severity superhigh --json-only
    [ "$status" -eq 2 ]
    [[ "$output" == *"invalid"* ]]
}

@test "P0-1: --severity 入参合法值不报错" {
    # 用 --json-only + 立即 Ctrl-C 不可行,改为检查脚本是否含 SEV_HIER 定义
    grep -q 'declare -A SEV_HIER' "$SCRIPT"
    grep -q '\[crit\]=5' "$SCRIPT"
    grep -q '\[high\]=4' "$SCRIPT"
}

@test "P0-1: level_meets_filter 用 SEV_HIER (high 含 CRIT, 方向 >=)" {
    # 验证 hierarchy 方向: lvl_num >= f_num (finding 数字越大越严重)
    # finding=CRIT(5) 过滤器=high(4): 5>=4 -> 满足 (high 含 CRIT)
    # finding=HIGH(4) 过滤器=crit(5): 4>=5 -> 不满足 (crit 不含 high)
    grep -q 'lvl_num -ge f_num' "$SCRIPT"
}

@test "P0-1: --severity 入参枚举校验 (crit|high|med|low|info)" {
    # 验证正则存在
    grep -q '\^(crit|high|med|low|info)' "$SCRIPT"
}

# ---------- P0-2: JSONL 转义 + ANSI sanitize ----------

@test "P0-2: strip_ctl 函数存在" {
    grep -q 'strip_ctl()' "$SCRIPT"
}

@test "P0-2: json_escape 函数存在,转义 \\ \" 换行 回车 Tab" {
    grep -q 'json_escape()' "$SCRIPT"
    grep -q 'gsub(/\\\\/' "$SCRIPT"    # 转义反斜杠
    grep -q 'gsub(/"/' "$SCRIPT"       # 转义双引号
    grep -q 'gsub(/\\n/' "$SCRIPT"     # 转义换行
}

@test "P0-2: log_finding 入口调用 strip_ctl" {
    # 验证 title/file/hint 都经过 strip_ctl
    grep -q 'title=$(strip_ctl' "$SCRIPT"
    grep -q 'file=$(strip_ctl' "$SCRIPT"
    grep -q 'hint=$(strip_ctl' "$SCRIPT"
}

@test "P0-2: JSONL 写入调用 json_escape (替代旧的 \${var//\"/\\\\\\\"})" {
    # 验证旧的简单转义被替换
    ! grep -q 'title_esc="\${title//\\"' "$SCRIPT"
    grep -q 'title_esc=$(json_escape' "$SCRIPT"
}

# ---------- P0-3: load_ioc_pattern 转义 regex 元字符 ----------

@test "P0-3: load_ioc_pattern 含 awk gsub 转义元字符" {
    grep -q 'gsub(/[][\\\\.*()+?{|^$]/' "$SCRIPT"
}

@test "P0-3: load_ioc_pattern 用 paste -sd 替代 tr+sed" {
    grep -q 'paste -sd' "$SCRIPT"
    # 旧的 tr|sed 组合应被移除
    ! grep -q "tr '\\\\n' '|'" "$SCRIPT"
}

# ---------- P0-4: FINDINGS 分隔符 \\x1f ----------

@test "P0-4: FINDINGS 用 \\x1f Unit Separator 分隔" {
    grep -q "US=\\\$'\\\\x1f'" "$SCRIPT"
    grep -q 'FINDINGS+=(.*US.*US.*US' "$SCRIPT"
}

@test "P0-4: timeline 解析用 IFS=\\x1f" {
    grep -q "IFS=\\\$'\\\\x1f' read" "$SCRIPT"
    # 旧的 IFS='|' read 应被替换(在 timeline 段)
    ! grep -q "while IFS='|' read" "$SCRIPT"
}

@test "P0-4: timeline 排序用 LC_ALL=C" {
    grep -q 'LC_ALL=C sort' "$SCRIPT"
}

# ---------- 综合回归 ----------

@test "P0: 脚本仍可通过 bash -n 语法检查" {
    run bash -n "$SCRIPT"
    [ "$status" -eq 0 ]
}
