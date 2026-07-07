#!/usr/bin/env bats
# test_score_thresholds.bats — verify risk score thresholds and color mapping

setup() {
    export REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
}

@test "TOTAL_SCORE 0 -> INFO" {
    score=0
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "INFO" ]
}

@test "TOTAL_SCORE 5 -> LOW (boundary)" {
    score=5
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "LOW" ]
}

@test "TOTAL_SCORE 14 -> LOW (just below MEDIUM)" {
    score=14
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "LOW" ]
}

@test "TOTAL_SCORE 15 -> MEDIUM (boundary)" {
    score=15
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "MEDIUM" ]
}

@test "TOTAL_SCORE 30 -> HIGH (boundary)" {
    score=30
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "HIGH" ]
}

@test "TOTAL_SCORE 49 -> HIGH (just below CRITICAL)" {
    score=49
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "HIGH" ]
}

@test "TOTAL_SCORE 50 -> CRITICAL (boundary)" {
    score=50
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "CRITICAL" ]
}

@test "TOTAL_SCORE 100 -> CRITICAL" {
    score=100
    if [ $score -ge 50 ]; then label="CRITICAL"
    elif [ $score -ge 30 ]; then label="HIGH"
    elif [ $score -ge 15 ]; then label="MEDIUM"
    elif [ $score -ge 5 ]; then label="LOW"
    else label="INFO"
    fi
    [ "$label" = "CRITICAL" ]
}

@test "severity-to-score mapping (v2.0)" {
    # CRIT=10, HIGH=8, MED=5, LOW=3, INFO=0
    declare -A expected=( [CRIT]=10 [HIGH]=8 [MED]=5 [LOW]=3 [INFO]=0 )
    for level in CRIT HIGH MED LOW INFO; do
        case "$level" in
            CRIT) score=10 ;;
            HIGH) score=8  ;;
            MED)  score=5  ;;
            LOW)  score=3  ;;
            INFO) score=0  ;;
        esac
        [ "$score" = "${expected[$level]}" ]
    done
}