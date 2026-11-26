# The suite each run of a TLS example must reach (docs/design.md §16 decision 48, as amended on
# 2026-11-26). The DoT, DoQ and DoH live checks and the interop check source this file.
#
# An example detects the CPU's features through stdx, and on arm64 sets PSTATE.DIT where the core
# has FEAT_DIT. Each of its handshakes must then run AES-GCM where the host reports the AES
# instructions and a carry-less multiply, on arm64 with FEAT_DIT too, and ChaCha20-Poly1305
# elsewhere. stdx states the timing of each x86-64 core from detection, as the owner ruled for
# stdx, so x86-64 needs no FEAT_DIT.
#
# This file reads what the system reports: sysctl on macOS, and the features of /proc/cpuinfo on
# Linux. stdx's detection reads the same CPU. This file never reads the host from the example. An
# example whose detection broke would otherwise lower what its run must reach. Each Apple arm64 CPU
# has all three features. So on arm64 macOS a run fails where sysctl does not report each of them
# as 1.

# Whether the space-separated list `$1` holds the word `$2`: `yes` or `no`.
cpu_suite_has() {
    if echo " $1 " | grep -qiw -- "$2"; then echo yes; else echo no; fi
}

# What this host's system reports, as three words: the AES instructions, a carry-less multiply,
# and the thread's PSTATE.DIT once an example sets it, each `yes` or `no`. On x86-64 the third is
# `no`: no program reads DOITM. On arm64 macOS where sysctl does not report one of the three
# features as 1, the words are `hidden`, the name of that feature, and `no`.
cpu_suite_read() {
    case $(uname -s):$(uname -m) in
    Darwin:arm64)
        for feature in FEAT_AES FEAT_PMULL FEAT_DIT; do
            if [ "$(sysctl -n "hw.optional.arm.$feature" 2>/dev/null)" != 1 ]; then
                echo "hidden $feature no"
                return
            fi
        done
        echo "yes yes yes" ;;
    Linux:aarch64)
        flags=$(grep -m 1 '^Features' /proc/cpuinfo || true)
        echo "$(cpu_suite_has "$flags" aes) $(cpu_suite_has "$flags" pmull) $(cpu_suite_has "$flags" dit)" ;;
    Linux:x86_64)
        flags=$(grep -m 1 '^flags' /proc/cpuinfo || true)
        echo "$(cpu_suite_has "$flags" aes) $(cpu_suite_has "$flags" pclmulqdq) no" ;;
    Darwin:x86_64)
        flags=$(sysctl -n machdep.cpu.features 2>/dev/null || true)
        echo "$(cpu_suite_has "$flags" aes) $(cpu_suite_has "$flags" pclmulqdq) no" ;;
    *) echo "no no no" ;;
    esac
}
cpu_suite_host=$(cpu_suite_read)
cpu_suite_aes=${cpu_suite_host%% *}
cpu_suite_rest=${cpu_suite_host#* }
cpu_suite_clmul=${cpu_suite_rest% *}
cpu_suite_dit=${cpu_suite_rest#* }

# The line each example prints before its first turn (`examples/cpu_text.zig`).
cpu_suite_stated="cpu: aes $cpu_suite_aes, carry-less multiply $cpu_suite_clmul, dit $cpu_suite_dit"

# Whether stdx offers AES-GCM on this host: the AES instructions and a carry-less multiply, and on
# arm64 PSTATE.DIT set.
cpu_suite_offers_aes() {
    [ "$cpu_suite_aes" = yes ] && [ "$cpu_suite_clmul" = yes ] || return 1
    case $(uname -m) in
    x86_64) return 0 ;;
    *) [ "$cpu_suite_dit" = yes ] ;;
    esac
}

# Says, once at the start of a check, what this host makes each run reach.
cpu_suite_says() {
    if [ "$cpu_suite_aes" = hidden ]; then
        echo "this host is arm64 macOS, but sysctl does not report $cpu_suite_clmul as 1: each run fails"
    elif cpu_suite_offers_aes; then
        echo "this host reports the AES instructions and a carry-less multiply: each run must state [$cpu_suite_stated] and reach AES-GCM"
    else
        echo "this host lacks the AES instructions, a carry-less multiply or FEAT_DIT: each run must state [$cpu_suite_stated] and reach ChaCha20-Poly1305"
    fi
}

# Checks the output `$1` of one run. It reads the statement that the example printed before its
# first turn, and the suite of each turn's handshake. It prints the suite that the run reached, or
# why the run fails, and returns 1 when it fails.
cpu_suite_check() {
    if [ "$cpu_suite_aes" = hidden ]; then
        echo "this host hides $cpu_suite_clmul, which each Apple arm64 CPU has, so no run can reach AES-GCM"
        return 1
    fi
    reached=ChaCha20-Poly1305 expected=': suite TLS_CHACHA20_POLY1305_SHA256$'
    if cpu_suite_offers_aes; then
        reached=AES-GCM expected=': suite TLS_AES_(128_GCM_SHA256|256_GCM_SHA384)$'
    fi
    if ! echo "$1" | grep -qxF "$cpu_suite_stated"; then
        echo "states [$(echo "$1" | grep '^cpu: ' || true)], not [$cpu_suite_stated]"
        return 1
    fi
    turns=$(echo "$1" | grep -c ': suite ' || true)
    others=$(echo "$1" | grep ': suite ' | grep -Evc "$expected" || true)
    if [ "$turns" -eq 0 ] || [ "$others" -ne 0 ]; then
        echo "$others of $turns turns not over $reached: $(echo "$1" | grep ': suite ' | tr '\n' ' ')"
        return 1
    fi
    echo "$reached"
}
