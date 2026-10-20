# The suite each run of a TLS example must reach, with the word `cpu` and without it
# (docs/design.md §16 decision 48). The DoT, DoQ and DoH live checks and the interop check source
# this file. Each of them resolves through each server in two runs: without the word, then with it.
#
# Without the word an example states nothing. Each of its handshakes must then run
# TLS_CHACHA20_POLY1305_SHA256. With the word it states `data_independent` where this host reports
# FEAT_DIT, and nothing elsewhere: on x86-64 no program can read DOITM. Each handshake must then
# run AES-GCM where the host also reports the AES instructions and PMULL, and ChaCha20-Poly1305
# elsewhere.
#
# This file reads what the system reports: sysctl on macOS, and the features of /proc/cpuinfo on
# Linux. Those come from the AT_HWCAP word, which stdx's probe reads. This file never reads the
# host from the example. An example whose probe broke would otherwise lower what its run must
# reach. stdx's probe takes the build target's answer where the system gives none, and this file
# does not. Each Apple arm64 CPU has all three features. So on arm64 macOS a run with the word
# fails where sysctl does not report each of them as 1. No run there can reach AES-GCM.

# What this host's system reports, as two words: whether it reports FEAT_DIT, then whether it
# reports the AES instructions and PMULL both. Each is `yes` or `no`. On arm64 macOS where sysctl
# does not report one of the three as 1, the words are `hidden` and the name of that feature.
cpu_word_read() {
    case $(uname -s):$(uname -m) in
    Darwin:arm64)
        for feature in FEAT_AES FEAT_PMULL FEAT_DIT; do
            if [ "$(sysctl -n "hw.optional.arm.$feature" 2>/dev/null)" != 1 ]; then
                echo "hidden $feature"
                return
            fi
        done
        echo "yes yes" ;;
    Linux:aarch64)
        flags=$(grep -m 1 '^Features' /proc/cpuinfo || true)
        dit=no aes=no
        if echo "$flags" | grep -qw dit; then dit=yes; fi
        if echo "$flags" | grep -qw aes && echo "$flags" | grep -qw pmull; then aes=yes; fi
        echo "$dit $aes" ;;
    *) echo "no no" ;;
    esac
}
cpu_word_host=$(cpu_word_read)
cpu_word_dit=${cpu_word_host% *}
cpu_word_aes=${cpu_word_host#* }

# What an example states without the word, and where it states no mode.
cpu_word_nothing="cpu: timing not_stated, aes_clmul not_known, dit not_known"

# The word each check passes to its example: empty, or `cpu`. A check sets it around each run.
word=

# Says, once at the start of a check, what this host makes each run with the word reach.
cpu_word_says() {
    case $cpu_word_dit:$cpu_word_aes in
    yes:yes) echo "this host reports FEAT_DIT, the AES instructions and PMULL: each run with the word must state data_independent and reach AES-GCM" ;;
    yes:no) echo "this host reports FEAT_DIT, but not the AES instructions and PMULL: each run with the word must state data_independent and reach ChaCha20-Poly1305" ;;
    hidden:*) echo "this host is arm64 macOS, but sysctl does not report $cpu_word_aes as 1: each run with the word fails" ;;
    *) echo "this host does not report FEAT_DIT: each run with the word must state nothing and reach ChaCha20-Poly1305" ;;
    esac
}

# Checks the output `$1` of one run, made with the word that `word` holds. It reads the statement
# that the example printed before its first turn, and the suite of each turn's handshake. It prints
# the suite that the run reached, or why the run fails, and returns 1 when it fails.
cpu_word_check() {
    stated=$cpu_word_nothing reached=ChaCha20-Poly1305
    expected=': suite TLS_CHACHA20_POLY1305_SHA256$'
    if [ -n "$word" ] && [ "$cpu_word_dit" = hidden ]; then
        echo "this host hides $cpu_word_aes, which each Apple arm64 CPU has, so no run with the word can reach AES-GCM"
        return 1
    fi
    if [ -n "$word" ] && [ "$cpu_word_dit" = yes ]; then
        stated="cpu: timing data_independent, aes_clmul $cpu_word_aes, dit yes"
        if [ "$cpu_word_aes" = yes ]; then
            reached=AES-GCM expected=': suite TLS_AES_(128_GCM_SHA256|256_GCM_SHA384)$'
        fi
    fi
    if ! echo "$1" | grep -qxF "$stated"; then
        echo "states [$(echo "$1" | grep '^cpu: ' || true)], not [$stated]"
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

# How a check names a run: "" without the word, and " with the word" with it.
cpu_word_named() {
    if [ -n "$word" ]; then echo " with the word"; fi
}
