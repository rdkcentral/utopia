#!/bin/sh
# resolve_mtrace_depth2_symbols.sh
#
# Decode my_mtrace_depth2.pl output and resolve Caller1/Caller2 tokens
# into function + file:line using rootfs-dbg binaries.
#
# Usage:
#   ./resolve_mtrace_depth2_symbols.sh <rootfs-dbg-dir> <depth2_analysis_input> <resolved-output> [proc-maps-file]
#
# Input format expected (from my_mtrace_depth2.pl):
#   Address            Size     Caller1                             Caller2
#   0x...              0x...    /lib/libfoo.so:[0xADDR1]            /usr/bin/bar:[0xADDR2]

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
    echo "Usage: $0 <rootfs-dbg-dir> <depth2_analysis_input> <resolved-output> [proc-maps-file]"
    exit 1
fi

ROOTFS_DBG=$(realpath "$1")
DEPTH2_IN=$2
OUTPUT_FILE=$3
MAPS_FILE=${4:-}

if [ ! -d "$ROOTFS_DBG" ]; then
    echo "ERROR: rootfs-dbg dir not found: $ROOTFS_DBG"
    exit 1
fi
if [ ! -f "$DEPTH2_IN" ]; then
    echo "ERROR: input file not found: $DEPTH2_IN"
    exit 1
fi
if [ -n "$MAPS_FILE" ] && [ ! -f "$MAPS_FILE" ]; then
    echo "ERROR: maps file not found: $MAPS_FILE"
    exit 1
fi

# Validate that input looks like my_mtrace_depth2.pl output.
if grep -q "Free .* was never alloc" "$DEPTH2_IN" 2>/dev/null; then
    echo "ERROR: Input appears to be mtrace/my_mtrace.pl output, not depth2 output."
    echo "       Found lines like: 'Free ... was never alloc\'d'."
    echo "       Use one of these inputs instead:"
    echo "         1) output of: perl /lib/rdk/my_mtrace_depth2.pl /tmp/mtrace2_<proc>_<pid>.log"
    echo "         2) triage analysis generated in depth2 mode"
    exit 1
fi

_try_addr2line() {
    [ -x "$1" ] && "$1" --version 2>/dev/null | grep -q "GNU Binutils"
}

BUILD_BASE="${ROOTFS_DBG%%/tmp/*}"
CROSS_A2L=$(find "$BUILD_BASE/tmp/sysroots-components" -name "*-addr2line" \
    -not -path "*/go/*" -not -path "*/go-runtime/*" 2>/dev/null | head -1)

ADDR2LINE=""
if _try_addr2line "$CROSS_A2L"; then
    ADDR2LINE="$CROSS_A2L"
fi
if [ -z "$ADDR2LINE" ]; then
    _hf=$(which arm-linux-gnueabihf-addr2line 2>/dev/null)
    _try_addr2line "$_hf" && ADDR2LINE="$_hf"
fi
if [ -z "$ADDR2LINE" ]; then
    _sys=$(which addr2line 2>/dev/null)
    _try_addr2line "$_sys" && ADDR2LINE="$_sys"
fi
if [ -z "$ADDR2LINE" ]; then
    echo "ERROR: GNU addr2line not found"
    exit 1
fi

echo "Using addr2line: $ADDR2LINE"
if [ -n "$MAPS_FILE" ]; then
    echo "Using maps file: $MAPS_FILE"
fi

TMP_LEAKS=$(mktemp /tmp/mtrace_depth2_leaks_XXXXXX.tsv)
TMP_GROUPED=$(mktemp /tmp/mtrace_depth2_grouped_XXXXXX.tsv)
TMP_ROOTS=$(mktemp /tmp/mtrace_depth2_roots_XXXXXX.tsv)
TMP_UNIQTOKENS=$(mktemp /tmp/mtrace_depth2_tokens_XXXXXX.tsv)
TMP_RESOLVED=$(mktemp /tmp/mtrace_depth2_resolved_XXXXXX.tsv)
trap 'rm -f "$TMP_LEAKS" "$TMP_GROUPED" "$TMP_ROOTS" "$TMP_UNIQTOKENS" "$TMP_RESOLVED"' EXIT

# Parse leak rows — support N-frame format (frames separated by ';' in col3+).
# New my_mtrace_depth2.pl format : addr  size(decimal)  frame0  frame1 ...
# Old on-device format           : addr  size(hex 0x..)  frame0  frame1 ...
# Both are accepted.
awk '
function ishex(s)  { return s ~ /^0x[0-9a-fA-F]+$/ }
function isnum(s)   { return ishex(s) || s ~ /^[0-9]+$/ }
{
    if (NF >= 3 && ishex($1) && isnum($2)) {
        row = $1 "|" $2
        for (i = 3; i <= NF; i++) {
            row = row "|" $i
        }
        print row
    }
}
' "$DEPTH2_IN" > "$TMP_LEAKS"

if [ ! -s "$TMP_LEAKS" ]; then
    echo "No depth2 leak rows found in input: $DEPTH2_IN"
    echo "Expected rows like (new format — decimal size):"
    echo "  0xADDR SIZE_decimal  lib.so:[0xOFFSET]  lib2.so:[0xOFFSET] ..."
    echo "Expected rows like (old format — hex size):"
    echo "  0xADDR 0xSIZE  lib.so:[0xOFFSET]  lib2.so:[0xOFFSET] ..."
    echo "Hint: run  perl my_mtrace_depth2.pl <raw_log.log> [maps.txt]  and feed its output here."
    exit 0
fi

# Detect capture depth from first data row (number of frame columns after addr+size).
CAPTURE_DEPTH=$(awk -F'|' 'NR==1{print NF-2}' "$TMP_LEAKS")
[ -z "$CAPTURE_DEPTH" ] || [ "$CAPTURE_DEPTH" -lt 1 ] && CAPTURE_DEPTH=2
echo "Detected capture depth: $CAPTURE_DEPTH frame(s)"

# Group by all caller frames (cols 3..N): count + total leaked bytes.
awk -F'|' -v depth="$CAPTURE_DEPTH" '
{
    # key = all frame cols joined by |
    key = ""
    for (i = 3; i <= 2+depth && i <= NF; i++) {
        key = key (i>3 ? "|" : "") $i
    }
    count[key]++
    total[key] += strtonum($2)
    if (!example[key]) example[key] = $1
}
END {
    for (k in count) {
        printf "%s|%d|%d|%s\n", k, count[k], total[k], example[k]
    }
}
' "$TMP_LEAKS" | sort -t'|' -k$((CAPTURE_DEPTH+2)),$((CAPTURE_DEPTH+2))nr > "$TMP_GROUPED"

# Merge by root cause (Caller1 alone) — multiple full chains that share the
# same Caller1 (the actual malloc/free call site) are the SAME leak reached
# via different outer callers. Showing each as a separate top-level entry
# looks like duplication; merge them here into one entry with combined
# count/total, keeping the distinct deeper paths as sub-detail below it.
awk -F'|' -v depth="$CAPTURE_DEPTH" '
{
    root = $1
    cnt  = $(depth+1)
    tot  = $(depth+2)
    rc[root] += cnt
    rt[root] += tot
    nv[root]++
}
END {
    for (r in rc) printf "%s|%d|%d|%d\n", r, rc[r], rt[r], nv[r]
}
' "$TMP_GROUPED" | sort -t'|' -k3,3nr > "$TMP_ROOTS"

# Build unique token list (all frame columns).
# Exclude '-' (no-frame placeholder) and empty strings — nothing to resolve.
awk -F'|' -v depth="$CAPTURE_DEPTH" '{
    for (i = 3; i <= 2+depth && i <= NF; i++) print $i
}' "$TMP_LEAKS" | sed '/^$/d' | grep -v '^-$' | sort -u > "$TMP_UNIQTOKENS"

# Resolve one token -> function/file:line and cache results.
resolve_token() {
    tok="$1"

    case "$tok" in
        "[unknown]:[0x0]"|"[unknown]:0x0"|"[unknown]"|"[unknown]:[0x00000000]")
            # Old on-device script padded missing frames with [unknown]:[0x0]
            # — the address itself is zero, so there is genuinely nothing to
            # decode (no offset to feed addr2line / no maps lookup possible).
            echo "$tok|no frame captured|?|unknown"
            return
            ;;
        "-"|"")
            # '-' means backtrace could not capture this frame (ARM unwind limit).
            echo "$tok|no frame captured|?|unknown"
            return
            ;;
    esac

    # [unknown]:[0xADDR] (non-zero) — dladdr() on the target could not map this
    # return address to a loaded library at capture time (common for PLT
    # stubs, statically-linked code, or libraries dlopen'd after capture
    # started). We still have a real absolute address, so do NOT just label
    # it unknown and move on: use the /proc/<pid>/maps snapshot to find which
    # mapping the address falls inside, compute the file-relative offset from
    # that mapping, and resolve it with addr2line exactly like any other
    # token below.
    unk_path=""
    unk_addr=""
    case "$tok" in
        "[unknown]:"*)
            _ua=$(echo "$tok" | sed -n 's/\[unknown\]:\[\(0x[0-9a-fA-F]*\)\]/\1/p')
            [ -z "$_ua" ] && _ua=$(echo "$tok" | sed -n 's/\[unknown\]:\(0x[0-9a-fA-F]*\)/\1/p')

            if [ -n "$MAPS_FILE" ] && [ -n "$_ua" ]; then
                hit=$(awk -v a="$_ua" '
                    function h2n(x){ return strtonum(x) }
                    {
                        # maps format: start-end perms offset dev inode path
                        if (NF >= 6 && $2 ~ /x/) {
                            split($1, r, "-")
                            start = h2n("0x" r[1])
                            end   = h2n("0x" r[2])
                            off   = h2n("0x" $3)
                            abs   = h2n(a)
                            if (abs >= start && abs < end) {
                                rel = abs - start + off
                                printf("%s|0x%x", $6, rel)
                                exit
                            }
                        }
                    }
                ' "$MAPS_FILE")
                if [ -n "$hit" ]; then
                    unk_path="${hit%%|*}"
                    unk_addr="${hit#*|}"
                fi
            fi

            if [ -z "$unk_path" ]; then
                # No maps snapshot was supplied, or the address genuinely isn't
                # inside any mapping captured in it (true kernel/JIT/unmapped
                # frame) — nothing left to decode.
                echo "$tok|not in any mapped library|${_ua:-?}|unknown"
                return
            fi
            ;;
    esac

    # accepted token formats:
    #   /path/to/lib.so:[0xADDR]
    #   /path/to/lib.so:0xADDR
    #   libfoo.so.0:0xADDR
    #   libfoo.so.0:[0xADDR]
    if [ -n "$unk_path" ]; then
        # Recovered from an [unknown] frame via the maps snapshot above —
        # already a (path, file-relative-offset) pair, ready to resolve.
        path="$unk_path"
        addr="$unk_addr"
    else
        path=$(echo "$tok" | sed -n 's|^\([^:][^:]*\):\[0x[0-9a-fA-F]\+\]$|\1|p')
        addr=$(echo "$tok" | sed -n 's|^[^:][^:]*:\[\(0x[0-9a-fA-F]\+\)\]$|\1|p')

        if [ -z "$path" ] || [ -z "$addr" ]; then
            path=$(echo "$tok" | sed -n 's|^\([^:][^:]*\):\(0x[0-9a-fA-F]\+\)$|\1|p')
            addr=$(echo "$tok" | sed -n 's|^[^:][^:]*:\(0x[0-9a-fA-F]\+\)$|\1|p')
        fi
    fi

    if [ -z "$path" ] || [ -z "$addr" ]; then
        echo "$tok|UNPARSEABLE|?|NOT FOUND"
        return
    fi

    # For old captures, tokens may contain absolute runtime PCs.
    # If a /proc/<pid>/maps snapshot is provided, translate absolute PC to
    # module-relative offset: rel = abs - (map_start - map_offset).
    # Then feed rel to addr2line. (Tokens recovered above from an [unknown]
    # frame are already module-relative, so skip re-translating those.)
    addr_rel=""
    if [ -n "$MAPS_FILE" ] && [ -z "$unk_path" ]; then
        addr_rel=$(awk -v p="$path" -v b="$(basename "$path")" -v a="$addr" '
            function h2n(x){ return strtonum(x) }
            function pick_match(path_field, p, b) {
                if (path_field == p) return 1
                # Fallback by basename (handles SONAME symlink mismatch)
                n = split(path_field, arr, "/")
                return (n > 0 && arr[n] == b)
            }
            {
                # maps format: start-end perms offset dev inode path
                # We prefer executable mappings for code address translation.
                if (NF >= 6 && $2 ~ /x/ && pick_match($6, p, b)) {
                    split($1, r, "-")
                    start = h2n("0x" r[1])
                    off   = h2n("0x" $3)
                    abs   = h2n(a)
                    base  = start - off
                    rel   = abs - base
                    if (rel >= 0) {
                        printf("0x%x", rel)
                        exit
                    }
                }
            }
        ' "$MAPS_FILE")
    fi

    base=$(basename "$path")
    debug_file=$(find "$ROOTFS_DBG" -name "$base*" -path "*/.debug/*" 2>/dev/null | head -1)
    if [ -z "$debug_file" ]; then
        base_noversion=$(echo "$base" | sed 's/\.so\.[0-9].*/\.so/')
        debug_file=$(find "$ROOTFS_DBG" -name "$base_noversion*" -path "*/.debug/*" 2>/dev/null | head -1)
    fi
    if [ -z "$debug_file" ]; then
        debug_file=$(find "$ROOTFS_DBG" -name "$base*" 2>/dev/null | grep -v "/\.debug/" | head -1)
    fi

    if [ -z "$debug_file" ] || [ ! -f "$debug_file" ]; then
        # If token had no absolute path (basename-only), broaden search by basename.
        if [ "${path#/}" = "$path" ]; then
            debug_file=$(find "$ROOTFS_DBG" -name "$path*" -path "*/.debug/*" 2>/dev/null | head -1)
            if [ -z "$debug_file" ]; then
                debug_file=$(find "$ROOTFS_DBG" -name "$path*" 2>/dev/null | grep -v "/\.debug/" | head -1)
            fi
        fi
    fi

    if [ -z "$debug_file" ] || [ ! -f "$debug_file" ]; then
        echo "$tok|unknown (debug file not found: $base)|?|NOT FOUND"
        return
    fi

    # Try translated relative addr first (when maps supplied), then raw token addr.
    try_addr="$addr"
    if [ -n "$addr_rel" ]; then
        try_addr="$addr_rel"
    fi

    a2l_out=$($ADDR2LINE -f -e "$debug_file" "$try_addr" 2>/dev/null)
    func=$(echo "$a2l_out" | head -n1)
    src_full=$(echo "$a2l_out" | tail -n1)

    case "$src_full" in
        \?\?:*|"")
            src_full=$($ADDR2LINE -e "$debug_file" "$try_addr" 2>/dev/null)
            ;;
    esac

    # Fallback to original raw addr if translated addr did not resolve.
    case "$src_full" in
        \?\?:*|"")
            if [ "$try_addr" != "$addr" ]; then
                a2l_out=$($ADDR2LINE -f -e "$debug_file" "$addr" 2>/dev/null)
                func=$(echo "$a2l_out" | head -n1)
                src_full=$(echo "$a2l_out" | tail -n1)
                case "$src_full" in
                    \?\?:*|"") src_full=$($ADDR2LINE -e "$debug_file" "$addr" 2>/dev/null) ;;
                esac
            fi
            ;;
    esac

    src=$(echo "$src_full" | sed 's|.*/||')
    [ -z "$func" ] || [ "$func" = "??" ] && func="unresolved"
    case "$src" in \?\?:*|"") src="?" ;; esac

    debug_display=$(echo "$debug_file" | sed 's|.*/\.debug/||')
    echo "$tok|$func|$src|$debug_display"
}

while IFS= read -r token; do
    resolve_token "$token" >> "$TMP_RESOLVED"
done < "$TMP_UNIQTOKENS"

lookup_field() {
    # $1 token, $2 field index in cached line split by '|'
    t=$1
    idx=$2
    grep -F "${t}|" "$TMP_RESOLVED" | head -1 | awk -F'|' -v i="$idx" '{print $i}'
}

{
    echo "================================================================"
    echo " MemTrace Depth-N Symbol Resolution Report"
    printf " Input         : %s\n" "$DEPTH2_IN"
    printf " DBG           : %s\n" "$ROOTFS_DBG"
    printf " Tool          : %s\n" "$ADDR2LINE"
    printf " Capture depth : %d frame(s)\n" "$CAPTURE_DEPTH"
    echo " Sorted        : largest leak group first"
    echo "================================================================"
    echo ""

    total_bytes=0
    entry_num=0

    while IFS='|' read -r _root _rcnt _rtot _rvariants; do
        entry_num=$((entry_num + 1))
        total_bytes=$((total_bytes + _rtot))

        if [ "$_rtot" -ge 1048576 ]; then
            sz_human=$(awk "BEGIN{printf \"%.1fMB\", $_rtot/1048576}")
        elif [ "$_rtot" -ge 1024 ]; then
            sz_human=$(awk "BEGIN{printf \"%.1fKB\", $_rtot/1024}")
        else
            sz_human="${_rtot}B"
        fi

        printf "[#%02d] %s\n" "$entry_num" "------------------------------------------------------------"

        case "$_root" in
            "-"|""|"[unknown]:[0x0]"|"[unknown]:0x0"|"[unknown]"|"[unknown]:[0x00000000]")
                printf "  Caller1       : (no frame \u2014 backtrace depth limit or missing unwind tables)\n"
                ;;
            *)
                _func=$(lookup_field "$_root" 2)
                _file=$(lookup_field "$_root" 3)
                _bin=$(lookup_field  "$_root" 4)
                printf "  Caller1 Token : %s\n" "$_root"
                printf "  Caller1 Func  : %s\n" "$_func"
                printf "  Caller1 File  : %s\n" "$_file"
                printf "  Caller1 Bin   : %s\n" "$_bin"
                ;;
        esac
        echo ""

        printf "  Count         : %d instance(s)  (merged across %d call path(s))\n" "$_rcnt" "$_rvariants"
        printf "  Total         : %s (%d bytes)\n" "$sz_human" "$_rtot"
        echo ""

        if [ "$CAPTURE_DEPTH" -gt 1 ]; then
            _vn=0
            while IFS='|' read -r _vline; do
                _vroot=$(printf '%s' "$_vline" | awk -F'|' '{print $1}')
                [ "$_vroot" = "$_root" ] || continue
                _vn=$((_vn + 1))
                _vcnt=$(printf '%s' "$_vline" | awk -F'|' -v d="$CAPTURE_DEPTH" '{print $(d+1)}')
                _vtot=$(printf '%s' "$_vline" | awk -F'|' -v d="$CAPTURE_DEPTH" '{print $(d+2)}')
                _vex=$(printf '%s'  "$_vline" | awk -F'|' -v d="$CAPTURE_DEPTH" '{print $(d+3)}')

                if [ "$_rvariants" -gt 1 ]; then
                    printf "  Path %d (Count %d, %d bytes, e.g. %s):\n" "$_vn" "$_vcnt" "$_vtot" "$_vex"
                else
                    printf "  Example Addr  : %s\n" "$_vex"
                fi

                for d in $(seq 2 "$CAPTURE_DEPTH"); do
                    _tok=$(printf '%s' "$_vline" | awk -F'|' -v i="$d" '{print $i}')
                    case "$_tok" in
                        "-"|""|"[unknown]:[0x0]"|"[unknown]:0x0"|"[unknown]"|"[unknown]:[0x00000000]")
                            printf "    Caller%d       : (no frame \u2014 backtrace depth limit or missing unwind tables)\n" "$d"
                            continue
                            ;;
                    esac
                    _func=$(lookup_field "$_tok" 2)
                    _file=$(lookup_field "$_tok" 3)
                    _bin=$(lookup_field  "$_tok" 4)
                    printf "    Caller%d Token : %s\n" "$d" "$_tok"
                    printf "    Caller%d Func  : %s\n" "$d" "$_func"
                    printf "    Caller%d File  : %s\n" "$d" "$_file"
                    printf "    Caller%d Bin   : %s\n" "$d" "$_bin"
                done
                echo ""
            done < "$TMP_GROUPED"
        fi
    done < "$TMP_ROOTS"

    echo "================================================================"
    if [ "$total_bytes" -ge 1048576 ]; then
        total_human=$(awk "BEGIN{printf \"%.2fMB\", $total_bytes/1048576}")
    elif [ "$total_bytes" -ge 1024 ]; then
        total_human=$(awk "BEGIN{printf \"%.2fKB\", $total_bytes/1024}")
    else
        total_human="${total_bytes}B"
    fi
    printf " Total leaked : %s (%d bytes) across %d merged leak site(s)\n" \
        "$total_human" "$total_bytes" "$entry_num"
    echo "================================================================"
} > "$OUTPUT_FILE"

echo ""
echo "Done. Report written to: $OUTPUT_FILE"
echo ""
cat "$OUTPUT_FILE"
