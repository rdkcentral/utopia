#!/bin/sh
# resolve_mtrace_symbols.sh
#
# Decodes my_mtrace.pl output — resolves raw lib:offset to function + file:line
# by finding matching debug .so files under rootfs-dbg/.
#
# Usage:
#   ./resolve_mtrace_symbols.sh <rootfs-dbg-dir> <my_mtrace_pl_output> <resolved-output> [main-binary-name]
#
# Arguments:
#   rootfs-dbg-dir     : path to rootfs-dbg (contains usr/bin/.debug/, usr/lib/.debug/)
#   my_mtrace_pl_output: output file from: perl my_mtrace.pl <binary> <mtrace.log>
#   resolved-output    : where to write the decoded report
#   main-binary-name   : (optional) process binary name, e.g. CcspPandMSsp
#                        needed only if allocations come from the main binary directly

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
    echo "Usage: $0 <rootfs-dbg-dir> <my_mtrace_pl_output> <resolved-output> [main-binary-name]"
    echo ""
    echo "  rootfs-dbg-dir      : path containing usr/bin/.debug/ and usr/lib/.debug/"
    echo "  my_mtrace_pl_output : output of: perl my_mtrace.pl [binary] <mtrace.log>"
    echo "  resolved-output     : where to write the decoded report"
    echo "  main-binary-name    : (optional) e.g. CcspPandMSsp — for main-binary allocations"
    exit 1
fi

ROOTFS_DBG=$(realpath "$1")
MTRACE_OUTPUT=$2
OUTPUT_FILE=$3
MAIN_BINARY_NAME=${4:-}

# ── Find addr2line ────────────────────────────────────────────────────────────
# Strategy:
#  1. Try Yocto cross addr2line (best ARM DWARF support; runnable only when the
#     uninative interpreter path matches — i.e. on machines where the workspace
#     is NOT bind-mounted under a different prefix like /mnt/home).
#  2. Fall back to arm-linux-gnueabihf-addr2line (distro cross tools).
#  3. Last resort: system addr2line (works on most distros for ARM DWARF,
#     but some older binutils versions output ??:? for line info).
_try_addr2line() {
    # Return success if the binary exists, prints a version string, AND is
    # a real binutils addr2line (not Go's addr2line which only handles Go binaries).
    # We check by running addr2line --version and confirming "GNU Binutils" appears.
    [ -x "$1" ] && "$1" --version 2>/dev/null | grep -q "GNU Binutils"
}

# Look for the Yocto cross addr2line in sysroots-components
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
    ADDR2LINE=$(which addr2line 2>/dev/null)
fi
if [ -z "$ADDR2LINE" ]; then
    echo "ERROR: addr2line not found. Install binutils."
    exit 1
fi
echo "Using addr2line: $ADDR2LINE"
# Get matching readelf
get_readelf()
{
    _r=$(dirname "$ADDR2LINE")/$(basename "$ADDR2LINE" | sed 's/addr2line$/readelf/')
    if [ -x "$_r" ]; then
        echo "$_r"
    else
        echo readelf
    fi
}

# Return .text VMA as decimal

get_text_vma()
{
    elf="$1"

    READELF=$(get_readelf)

    hex=$("$READELF" -S "$elf" 2>/dev/null |
          awk '$2==".text" {print $4; exit}')

    [ -z "$hex" ] && return

    printf "%d\n" "0x$hex"
}
# ── Temp files ────────────────────────────────────────────────────────────────
TMP_LEAKS=$(mktemp /tmp/mtrace_leaks_XXXXXX.tsv)
TMP_GROUPED=$(mktemp /tmp/mtrace_grouped_XXXXXX.tsv)
trap 'rm -f "$TMP_LEAKS" "$TMP_GROUPED"' EXIT

# ── Pass 1: Extract (lib, offset, address, size) from "Memory not freed" ─────
#
# my_mtrace.pl output format in the leak section:
#   addr2line: '/usr/lib/libFOO.so': No such file   <- sets current library
#   addr2line: '/usr/lib/libFOO.so': No such file   <- duplicate (two addr2line calls), skip
#   0xADDR   0xSIZE  at 0xOFFSET                   <- leak entry
#   0xADDR   0xSIZE  at 0xOFFSET                   <- cached caller, no preceding error
#
# Rule: current_lib stays set until a NEW library error appears.
# Entries with no preceding error use the last seen library (cached addr2line result).

current_lib="[main_binary]"
in_leak_section=0

while IFS= read -r line; do
    # ── Detect section boundaries ──
    case "$line" in
        "Memory not freed:"*)
            in_leak_section=1
            continue
            ;;
        "Invalid Free Summary"*|"Duplicate Allocation"*)
            in_leak_section=0
            continue
            ;;
    esac

    # ── Track current library from addr2line error lines ──
    # Format: addr2line: '/path/to/lib.so.N': No such file
    # Match any absolute path (covers /usr/lib, /usr/lib64, /lib, etc.)
    lib_hint=$(echo "$line" | sed -n "s|addr2line: '\(/'[^']*\)': No such file|\1|p")
    # Also handle paths without leading quote issue — more robust match
    lib_hint=$(echo "$line" | sed -n "s|^addr2line: '\(/[^']*\)': No such file.*|\1|p")
    if [ -n "$lib_hint" ]; then
        current_lib="$lib_hint"
        continue
    fi

    # ── Parse leak entry line ──
    # Format: 0xADDR   0xSIZE  at 0xOFFSET
    #      or 0xADDR   0xSIZE  at function @ 0xOFFSET  (already resolved)
    if [ "$in_leak_section" = "1" ]; then
        case "$line" in
            0x*)
                addr=$(echo "$line" | awk '{print $1}')
                size=$(echo "$line" | awk '{print $2}')
                offset_raw=$(echo "$line" | awk '{print $4}')

                # If already resolved (contains letters other than hex), keep as-is
                # Otherwise treat as raw hex offset
                case "$offset_raw" in
                    0x*) offset="$offset_raw" ;;
                    *)   offset="$offset_raw" ;;  # function@addr — will handle below
                esac

                # size decimal
                size_dec=$(printf "%d" "$size" 2>/dev/null || echo 0)

                # Write pipe-delimited: lib|offset|addr|size_dec
                printf "%s|%s|%s|%d\n" \
                    "$current_lib" "$offset" "$addr" "$size_dec" >> "$TMP_LEAKS"
                ;;
        esac
    fi
done < "$MTRACE_OUTPUT"

if [ ! -s "$TMP_LEAKS" ]; then
    echo "No 'Memory not freed' entries found in $MTRACE_OUTPUT"
    echo "Check that the file is my_mtrace.pl output containing a leak section."
    exit 0
fi

# ── Pass 2: Group by (lib, offset) — count instances + total bytes ────────────
# Sort by lib+offset, then awk-aggregate (use | delimiter, POSIX sh compatible)
sort -t'|' -k1,1 -k2,2 "$TMP_LEAKS" | awk -F'|' '
{
    key = $1 "|" $2
    count[key]++
    total[key] += $4
    if (!first_addr[key]) first_addr[key] = $3
}
END {
    for (k in count) {
        split(k, parts, "|")
        printf "%s|%s|%d|%d|%s\n", parts[1], parts[2], count[k], total[k], first_addr[k]
    }
}' | sort -t'|' -k4 -rn > "$TMP_GROUPED"

# ── Pass 3: Resolve each unique (lib, offset) with addr2line ─────────────────
{
    echo "================================================================"
    echo " MemTrace Symbol Resolution Report"
    printf " Input  : %s\n" "$MTRACE_OUTPUT"
    printf " DBG    : %s\n" "$ROOTFS_DBG"
    printf " Tool   : %s\n" "$ADDR2LINE"
    echo " Sorted : largest leak first"
    echo "================================================================"
    echo ""

    total_bytes=0
    entry_num=0

    while IFS='|' read -r lib offset count size_total first_addr; do
	    resolve_addr="$offset"
        entry_num=$((entry_num + 1))
        total_bytes=$((total_bytes + size_total))

        # ── Find debug file for this library ──
        debug_file=""
        if [ "$lib" = "[main_binary]" ]; then
            if [ -n "$MAIN_BINARY_NAME" ]; then
                debug_file=$(find "$ROOTFS_DBG" -name "$MAIN_BINARY_NAME" -path "*/.debug/*" 2>/dev/null | head -1)
                lib_display="$MAIN_BINARY_NAME (main binary)"
            else
                debug_file=""
                lib_display="main binary (pass name as 4th arg to resolve)"
            fi
        else
            lib_basename=$(basename "$lib")
            # Try exact SONAME match in .debug/ first
            debug_file=$(find "$ROOTFS_DBG" -name "${lib_basename}*" -path "*/.debug/*" 2>/dev/null | head -1)
            # Fallback: strip SONAME version (e.g. libfoo.so.0 -> libfoo.so)
            # and search for any versioned debug file (e.g. libfoo.so.2.11.0)
            if [ -z "$debug_file" ]; then
                lib_base_noversion=$(echo "$lib_basename" | sed 's/\.so\.[0-9].*/\.so/')
                debug_file=$(find "$ROOTFS_DBG" -name "${lib_base_noversion}*" -path "*/.debug/*" 2>/dev/null | head -1)
            fi
            # Last resort: unstripped copy anywhere under rootfs-dbg
            if [ -z "$debug_file" ]; then
                debug_file=$(find "$ROOTFS_DBG" -name "${lib_basename}*" 2>/dev/null | grep -v ".debug" | head -1)
            fi
            lib_display="$lib_basename"
        fi

        # ── Resolve offset → function + file:line ──
        if [ -n "$debug_file" ] && [ -f "$debug_file" ]; then
            # addr2line -f outputs: function\nfile:line
            #a2l_out=$("$ADDR2LINE" -f -e "$debug_file" "$offset" 2>/dev/null)
            #func=$(echo "$a2l_out" | head -n1)
            #src_full=$(echo "$a2l_out" | tail -n1)

            # If file:line unresolved, try without -f (some addr2line versions differ)
            #case "$src_full" in
             #   \?\?:*|"") src_full=$("$ADDR2LINE" -e "$debug_file" "$offset" 2>/dev/null) ;;
            #esac
	    # ------------------------------------------------------------------
# First try raw offset
# ------------------------------------------------------------------
echo "DEBUG CALL1:" >&2
echo "  debug_file=$debug_file" >&2
echo "  resolve_addr=$resolve_addr" >&2

#resolve_addr="$offset"
# ------------------------------------------------------------------
# Resolution Strategy
#
# 1. Try raw offset first
# 2. If unresolved, try offset + .text VMA
# 3. Accept retry ONLY if it resolves
# ------------------------------------------------------------------

resolve_addr="$offset"

a2l_out=$("$ADDR2LINE" -f -C -e "$debug_file" "$offset" 2>/dev/null)

func=$(echo "$a2l_out" | head -n1)
src_full=$(echo "$a2l_out" | tail -n1)

# Did raw lookup fail?
if [ "$func" = "??" ] || printf "%s" "$src_full" | grep -q "??:0"; then

    text_vma=$(get_text_vma "$debug_file")

    if [ -n "$text_vma" ]; then

        offset_dec=$((offset))
        final_addr_dec=$((offset_dec + text_vma))
        final_addr_hex=$(printf "0x%x" "$final_addr_dec")

        echo "DEBUG RETRY:" >&2
        echo "  lib=$lib_display" >&2
        echo "  offset=$offset" >&2
        echo "  text_vma=$(printf '0x%x' "$text_vma")" >&2
        echo "  adjusted=$final_addr_hex" >&2

        retry_out=$(
            "$ADDR2LINE" \
            -f -C \
            -e "$debug_file" \
            "$final_addr_hex" 2>/dev/null
        )

        retry_func=$(echo "$retry_out" | head -n1)
        retry_src=$(echo "$retry_out" | tail -n1)

        echo "DEBUG RETRY RESULT:" >&2
        echo "$retry_out" >&2

        # Only use retry result if it really resolved
        if [ "$retry_func" != "??" ] &&
           ! printf "%s" "$retry_src" | grep -q "??:0"
        then
            func="$retry_func"
            src_full="$retry_src"
            resolve_addr="$final_addr_hex"
        fi
    fi
fi

# Fallback
case "$src_full" in
    \?\?:*|"")
        src_full=$("$ADDR2LINE" \
            -e "$debug_file" \
            "$resolve_addr" \
            2>/dev/null)
        ;;
esac
#newchanges

            # Shorten path: keep only filename.c:line (strip long debug prefix)
            src=$(echo "$src_full" | sed 's|.*/||')

            [ -z "$func" ] || [ "$func" = "??" ] && func="unresolved (check debug symbols)"
            case "$src" in \?\?:*|"") src="? (line info missing — check debug binary has full DWARF)" ;; esac
        else
            func="unknown (debug file not found: $lib_basename)"
            src="?"
            debug_file="NOT FOUND"
        fi
        debug_file_display=$(echo "$debug_file" | sed 's|.*/\.debug/||')

        # ── Format size ──
        if   [ "$size_total" -ge 1048576 ]; then
            size_human=$(awk "BEGIN{printf \"%.1fMB\", $size_total/1048576}")
        elif [ "$size_total" -ge 1024 ]; then
            size_human=$(awk "BEGIN{printf \"%.1fKB\", $size_total/1024}")
        else
            size_human="${size_total}B"
        fi
	echo "DEBUG: LIB=$lib_display OFFSET=$offset RESOLVED_ADDR=$resolve_addr" >&2

        printf "[#%02d] %-60s\n" "$entry_num" "$(printf '%.0s─' $(seq 1 60))"
        printf "  Library  : %s\n"           "$lib_display"
        printf "  Function : %s\n"           "$func"
        printf "  File     : %s\n"           "$src"
        printf "  Offset   : %s\n"           "$offset"
        printf "  Count    : %d instance(s)\n"  "$count"
        printf "  Total    : %s (%d bytes)\n"   "$size_human" "$size_total"
        printf "  Example  : %s\n"           "$first_addr"
        printf "  DebugBin : %s\n"           "$debug_file_display"
        echo ""

    done < "$TMP_GROUPED"

    echo "================================================================"
    if   [ "$total_bytes" -ge 1048576 ]; then
        total_human=$(awk "BEGIN{printf \"%.2fMB\", $total_bytes/1048576}")
    elif [ "$total_bytes" -ge 1024 ]; then
        total_human=$(awk "BEGIN{printf \"%.2fKB\", $total_bytes/1024}")
    else
        total_human="${total_bytes}B"
    fi
    printf " Total leaked : %s (%d bytes) across %d unique caller(s)\n" \
        "$total_human" "$total_bytes" "$entry_num"
    echo "================================================================"

} > "$OUTPUT_FILE"

echo ""
echo "Done. Report written to: $OUTPUT_FILE"
echo ""
cat "$OUTPUT_FILE"
