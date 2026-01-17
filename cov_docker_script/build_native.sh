#!/usr/bin/env bash
set -e

################################################################################
# Generic Native Component Build Script
# Usage: ./build_native.sh [config_file] [component_dir]
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-$SCRIPT_DIR/component_config.json}"
COMPONENT_DIR="${2:-$(cd "$SCRIPT_DIR/.." && pwd)}"

# Source common utilities
source "$SCRIPT_DIR/common_build_utils.sh"

# Validate environment
if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Config file not found: $CONFIG_FILE"
    exit 1
fi

if [[ ! -d "$COMPONENT_DIR" ]]; then
    err "Component directory not found: $COMPONENT_DIR"
    exit 1
fi

check_dependencies || exit 1

# Read component configuration
COMPONENT_NAME=$(jq -r '.native_component.name' "$CONFIG_FILE")
BUILD_TYPE=$(jq -r '.native_component.build.type' "$CONFIG_FILE")
HEADER_PATH=$(expand_path "$(jq -r '.native_component.include_path' "$CONFIG_FILE")")
LIB_PATH=$(expand_path "$(jq -r '.native_component.lib_output_path' "$CONFIG_FILE")")

# Configure environment
configure_environment() {
    print_banner "Building Native Component: $COMPONENT_NAME"
    
    log "Component: $COMPONENT_NAME"
    log "Build type: $BUILD_TYPE"
    log "Component directory: $COMPONENT_DIR"
    log "Header path: $HEADER_PATH"
    log "Library path: $LIB_PATH"
    echo ""
    
    # Setup PKG_CONFIG_PATH and LD_LIBRARY_PATH
    export PKG_CONFIG_PATH="$LIB_PATH/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="$LIB_PATH:${LD_LIBRARY_PATH:-}"
    
    # Add common include and lib paths
    export CPPFLAGS="${CPPFLAGS:-} -I$HEADER_PATH"
    export CFLAGS="${CFLAGS:-} -I$HEADER_PATH"
    export LDFLAGS="${LDFLAGS:-} -L$LIB_PATH"
    
    log "Environment configured"
    log "  PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    log "  LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
    echo ""
}

# Apply source patches
apply_source_patches() {
    local patch_count
    patch_count=$(jq -r '.native_component.source_patches // [] | length' "$CONFIG_FILE")
    
    if [[ "$patch_count" -eq 0 ]]; then
        log "No source patches configured"
        return 0
    fi
    
    step "Applying source patches ($patch_count patches)"
    
    local i=0
    while [[ $i -lt $patch_count ]]; do
        local file search replace type content
        file=$(jq -r ".native_component.source_patches[$i].file" "$CONFIG_FILE")
        type=$(jq -r ".native_component.source_patches[$i].type // \"replace\"" "$CONFIG_FILE")
        search=$(jq -r ".native_component.source_patches[$i].search // \"\"" "$CONFIG_FILE")
        replace=$(jq -r ".native_component.source_patches[$i].replace // \"\"" "$CONFIG_FILE")
        content=$(jq -r ".native_component.source_patches[$i].content // \"\"" "$CONFIG_FILE")
        
        # Expand $HOME in file path, then resolve relative paths from COMPONENT_DIR
        local expanded_file=$(expand_path "$file")
        local target_file
        if [[ "$expanded_file" = /* ]]; then
            # Absolute path - use as is
            target_file="$expanded_file"
        else
            # Relative path - prepend COMPONENT_DIR
            target_file="$COMPONENT_DIR/$expanded_file"
        fi
        
        if ! apply_patch "$target_file" "$search" "$replace" "$type" "$content"; then
            err "Failed to apply patch $((i+1))/$patch_count"
            return 1
        fi
        
        i=$((i + 1))
    done
    
    ok "All patches applied successfully"
    echo ""
    return 0
}

# Process native headers
process_native_headers() {
    local header_count
    header_count=$(jq -r '.native_component.header_sources // [] | length' "$CONFIG_FILE")
    
    if [[ "$header_count" -eq 0 ]]; then
        log "No header sources configured"
        return 0
    fi
    
    step "Processing native component headers ($header_count sources)"
    
    local i=0
    while [[ $i -lt $header_count ]]; do
        local src dst
        src=$(jq -r ".native_component.header_sources[$i].source" "$CONFIG_FILE")
        dst=$(jq -r ".native_component.header_sources[$i].destination" "$CONFIG_FILE")
        
        # Expand paths
        src="$COMPONENT_DIR/$src"
        dst=$(expand_path "$dst")
        
        copy_headers "$src" "$dst"
        i=$((i + 1))
    done
    
    ok "All headers processed successfully"
    echo ""
    return 0
}

# Parse configure options from external file
parse_configure_options_file() {
    local conf_file="$1"
    local -n options_array=$2
    
    if [[ ! -f "$conf_file" ]]; then
        err "Configure options file not found: $conf_file"
        return 1
    fi
    
    local current_section=""
    local cppflags=""
    local cflags=""
    local ldflags=""
    local libs=""
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Detect section headers
        if [[ "$line" =~ ^\[([A-Z_]+)\] ]]; then
            current_section="${BASH_REMATCH[1]}"
            continue
        fi
        
        # Trim whitespace
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" ]] && continue
        
        # Append to appropriate section
        case "$current_section" in
            CPPFLAGS)
                cppflags+="$line "
                ;;
            CFLAGS)
                cflags+="$line "
                ;;
            LDFLAGS)
                ldflags+="$line "
                ;;
            LIBS)
                libs+="$line "
                ;;
        esac
    done < "$conf_file"
    
    # Expand environment variables in the flags using envsubst or manual replacement
    # Use manual replacement for better control and to avoid shell interpretation issues
    cppflags="${cppflags//\$HOME/$HOME}"
    cflags="${cflags//\$HOME/$HOME}"
    ldflags="${ldflags//\$HOME/$HOME}"
    libs="${libs//\$HOME/$HOME}"
    
    # Build final options array
    [[ -n "$cppflags" ]] && options_array+=("CPPFLAGS=${cppflags% }")
    [[ -n "$cflags" ]] && options_array+=("CFLAGS=${cflags% }")
    [[ -n "$ldflags" ]] && options_array+=("LDFLAGS=${ldflags% }")
    [[ -n "$libs" ]] && options_array+=("LIBS=${libs% }")
}

# Build with autotools
build_component_autotools() {
    cd "$COMPONENT_DIR"
    
    # Read configure options as array
    local configure_options=()
    
    # Check if using external configure options file
    local config_file_path
    config_file_path=$(jq -r '.native_component.build.configure_options_file // empty' "$CONFIG_FILE")
    
    if [[ -n "$config_file_path" ]]; then
        # Using external configuration file
        config_file_path=$(expand_path "$config_file_path")
        # If relative path, make it relative to component dir
        if [[ ! "$config_file_path" = /* ]]; then
            config_file_path="$COMPONENT_DIR/$config_file_path"
        fi
        
        step "Reading configure options from: $config_file_path"
        if ! parse_configure_options_file "$config_file_path" configure_options; then
            err "Failed to parse configure options file"
            return 1
        fi
        ok "Loaded configure options from file"
    else
        # Using inline configure_options array (legacy support)
        local opt_count
        opt_count=$(jq -r '.native_component.build.configure_options // [] | length' "$CONFIG_FILE")
        
        local i=0
        while [[ $i -lt $opt_count ]]; do
            local option
            option=$(jq -r ".native_component.build.configure_options[$i]" "$CONFIG_FILE")
            option=$(expand_path "$option")
            configure_options+=("$option")
            i=$((i + 1))
        done
    fi
    
    # Run autogen if exists
    if [[ -f "./autogen.sh" ]]; then
        step "Running autogen.sh"
        chmod +x ./autogen.sh
        # Set NOCONFIGURE to prevent autogen.sh from automatically running configure
        if ! NOCONFIGURE=1 ./autogen.sh; then
            err "autogen.sh failed"
            return 1
        fi
        ok "autogen.sh completed"
        echo ""
    fi
    
    # Configure
    step "Running configure"
    
    # Export configure options as environment variables
    for option in "${configure_options[@]}"; do
        export "$option"
    done
    
    if ! ./configure; then
        err "Configure failed"
        return 1
    fi
    ok "Configure completed"
    echo ""
    
    # Make
    local make_targets
    make_targets=$(jq -r '.native_component.build.make_targets[]? // "all"' "$CONFIG_FILE" | tr '\n' ' ')
    
    local parallel_make
    parallel_make=$(jq -r '.native_component.build.parallel_make // true' "$CONFIG_FILE")
    
    local make_jobs=""
    [[ "$parallel_make" == "true" ]] && make_jobs="-j$(nproc)"
    
    step "Running make $make_jobs $make_targets"
    if ! make $make_jobs $make_targets; then
        err "Make failed"
        return 1
    fi
    ok "Make completed"
    echo ""
    
    return 0
}

# Run pre-build commands from native_component.pre_build_commands[]
run_pre_build_commands() {

    log "copying python files generic..."
    copy_python_files_generic
    
    log "Running pre-build commands..."

    if [[ -z "$CONFIG_FILE" ]] || [[ ! -f "$CONFIG_FILE" ]]; then
        err "CONFIG_FILE not set or file missing"
        return 1
    fi

    if [[ -z "$COMPONENT_DIR" ]] || [[ ! -d "$COMPONENT_DIR" ]]; then
        err "COMPONENT_DIR not set or directory missing"
        return 1
    fi

    local cmd_count
    cmd_count=$(jq '.native_component.pre_build_commands // [] | length' "$CONFIG_FILE")

    if [[ "$cmd_count" -eq 0 ]]; then
        log "No pre-build commands to run"
        return 0
    fi

    pushd "$COMPONENT_DIR" >/dev/null || {
        err "Failed to enter component root: $COMPONENT_DIR"
        return 1
    }

    local i description command
    for ((i=0; i<cmd_count; i++)); do
        description=$(jq -r ".native_component.pre_build_commands[$i].description" "$CONFIG_FILE")
        command=$(jq -r ".native_component.pre_build_commands[$i].command" "$CONFIG_FILE")

        # Expand variables safely
        command=$(eval echo "$command")

        log "  [$((i+1))/$cmd_count] $description"
        if eval "$command"; then
            ok "Success: $description"
        else
            err "Failed: $description"
            popd >/dev/null
            return 1
        fi
    done

    popd >/dev/null
    ok "Pre-build commands completed"
    return 0
}

# Build with CMake
build_component_cmake() {
    cd "$COMPONENT_DIR"
    
    local build_dir cmake_flags make_targets parallel_make
    build_dir=$(jq -r '.native_component.build.build_dir // "build"' "$CONFIG_FILE")
    cmake_flags=$(jq -r '.native_component.build.cmake_flags // empty' "$CONFIG_FILE")
    cmake_flags=$(expand_path "$cmake_flags")
    make_targets=$(jq -r '.native_component.build.make_targets[]? // "all"' "$CONFIG_FILE" | tr '\n' ' ')
    parallel_make=$(jq -r '.native_component.build.parallel_make // true' "$CONFIG_FILE")
    
    build_cmake "$COMPONENT_DIR" "$build_dir" "$cmake_flags" "$make_targets" "$parallel_make" || return 1
    
    return 0
}

# Install libraries
install_libraries() {
    step "Installing libraries to $LIB_PATH"
    mkdir -p "$LIB_PATH"
    
    # Find and copy all library files (shared objects, static, libtool archives)
    find "$COMPONENT_DIR" \( -name "*.so*" -o -name "*.a" -o -name "*.la*" \) \( -type f -o -type l \) -exec cp -Pv {} "$LIB_PATH/" \; 2>/dev/null || true
    
    ok "Libraries installed"
    echo ""
}

# Main execution
main() {
    configure_environment
    
    # Process native headers
    if ! process_native_headers; then
        err "Header processing failed"
        exit 1
    fi
    
    # Apply patches
    if ! apply_source_patches; then
        err "Patch application failed"
        exit 1
    fi
    
    # Run pre-build commands
    if ! run_pre_build_commands; then
        err "Pre-build commands failed"
        exit 1
    fi

    # Build based on type
    case "$BUILD_TYPE" in
        autotools)
            if ! build_component_autotools; then
                err "Autotools build failed"
                exit 1
            fi
            ;;
            
        cmake)
            if ! build_component_cmake; then
                err "CMake build failed"
                exit 1
            fi
            ;;
            
        *)
            err "Unsupported build type: $BUILD_TYPE"
            exit 1
            ;;
    esac
    
    # Install libraries
    install_libraries
    
    print_banner "Native Component Build Completed Successfully"
    log "Component: $COMPONENT_NAME"
    log "Headers: $HEADER_PATH"
    log "Libraries: $LIB_PATH"
    echo ""
}

main
