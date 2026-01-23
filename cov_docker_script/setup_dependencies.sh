#!/usr/bin/env bash
set -e

################################################################################
# Generic Dependency Setup Script
# Usage: ./setup_dependencies.sh [config_file]
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-$SCRIPT_DIR/component_config.json}"

# Source common utilities
source "$SCRIPT_DIR/common_build_utils.sh"

# Default directories
BUILD_DIR="${BUILD_DIR:-$HOME/build}"
USR_DIR="${USR_DIR:-$HOME/usr}"

# Validate environment
if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Config file not found: $CONFIG_FILE"
    exit 1
fi

check_dependencies || exit 1

# Initialize environment
initialize_environment() {
    print_banner "Dependency Setup"
    
    log "Configuration: $CONFIG_FILE"
    log "Build directory: $BUILD_DIR"
    log "Install directory: $USR_DIR"
    echo ""
    
    # Clean if requested
    if [[ "${CLEAN_BUILD:-false}" == "true" ]]; then
        warn "Cleaning previous build artifacts"
        [[ -d "$BUILD_DIR" ]] && rm -rf "$BUILD_DIR"
        [[ -d "$USR_DIR" ]] && rm -rf "$USR_DIR"
    fi
    
    # Create directories
    mkdir -p "$BUILD_DIR"
    mkdir -p "$USR_DIR/include/rdkb"
    mkdir -p "$USR_DIR/local/lib"
    mkdir -p "$USR_DIR/local/lib/pkgconfig"
    mkdir -p "$USR_DIR/lib"
    
    # Setup PKG_CONFIG_PATH and LD_LIBRARY_PATH for dependencies
    export PKG_CONFIG_PATH="$USR_DIR/local/lib/pkgconfig:$USR_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="$USR_DIR/local/lib:$USR_DIR/lib:${LD_LIBRARY_PATH:-}"
    export CPPFLAGS="${CPPFLAGS:-} -I$USR_DIR/include"
    export LDFLAGS="${LDFLAGS:-} -L$USR_DIR/local/lib"
    
    log "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
    log "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
    echo ""
    
    ok "Environment initialized"
}

# Process header paths for a repository
process_headers() {
    local index="$1"
    local repo_dir="$2"
    local name="$3"
    
    local count
    count=$(jq ".dependencies.repos[$index].header_paths | length" "$CONFIG_FILE")
    
    if [[ "$count" -eq 0 ]]; then
        log "No headers configured for $name"
        return 0
    fi
    
    local i=0
    while [[ $i -lt $count ]]; do
        local src dst
        src=$(jq -r ".dependencies.repos[$index].header_paths[$i].source" "$CONFIG_FILE")
        dst=$(jq -r ".dependencies.repos[$index].header_paths[$i].destination" "$CONFIG_FILE")
        
        copy_headers "$repo_dir/$src" "$dst"
        i=$((i + 1))
    done
    
    return 0
}

# Build a repository
build_repository() {
    local index="$1"
    local repo_dir="$2"
    local name="$3"
    
    local build_type
    build_type=$(jq -r ".dependencies.repos[$index].build.type // empty" "$CONFIG_FILE")
    
    if [[ -z "$build_type" ]]; then
        log "No build configuration for $name (headers only)"
        return 0
    fi
    
    step "Building $name (type: $build_type)"
    
    case "$build_type" in
        autotools)
            local configure_flags make_targets parallel_make
            configure_flags=$(jq -r ".dependencies.repos[$index].build.configure_flags // empty" "$CONFIG_FILE")
            make_targets=$(jq -r ".dependencies.repos[$index].build.make_targets[]? // \"all\"" "$CONFIG_FILE" | tr '\n' ' ')
            parallel_make=$(jq -r ".dependencies.repos[$index].build.parallel_make // true" "$CONFIG_FILE")
            
            build_autotools "$repo_dir" "$configure_flags" "$make_targets" "$parallel_make" || return 1
            ;;
            
        cmake)
            local build_dir cmake_flags make_targets parallel_make
            build_dir=$(jq -r ".dependencies.repos[$index].build.build_dir // \"build\"" "$CONFIG_FILE")
            cmake_flags=$(jq -r ".dependencies.repos[$index].build.cmake_flags // empty" "$CONFIG_FILE")
            make_targets=$(jq -r ".dependencies.repos[$index].build.make_targets[]? // \"all\"" "$CONFIG_FILE" | tr '\n' ' ')
            parallel_make=$(jq -r ".dependencies.repos[$index].build.parallel_make // true" "$CONFIG_FILE")
            
            build_cmake "$repo_dir" "$build_dir" "$cmake_flags" "$make_targets" "$parallel_make" || return 1
            ;;
            
        meson)
            local build_dir meson_flags ninja_targets
            build_dir=$(jq -r ".dependencies.repos[$index].build.build_dir // \"builddir\"" "$CONFIG_FILE")
            meson_flags=$(jq -r ".dependencies.repos[$index].build.meson_flags // empty" "$CONFIG_FILE")
            ninja_targets=$(jq -r ".dependencies.repos[$index].build.ninja_targets[]? // \"all\"" "$CONFIG_FILE" | tr '\n' ' ')
            
            build_meson "$repo_dir" "$build_dir" "$meson_flags" "$ninja_targets" || return 1
            ;;
            
        commands)
            execute_commands "$repo_dir" "$CONFIG_FILE" "$index" || return 1
            ;;
            
        script)
            local script_path
            script_path=$(jq -r ".dependencies.repos[$index].build.script" "$CONFIG_FILE")
            local full_script="$repo_dir/$script_path"
            
            if [[ -f "$full_script" ]]; then
                step "Executing build script: $script_path"
                chmod +x "$full_script"
                
                export PARENT_BUILD_DIR="$BUILD_DIR"
                export PARENT_USR_DIR="$USR_DIR"
                
                pushd "$repo_dir" >/dev/null || return 1
                if ! "$full_script"; then
                    err "Build script failed"
                    popd >/dev/null
                    return 1
                fi
                popd >/dev/null
                
                unset PARENT_BUILD_DIR PARENT_USR_DIR
            else
                err "Build script not found: $full_script"
                return 1
            fi
            ;;
            
        *)
            err "Unknown build type: $build_type"
            return 1
            ;;
    esac
    
    # Copy libraries
    copy_libraries "$repo_dir" "$USR_DIR/local/lib"
    copy_libraries "$repo_dir" "$USR_DIR/lib"
    
    ok "$name build completed"
    return 0
}

# Process a single dependency
process_dependency() {
    local index="$1"
    
    local name repo branch
    name=$(jq -r ".dependencies.repos[$index].name" "$CONFIG_FILE")
    repo=$(jq -r ".dependencies.repos[$index].repo" "$CONFIG_FILE")
    branch=$(jq -r ".dependencies.repos[$index].branch" "$CONFIG_FILE")
    
    local repo_dir="$BUILD_DIR/$name"
    
    print_section "Processing: $name"
    
    # Clone repository
    if ! clone_repo "$name" "$repo" "$branch" "$repo_dir"; then
        err "Failed to process $name"
        return 1
    fi
    
    # Copy headers
    if ! process_headers "$index" "$repo_dir" "$name"; then
        err "Failed to copy headers for $name"
        return 1
    fi
    
    # Build if needed
    if ! build_repository "$index" "$repo_dir" "$name"; then
        err "Failed to build $name"
        return 1
    fi
    
    ok "$name processed successfully"
    return 0
}

# Main execution
main() {
    initialize_environment
    
    local count
    count=$(jq ".dependencies.repos | length" "$CONFIG_FILE")
    
    log "Found $count dependencies to process"
    echo ""
    
    local i=0
    while [[ $i -lt $count ]]; do
        if ! process_dependency "$i"; then
            err "Dependency setup failed"
            exit 1
        fi
        i=$((i + 1))
    done
    
    echo ""
    print_banner "Dependencies Setup Completed Successfully"
    log "Headers installed: $USR_DIR/include/rdkb"
    log "Libraries installed: $USR_DIR/local/lib and $USR_DIR/lib"
    echo ""
}

main
