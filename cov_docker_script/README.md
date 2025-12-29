# Coverity Build System for RDK-B Components

**Generic, reusable build system for any RDK-B component.** Just copy the scripts and customize `component_config.json`.

## Quick Start

### Complete Build (Recommended)

```bash
cd /path/to/component/cov_docker_script
./common_external_build.sh
```

This runs the complete 2-step pipeline:
1. **Setup Dependencies** - Clones repos, copies headers, builds libraries
2. **Build Component** - Applies patches, builds component, installs libraries

### Clean Build

```bash
CLEAN_BUILD=true ./common_external_build.sh
```

Removes all previous build artifacts before starting.

## Scripts Overview

### 1. common_build_utils.sh

**Purpose:** Shared utility library with common functions used by all build scripts.

**Key Functions:**
- `log()`, `ok()`, `warn()`, `err()`, `step()` - Color-coded logging
- `expand_path()` - Expands `$HOME` variables in paths
- `check_dependencies()` - Validates required system tools (git, jq, gcc, make)
- `clone_repo()` - Clones git repositories with depth 1
- `copy_headers()` - Copies header files from source to destination
- `apply_patch()` - Applies patches using Python3 for safe string replacement
- `build_autotools()`, `build_cmake()`, `build_meson()` - Build functions for different systems
- `execute_commands()` - Runs custom command sequences
- `copy_libraries()` - Finds and copies library files (.so, .a, .la)

**Usage:**
```bash
# This script is sourced by other scripts, not run directly
source common_build_utils.sh
```

**Auto-configured:**
- Validates presence of git, jq, gcc, make
- Sets up color-coded terminal output
- Exports all functions for use in other scripts

---

### 2. setup_dependencies.sh

**Purpose:** Clones dependency repositories, copies headers, and builds required libraries.

**What it does:**
1. Reads dependency list from `component_config.json`
2. Clones each repository to `$HOME/build/<repo-name>`
3. Copies headers to `$HOME/usr/include/rdkb/`
4. Builds libraries (if `build` section present)
5. Installs libraries to `$HOME/usr/local/lib/` and `$HOME/usr/lib/`
6. Configures PKG_CONFIG_PATH and LD_LIBRARY_PATH

**Usage:**
```bash
# Use default config (component_config.json in same directory)
./setup_dependencies.sh

# Use custom config file
./setup_dependencies.sh /path/to/custom_config.json

# Clean build (removes $HOME/build and $HOME/usr first)
CLEAN_BUILD=true ./setup_dependencies.sh

# Custom directories
BUILD_DIR=/tmp/build USR_DIR=/opt/rdkb ./setup_dependencies.sh
```

**Environment Variables:**
- `BUILD_DIR` - Where to clone repos (default: `$HOME/build`)
- `USR_DIR` - Install directory (default: `$HOME/usr`)
- `CLEAN_BUILD` - Set to `true` to remove previous artifacts

**Output:**
- Headers: `$HOME/usr/include/rdkb/`
- Libraries: `$HOME/usr/local/lib/` and `$HOME/usr/lib/`

---

### 3. build_native.sh

**Purpose:** Builds the native component after dependencies are setup.

**What it does:**
1. Reads component configuration from `component_config.json`
2. Processes native component headers (copies to destination)
3. Applies source patches (if configured)
4. Configures build environment (PKG_CONFIG_PATH, LD_LIBRARY_PATH, CPPFLAGS, LDFLAGS)
5. Runs autogen.sh or autoreconf (for autotools)
6. Executes configure/cmake with specified options
7. Builds component with make (parallel by default)
8. Copies libraries to configured output path

**Usage:**
```bash
# Use defaults (assumes setup_dependencies.sh already run)
./build_native.sh

# Specify custom config and component directory
./build_native.sh /path/to/config.json /path/to/component

# With environment overrides
HEADER_PATH=/custom/include ./build_native.sh
```

**Prerequisites:**
- `setup_dependencies.sh` must have run successfully
- Headers and libraries must be in `$HOME/usr/`

**Output:**
- Component libraries in path specified by `native_component.lib_output_path`
- Default: `$HOME/usr/local/lib/`

---

### 4. common_external_build.sh

**Purpose:** Orchestrates complete build pipeline (dependencies + component).

**What it does:**
1. Validates configuration and paths
2. Runs `setup_dependencies.sh` (Step 1/2)
3. Runs `build_native.sh` (Step 2/2)
4. Displays progress banners and status

**Usage:**
```bash
# Complete build with defaults
./common_external_build.sh

# With custom config and component directory
./common_external_build.sh /path/to/config.json /path/to/component

# Clean build
CLEAN_BUILD=true ./common_external_build.sh
```

**This is the recommended entry point for complete builds.**

**Output:**
- Complete dependency setup
- Built component with all libraries
- Success/failure status for entire pipeline

---

### 5. component_config.json

**Purpose:** JSON configuration defining all dependencies and build settings.

**Key Sections:**
- `dependencies.repos[]` - List of dependency repositories
- `native_component` - Component-specific build configuration
- `source_patches[]` - Patches to apply before building

**Not a script, but required by all build scripts.**

See **Configuration** section below for detailed format.

---

## Configuration

All build configuration is in **`component_config.json`**. This file defines:
- Dependencies to clone and build
- Headers to copy
- Patches to apply
- Build settings

### Key Configuration Sections

#### Dependencies

```json
{
  "dependencies": {
    "repos": [
      {
        "name": "repo-name",
        "repo": "https://github.com/org/repo.git",
        "branch": "main",
        "header_paths": [
          { "source": "include", "destination": "$HOME/usr/include/rdkb" }
        ],
        "build": {
          "type": "autotools|cmake|meson|commands|script",
          "configure_flags": "--prefix=$HOME/usr",
          "parallel_make": true
        }
      }
    ]
  }
}
```

**Note:** The `build` section is optional - omit it for header-only dependencies.

#### Native Component

```json
{
  "native_component": {
    "name": "component-name",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "header_sources": [
      { "source": "source/ccsp/include", "destination": "$HOME/usr/include/rdkb" },
      { "source": "source/cosa/include", "destination": "$HOME/usr/include/rdkb" }
    ],
    "source_patches": [
      {
        "file": "$HOME/usr/include/rdkb/header.h",
        "type": "replace",
        "search": "old text",
        "replace": "new text"
      }
    ],
    "build": {
      "type": "autotools|cmake",
      "configure_options": [
        "CPPFLAGS=-I$HOME/usr/include/rdkb",
        "LDFLAGS=-L$HOME/usr/lib"
      ]
    }
  }
}
```

**Configuration Details:**
- `header_sources[]` - Component headers to copy before building. Source paths are relative to component directory.
- `source_patches[]` - Patches to apply after headers are copied. Use absolute paths with `$HOME` for files in install directories.
- `include_path` - Colon-separated include paths for building
- `lib_output_path` - Where to install built libraries

## Build Types

### Autotools
```json
"build": {
  "type": "autotools",
  "configure_flags": "--prefix=$HOME/usr --enable-feature"
}
```

### CMake
```json
"build": {
  "type": "cmake",
  "build_dir": "build",
  "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr"
}
```

### Meson
```json
"build": {
  "type": "meson",
  "meson_flags": "--prefix=$HOME/usr"
}
```

### Custom Commands
```json
"build": {
  "type": "commands",
  "commands": ["meson setup build --prefix=$HOME/usr", "meson compile -C build"]
}
```

### Custom Script
```json
"build": {
  "type": "script",
  "script": "cov_docker_script/build.sh"
}
```

## Troubleshooting

### Build fails with "command not found"
**Install required tools:**
```bash
sudo apt-get install git jq gcc make autoconf automake libtool cmake python3
```

### Dependencies fail to build
- Check `$HOME/build/<repo-name>` for build logs
- Verify `configure_flags` in JSON are correct
- Ensure system packages for build type are installed (cmake, meson, etc.)

### Headers not found during component build
- Verify `setup_dependencies.sh` completed successfully
- Check `$HOME/usr/include/rdkb/` contains expected headers
- Verify `header_paths` in JSON point to correct source directories

### Libraries not found
- Check library directories:
  - `$HOME/usr/local/lib/` - Primary location
  - `$HOME/usr/lib/` - Secondary location
- Verify dependencies built successfully (look for `.so`, `.a` files)
- Check build logs for `make install` errors

### Patches fail to apply
- **File not found:** Verify file path is relative to component directory
- **Use `../`** for files outside component (e.g., `../usr/include/rdkb/header.h`)
- **Exact match required:** Search string must exactly match file content
- **Python3 required:** Ensure Python3 is installed

### Clean build needed
```bash
# Remove all previous build artifacts
CLEAN_BUILD=true ./common_external_build.sh
```

### Validate configuration
```bash
# Check JSON syntax
jq . component_config.json

# List all dependencies
jq '.dependencies.repos[].name' component_config.json
```

## Directory Structure After Build

```
$HOME/
├── build/              # Cloned repositories (removed after build)
└── usr/
    ├── include/
    │   └── rdkb/       # All dependency headers
    ├── lib/            # Secondary library location
    └── local/
        └── lib/        # Primary library location (.so, .a files)
```

## Environment Variables

These are automatically configured by the scripts:

- `BUILD_DIR` - Repository clone location (default: `$HOME/build`)
- `USR_DIR` - Install directory (default: `$HOME/usr`)
- `PKG_CONFIG_PATH` - Configured for dependency detection
- `LD_LIBRARY_PATH` - Configured for runtime linking
- `CPPFLAGS` - Include paths for compilation
- `LDFLAGS` - Library paths for linking
- `CLEAN_BUILD` - Set to `true` to clean before build

## Required System Tools

- `bash` (version 4.0+)
- `git` - Repository cloning
- `jq` - JSON parsing
- `gcc`/`g++` - C/C++ compiler
- `make` - Build automation
- `python3` - Patch application

**Optional (based on dependency types):**
- `autoconf`, `automake`, `libtool` - For autotools builds
- `cmake` - For CMake builds
- `meson`, `ninja` - For Meson builds
- `pkg-config` - For dependency detection

---

## Adopting for Another Component

**These scripts are 100% generic and component-agnostic.** To use them for a different component:

### Step 1: Copy the Scripts

```bash
# Copy all scripts to your component's build directory
cp common_build_utils.sh setup_dependencies.sh build_native.sh common_external_build.sh /path/to/new-component/cov_docker_script/

# Make executable
chmod +x /path/to/new-component/cov_docker_script/*.sh
```

### Step 2: Create component_config.json

Create a new `component_config.json` for your component:

```json
{
  "_comment": "Component Build Configuration",
  "_version": "2.0",
  
  "dependencies": {
    "repos": [
      {
        "name": "your-dependency",
        "repo": "https://github.com/org/your-dependency.git",
        "branch": "main",
        "header_paths": [
          { "source": "include", "destination": "$HOME/usr/include/rdkb" }
        ],
        "build": {
          "type": "cmake",
          "cmake_flags": "-DCMAKE_INSTALL_PREFIX=$HOME/usr"
        }
      }
    ]
  },
  
  "native_component": {
    "name": "your-component-name",
    "include_path": "$HOME/usr/include/rdkb/",
    "lib_output_path": "$HOME/usr/local/lib/",
    "source_patches": [],
    "build": {
      "type": "autotools",
      "configure_options": [
        "CPPFLAGS=-I$HOME/usr/include/rdkb",
        "LDFLAGS=-L$HOME/usr/local/lib"
      ]
    }
  }
}
```

### Step 3: Run the Build

```bash
cd /path/to/new-component/cov_docker_script
./common_external_build.sh
```

**That's it!** No script modifications needed. The scripts automatically:
- Read component name from JSON
- Find component directory (parent of script directory)
- Clone dependencies listed in JSON
- Copy headers from paths specified in JSON
- Build using build type specified in JSON
- Apply patches listed in JSON

### What Makes These Scripts Generic?

✅ **No hardcoded paths** - All paths from JSON or environment variables  
✅ **No hardcoded component names** - Component name read from JSON  
✅ **No hardcoded dependencies** - All dependencies defined in JSON  
✅ **No hardcoded build commands** - Build type and options from JSON  
✅ **Flexible build systems** - Supports autotools, cmake, meson, custom commands, custom scripts  
✅ **Configurable patches** - All patches defined in JSON  

### Example: Migrating from Utopia to CcspPandM

```bash
# 1. Copy scripts to CcspPandM
cp utopia/cov_docker_script/*.sh ccsp-p-and-m/cov_docker_script/

# 2. Create ccsp-p-and-m/cov_docker_script/component_config.json
# Update: component name, dependencies, build settings

# 3. Run build
cd ccsp-p-and-m/cov_docker_script
./common_external_build.sh
```

**Scripts remain unchanged - only JSON changes!**

---
