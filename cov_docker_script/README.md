# Component Native Build Configuration

**Coverity/Native build configuration for RDK-B components.**

---

## 📋 Overview

This directory contains configuration files for building RDK-B components in a native (non-Yocto) environment. This setup enables Coverity static analysis and validates that components can be built with explicitly declared dependencies.

The build scripts are maintained in the `build_tools_workflows` repository and included as a git submodule.

### Directory Contents

```
<your-component>/
├── .gitmodules                       # Git submodule configuration
├── cov_docker_script/
│   ├── README.md                     # This file
│   ├── component_config.json         # Dependency & build configuration
│   └── configure_options.conf        # Autotools configure flags (optional)
└── build_tools_workflows/            # Git submodule (rdkcentral/build_tools_workflows)
    └── cov_docker_script/
        ├── build_native.sh           # Build main component
        ├── common_build_utils.sh     # Utility functions for other scripts
        ├── common_external_build.sh  # Combined setup + build script
        ├── setup_dependencies.sh     # Setup build tools & dependencies
        └── README.md                 # Detailed build tools documentation
```

### Important: Add to .gitignore

Add the following to your component's `.gitignore` to exclude temporary build artifacts:

```gitignore
# Dependency build artifacts
build/
```

### Required: Add build_tools_workflows as Git Submodule

The `build_tools_workflows` directory **must be tracked as a git submodule** in your repository. Add it using the following commands:

```bash
# Add build_tools_workflows as a submodule
git submodule add -b develop https://github.com/rdkcentral/build_tools_workflows.git build_tools_workflows

# Commit the .gitmodules file and submodule reference
git add .gitmodules build_tools_workflows
git commit -m "Add build_tools_workflows as submodule"
```

**Important:** When cloning your repository, always initialize and update submodules to ensure `build_tools_workflows` is available:

```bash
git clone --recurse-submodules <your-repo-url>
# OR
git clone <your-repo-url>
git submodule update --init --recursive
```

---

## 🚀 Quick Start

### Prerequisites

- Docker container with [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci) image
- Git submodules initialized

### Build Commands

#### Complete Build Pipeline

```bash
# From your component root directory
cd /path/to/your-component

# Initialize/update build_tools_workflows submodule
git submodule update --init --recursive --remote

# Step 1: Setup dependencies
./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json

# Step 2: Build component
./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"

# Clean build (removes previous artifacts)
CLEAN_BUILD=true ./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json
./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"
```

#### Alternative: Single-Script Build (All-in-One)

```bash
# Run setup dependencies + native build in one command
./build_tools_workflows/cov_docker_script/common_external_build.sh ./cov_docker_script/component_config.json

# Clean build
CLEAN_BUILD=true ./build_tools_workflows/cov_docker_script/common_external_build.sh ./cov_docker_script/component_config.json
```

**Note:** `common_external_build.sh` automatically detects the configuration file location and performs both dependency setup and component build in one execution.

---

## 📖 Build Scripts Reference

All build scripts are located in `build_tools_workflows/cov_docker_script/` and are maintained in the [rdkcentral/build_tools_workflows](https://github.com/rdkcentral/build_tools_workflows) repository.

### 1. setup_dependencies.sh

**Purpose:** Clone and build all external dependencies required by the component.

**Location:** `build_tools_workflows/cov_docker_script/setup_dependencies.sh`

**Usage:**
```bash
./build_tools_workflows/cov_docker_script/setup_dependencies.sh <path-to-component_config.json>

# Example
./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json
```

**What it does:**
1. Reads dependency list from `component_config.json`
2. Clones all dependency repositories to `$HOME/build/`
3. Copies header files to `$HOME/usr/include/rdkb/`
4. Builds and installs dependency libraries to `$HOME/usr/local/lib/` and `$HOME/usr/lib/`

**Environment Variables:**
- `BUILD_DIR` - Override build directory (default: `$HOME/build`)
- `USR_DIR` - Override install directory (default: `$HOME/usr`)
- `CLEAN_BUILD` - Set to `true` to remove previous builds before starting

**Outputs:**
- Dependency source code: `$HOME/build/<dependency-name>/`
- Headers: `$HOME/usr/include/rdkb/`
- Libraries: `$HOME/usr/local/lib/` and `$HOME/usr/lib/`

---

### 2. build_native.sh

**Purpose:** Build the main component using autotools, cmake, or meson.

**Location:** `build_tools_workflows/cov_docker_script/build_native.sh`

**Usage:**
```bash
./build_tools_workflows/cov_docker_script/build_native.sh <path-to-component_config.json> <component-directory>

# Example
./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"
```

**What it does:**
1. Reads build configuration from `component_config.json`
2. Applies source patches (if configured)
3. Processes component headers
4. Reads compiler/linker flags from `configure_options.conf`
5. Runs pre-build commands (if configured)
6. Configures and builds the component (autogen/configure/make or cmake/make)
7. Installs component libraries to `$HOME/usr/local/lib/`

**Prerequisites:**
- `setup_dependencies.sh` must be run first
- All dependency headers/libraries must be available

**Required files:**
- `component_config.json` - Build configuration
- `configure_options.conf` - Compiler/linker flags (for autotools builds)

**Outputs:**
- Component libraries in `$HOME/usr/local/lib/`
- Build artifacts in component root directory

---

### 3. common_external_build.sh

**Purpose:** Combined script that runs both dependency setup and component build.

**Location:** `build_tools_workflows/cov_docker_script/common_external_build.sh`

**Usage:**
```bash
./build_tools_workflows/cov_docker_script/common_external_build.sh [config-file]

# Example with explicit config
./build_tools_workflows/cov_docker_script/common_external_build.sh ./cov_docker_script/component_config.json

# Example with auto-detection
./build_tools_workflows/cov_docker_script/common_external_build.sh
```

**What it does:**
1. Auto-detects `component_config.json` location (if not provided)
2. Runs `setup_dependencies.sh` with the configuration
3. Runs `build_native.sh` with the configuration
4. Provides complete build pipeline in one command

**Use Cases:**
- **Main component builds:** Simplifies the build process into a single command
- **Dependency builds:** Used when a dependency repository has complex build requirements and is referenced in a parent component's `component_config.json` with `"type": "script"`

**Example in component_config.json (for dependency builds):**
```json
{
  "name": "Utopia",
  "repo": "https://github.com/rdkcentral/utopia.git",
  "branch": "develop",
  "build": {
    "type": "script",
    "script": "build_tools_workflows/cov_docker_script/common_external_build.sh"
  }
}
```

---

## 📝 Configuration Files

### component_config.json

**JSON configuration defining all dependencies and build settings.**

**Key Sections:**

1. **dependencies.repos[]** - External dependencies required by your component
   ```json
   {
     "name": "rbus",
     "repo": "https://github.com/rdkcentral/rbus.git",
     "branch": "v2.7.0",
     "header_paths": [...],
     "build": {...}
   }
   ```

2. **native_component** - Component build configuration
   ```json
   {
     "name": "your-component",
     "build": {
       "type": "autotools",
       "configure_options_file": "cov_docker_script/configure_options.conf"
     }
   }
   ```

**Example Dependencies:**
Your component may require dependencies such as:
- rbus
- rdk_logger
- safec
- common-library
- halinterface
- And other component-specific dependencies

See [component_config.json](component_config.json) for your component's specific dependency configuration.

---

### configure_options.conf

**Autotools configuration file with preprocessor, compiler, and linker flags.**

**Format:**
```properties
[CPPFLAGS]
-I$HOME/usr/include/rdkb/
-DFEATURE_FLAG

[CFLAGS]
-Wall -Wextra

[LDFLAGS]
-L$HOME/usr/local/lib/
```

**Sections:**
- `[CPPFLAGS]` - Preprocessor flags (includes `-I`, defines `-D`)
- `[CFLAGS]` - C compiler flags
- `[CXXFLAGS]` - C++ compiler flags
- `[LDFLAGS]` - Linker flags (library paths `-L`, linker options `-Wl`)

**Component-Specific Flags:**
Customize flags based on your component's requirements:
- Platform defines: `_COSA_INTEL_USG_ARM_`, `_COSA_BCM_ARM_`, etc.
- Product defines: `_XB6_PRODUCT_REQ_`, `_XB7_PRODUCT_REQ_`, etc.
- Feature flags: `FEATURE_SUPPORT_RDKLOG`, component-specific features, etc.

See [configure_options.conf](configure_options.conf) for your component's complete flag list.

---

## 🔧 Build System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Git Submodule: build_tools_workflows (develop branch)     │
│  https://github.com/rdkcentral/build_tools_workflows       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│         setup_dependencies.sh                               │
│  build_tools_workflows/cov_docker_script/                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Input: ./cov_docker_script/component_config.json      │  │
│  │                                                        │  │
│  │ 1. Read dependencies from component_config.json       │  │
│  │ 2. Clone dependency repositories to $HOME/build/      │  │
│  │ 3. Copy headers to $HOME/usr/include/rdkb/            │  │
│  │ 4. Build dependencies (autotools/cmake/meson)         │  │
│  │ 5. Install libraries to $HOME/usr/local/lib/          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│         build_native.sh                                     │
│  build_tools_workflows/cov_docker_script/                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Input: ./cov_docker_script/component_config.json      │  │
│  │        $(pwd)  # Component directory                  │  │
│  │                                                        │  │
│  │ 1. Process component headers                          │  │
│  │ 2. Apply source patches (if configured)               │  │
│  │ 3. Run pre-build commands (if configured)             │  │
│  │ 4. Read configure_options.conf                        │  │
│  │ 5. Configure build (autogen/configure or cmake)       │  │
│  │ 6. Build component (make)                             │  │
│  │ 7. Install libraries to $HOME/usr/local/lib/          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Alternative: Single-Command Build**

```
┌─────────────────────────────────────────────────────────────┐
│         common_external_build.sh                            │
│  build_tools_workflows/cov_docker_script/                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Auto-detects component_config.json                    │  │
│  │                                                        │  │
│  │ 1. Run setup_dependencies.sh                          │  │
│  │ 2. Run build_native.sh                                │  │
│  │                                                        │  │
│  │ Complete pipeline in one command                      │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting

### Build Failures

**Problem:** Missing headers

```bash
# Solution: Check if dependencies were installed
ls -la $HOME/usr/include/rdkb/

# Verify component_config.json has correct header_paths
cat ./cov_docker_script/component_config.json | jq '.dependencies.repos[].header_paths'

# Re-run dependency setup
CLEAN_BUILD=true ./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json
```

**Problem:** Missing libraries

```bash
# Solution: Check library installation
ls -la $HOME/usr/local/lib/
ls -la $HOME/usr/lib/

# Verify PKG_CONFIG_PATH
echo $PKG_CONFIG_PATH

# Check if dependency build failed
cd $HOME/build/<dependency-name>
cat config.log  # For autotools
cat build/meson-log.txt  # For meson
```

**Problem:** Configure errors

```bash
# Solution: Check configure_options.conf syntax
cat ./cov_docker_script/configure_options.conf

# Verify flags are valid
./configure --help
```

**Problem:** build_tools_workflows not found

```bash
# Solution: Initialize git submodules
git submodule update --init --recursive --remote

# Verify submodule is present
ls -la build_tools_workflows/cov_docker_script/
```

### Script Errors

**Problem:** Permission denied

```bash
# Solution: Make scripts executable
chmod +x build_tools_workflows/cov_docker_script/*.sh
```

**Problem:** Permission denied

```bash
# Solution: Fix container permissions
# (Run on host, not in container)
sudo docker exec <container-name> chown -R $(id -u):$(id -g) /path/to/workspace
```

---

## 🔄 Workflow Integration

### CI/CD Integration (GitHub Actions)

This configuration is used by GitHub Actions to validate builds. See [.github/workflows/native-build.yml](.github/workflows/native-build.yml):

```yaml
- name: Checkout code
  uses: actions/checkout@v3

- name: native build
  run: |
    # Trust the workspace
    git config --global --add safe.directory '*'
    
    # Pull the latest changes for the native build system
    git submodule update --init --recursive --remote
    
    # Build and install dependencies
    chmod +x build_tools_workflows/cov_docker_script/setup_dependencies.sh
    ./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json
    
    # Build component
    chmod +x build_tools_workflows/cov_docker_script/build_native.sh
    ./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"
```

### Local Development

```bash
# Make changes to source code
vim source/your_component.c

# Rebuild component (dependencies already built)
./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"

# Clean rebuild (rebuild dependencies too)
CLEAN_BUILD=true ./build_tools_workflows/cov_docker_script/setup_dependencies.sh ./cov_docker_script/component_config.json
./build_tools_workflows/cov_docker_script/build_native.sh ./cov_docker_script/component_config.json "$(pwd)"
```

---

## � Related Documentation

- **Build Tools Repository:** [build_tools_workflows](https://github.com/rdkcentral/build_tools_workflows/tree/develop)
- **Docker Environment:** [docker-rdk-ci](https://github.com/rdkcentral/docker-rdk-ci)
- **Detailed Build Guide:** See `build_tools_workflows/cov_docker_script/README.md`

---

## ⚠️ Important Notes

### DO NOT Modify Scripts in build_tools_workflows

The scripts in `build_tools_workflows/` are maintained as a git submodule and **must not be modified locally**:

- ❌ `build_tools_workflows/cov_docker_script/build_native.sh`
- ❌ `build_tools_workflows/cov_docker_script/common_build_utils.sh`
- ❌ `build_tools_workflows/cov_docker_script/common_external_build.sh`
- ❌ `build_tools_workflows/cov_docker_script/setup_dependencies.sh`

Changes to these scripts should be made in the [rdkcentral/build_tools_workflows](https://github.com/rdkcentral/build_tools_workflows) repository.

### DO Modify Component Configuration

The following files are component-specific and **should be customized**:

- ✅ `cov_docker_script/component_config.json` - Dependency and build configuration
- ✅ `cov_docker_script/configure_options.conf` - Autotools compiler/linker flags

---

**Last Updated:** February 2026
