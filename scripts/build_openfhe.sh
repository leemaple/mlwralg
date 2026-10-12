#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dependency_dir="${MLWR_DEPENDENCY_DIR:-$project_dir/.deps}"
source_dir="$dependency_dir/openfhe-src"
build_dir="$dependency_dir/openfhe-build"
install_dir="$dependency_dir/openfhe-install"
openfhe_commit=b59e1f291965f14fbee5172cd83a20f5b856204f

mkdir -p "$dependency_dir"
if [[ ! -d "$source_dir/.git" ]]; then
    git clone --depth 1 --branch v1.6.1 \
        https://github.com/openfheorg/openfhe-development.git "$source_dir"
fi
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$openfhe_commit" ]]; then
    printf '%s\n' "OpenFHE checkout does not match pinned commit $openfhe_commit" >&2
    exit 1
fi
git -C "$source_dir" submodule update --init --depth 1 third-party/cereal
cmake -S "$source_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$install_dir" \
    -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
    -DBUILD_EXTRAS=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF \
    -DGIT_SUBMOD_AUTO=OFF -DWITH_OPENMP=OFF -DNATIVE_SIZE=64
cmake --build "$build_dir" --parallel "${MLWR_BUILD_JOBS:-4}"
cmake --install "$build_dir"
printf 'OpenFHE_DIR=%s\n' "$install_dir/lib/OpenFHE"
