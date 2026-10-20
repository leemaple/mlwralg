#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dependency_dir="${MLWR_DEPENDENCY_DIR:-$project_dir/.deps}"
source_dir="$dependency_dir/openfhe-src"
port_id="$(python3 - "$project_dir" <<'PY'
import hashlib,sys
from pathlib import Path
p=Path(sys.argv[1]);h=hashlib.sha256()
for f in ['scripts/patch_openfhe_sparse.py','patches/openfhe-p03-small.inc']:
 h.update((p/f).read_bytes())
print(h.hexdigest()[:16])
PY
)"
port_source="$dependency_dir/p03-$port_id-src"
port_build="$dependency_dir/p03-$port_id-build"
port_install="$dependency_dir/p03-$port_id-install"
commit=b59e1f291965f14fbee5172cd83a20f5b856204f
mkdir -p "$dependency_dir"
if [[ ! -d "$source_dir/.git" ]]; then
    git clone --depth 1 --branch v1.6.1 https://github.com/openfheorg/openfhe-development.git "$source_dir"
fi
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$commit" ]]
git -C "$source_dir" diff --exit-code "$commit" -- src
git -C "$source_dir" submodule update --init --depth 1 third-party/cereal
if [[ ! -e "$port_source" ]]; then
    python3 - "$source_dir" "$port_source" <<'PY'
import shutil,sys
shutil.copytree(sys.argv[1],sys.argv[2],ignore=shutil.ignore_patterns('.git'))
PY
    python3 "$project_dir/scripts/patch_openfhe_sparse.py" "$port_source"
fi
cmake -S "$port_source" -B "$port_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$port_install" \
    -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
    -DBUILD_EXTRAS=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF \
    -DGIT_SUBMOD_AUTO=OFF -DWITH_OPENMP=OFF -DNATIVE_SIZE=64 \
    -DCMAKE_CXX_FLAGS=-DBOOTSTRAPTIMING
cmake --build "$port_build" --parallel "${MLWR_BUILD_JOBS:-4}"
cmake --install "$port_build"
python3 - "$project_dir" "$port_source" "$port_install" "$commit" <<'PY'
import hashlib,json,sys
from pathlib import Path
root,src,install=map(Path,sys.argv[1:4])
files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [
 root/'scripts/patch_openfhe_sparse.py',root/'patches/openfhe-p03-small.inc',
 src/'src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp']}
(install/'mlwr-port-manifest.json').write_text(json.dumps({'upstream_commit':sys.argv[4],
 'files':files,'native_bits':64,'openmp':False,'bootstrap_timing':True,
 'helper_sha256':hashlib.sha256((root/'patches/openfhe-p03-small.inc').read_bytes()).hexdigest(),
 'patcher_sha256':hashlib.sha256((root/'scripts/patch_openfhe_sparse.py').read_bytes()).hexdigest(),
 'patched_fhe_sha256':hashlib.sha256((src/'src/pke/lib/scheme/ckksrns/ckksrns-fhe.cpp').read_bytes()).hexdigest(),
 'pke_library_sha256':hashlib.sha256((install/'lib/libOPENFHEpke_static.a').read_bytes()).hexdigest()},indent=2))
PY
printf '%s\n' "$port_install/lib/OpenFHE" > "$dependency_dir/p03-openfhe-dir.txt"
printf 'OpenFHE_DIR=%s\n' "$port_install/lib/OpenFHE"
