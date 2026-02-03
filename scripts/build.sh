#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="build"
jobs=""
cmake_args=()
tls_choice=""

if command -v getconf >/dev/null 2>&1; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
elif command -v sysctl >/dev/null 2>&1; then
  jobs="$(sysctl -n hw.ncpu 2>/dev/null || true)"
fi
if [ -z "${jobs}" ]; then
  jobs=4
fi

usage() {
  cat <<'EOF'
Usage: scripts/build.sh [debug] [tls] [options]

TLS options (choose one, default: openssl):
  openssl | mbedtls | wolfssl | libressl | boringssl | awslc | openhitls

Options:
  -h, --help  Show help

Environment variables:
  OPENHITLS_INCLUDE_DIRS  OpenHITLS include dirs (semicolon-separated)
  OPENHITLS_LIBRARIES     OpenHITLS libraries (semicolon-separated)

Examples:
  scripts/build.sh
  scripts/build.sh debug
  scripts/build.sh openssl
  scripts/build.sh debug mbedtls
  OPENHITLS_INCLUDE_DIRS=/path/include OPENHITLS_LIBRARIES=/path/lib/libopenhitls.so \\
    scripts/build.sh openhitls
EOF
}

for arg in "$@"; do
  case "${arg}" in
    debug)
      cmake_args+=("-DCMAKE_BUILD_TYPE=DEBUG")
      ;;
    openssl|mbedtls|wolfssl|libressl|boringssl|awslc|openhitls)
      if [ -n "${tls_choice}" ] && [ "${tls_choice}" != "${arg}" ]; then
        echo "Only one TLS option is allowed: already set to '${tls_choice}'" >&2
        exit 2
      fi
      tls_choice="${arg}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${tls_choice}" in
  "") ;; # default OpenSSL
  openssl) ;;
  mbedtls) cmake_args+=("-DLWS_WITH_MBEDTLS=1") ;;
  wolfssl) cmake_args+=("-DLWS_WITH_WOLFSSL=1") ;;
  libressl) cmake_args+=("-DLWS_WITH_LIBRESSL=1") ;;
  boringssl) cmake_args+=("-DLWS_WITH_BORINGSSL=1") ;;
  awslc) cmake_args+=("-DLWS_WITH_AWSLC=1") ;;
  openhitls)
    cmake_args+=("-DLWS_WITH_OPENHITLS=1")
    if [ -n "${OPENHITLS_INCLUDE_DIRS:-}" ]; then
      cmake_args+=("-DOPENHITLS_INCLUDE_DIRS=${OPENHITLS_INCLUDE_DIRS}")
    fi
    if [ -n "${OPENHITLS_LIBRARIES:-}" ]; then
      cmake_args+=("-DOPENHITLS_LIBRARIES=${OPENHITLS_LIBRARIES}")
    fi
    ;;
esac

rm -rf "${repo_root}/${build_dir}"
if [ ${#cmake_args[@]} -gt 0 ]; then
  cmake -S "${repo_root}" -B "${repo_root}/${build_dir}" "${cmake_args[@]}"
else
  cmake -S "${repo_root}" -B "${repo_root}/${build_dir}"
fi
cmake --build "${repo_root}/${build_dir}" -- -j"${jobs}"
