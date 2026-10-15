#!/usr/bin/env bash
#
# Linux / CI 构建脚本 —— 与 Windows 的 build_pack.ps1 等价（同样的 clang 参数与 zip 布局）
#
# 用法:
#   ANDROID_NDK_ROOT=/opt/android-ndk-r26d ./build_linux.sh [输出目录]
#
# 成功时最后一行 stdout 为产物 zip 的绝对路径，其余日志一律走 stderr。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT_DIR="${1:-$SCRIPT_DIR/dist}"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log "$*"; exit 1; }

command -v zip >/dev/null || die "缺少 zip 命令"
[[ -f magisk/module.prop ]] || die "找不到 magisk/module.prop，请在本脚本所在目录运行"

: "${ANDROID_NDK_ROOT:?请设置 ANDROID_NDK_ROOT 指向 Android NDK}"
TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64"
CLANG="$TOOLCHAIN/bin/clang++"
SYSROOT="--sysroot=$TOOLCHAIN/sysroot"
[[ -x "$CLANG" ]] || die "找不到 clang++: $CLANG"
log "工具链 $("$CLANG" --version | head -1)"

# 与 build_pack.ps1 第 23 行保持一致
read -r -a CPPFLAGS <<<"-std=c++20 -static -s -Ofast -Wall -Wextra -Wshadow -fno-exceptions -fno-rtti -DNDEBUG -fPIE"

prop() { sed -n "s/^$1=//p" magisk/module.prop | head -1 | tr -d '\r'; }
ID="$(prop id)"
VERSION="$(prop version)"
VERSION_CODE="$(prop versionCode)"
[[ -n "$ID" && -n "$VERSION" ]] || die "解析 magisk/module.prop 失败"
ZIP_NAME="${ID}_v${VERSION}.zip"
log "模块 $ID  版本 $VERSION ($VERSION_CODE)"

compile() { # $1 = target triple, $2 = 输出文件名
    log "编译 $2  <- $1"
    "$CLANG" "--target=$1" "$SYSROOT" "${CPPFLAGS[@]}" -Iinclude src/main.cpp -o "magisk/$2"
    log "  -> magisk/$2  $(stat -c %s "magisk/$2") bytes"
}

compile aarch64-none-linux-android31 "${ID}ARM64"

# 只发布 ARM64；清掉可能残留的 X64 产物，避免被打进 zip
rm -f "magisk/${ID}X64"

cp -f changelog.txt magisk/changelog.txt

mkdir -p "$OUT_DIR"
ZIP_PATH="$(cd "$OUT_DIR" && pwd)/$ZIP_NAME"
rm -f "$ZIP_PATH"

# 与 `7za.exe a <zip> ./magisk/*` 等价：条目平铺在 zip 根目录
log "打包 $ZIP_NAME"
( cd magisk && zip -q -r -9 -X "$ZIP_PATH" . )
unzip -l "$ZIP_PATH" >&2

echo "$ZIP_PATH"
