#!/system/bin/sh
# Installation integrity check; user configuration can change after installation.
VERIFY_DIR=${1:-${0%/*}}
. "$VERIFY_DIR/locale.sh" || exit 1
[ -s "$VERIFY_DIR/SHA256SUMS" ] || { hma_message '缺少 SHA256SUMS 校验清单' 'The SHA256SUMS manifest is missing' >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { hma_message '安装环境缺少 sha256sum' 'sha256sum is unavailable in the installer environment' >&2; exit 1; }
(
    cd "$VERIFY_DIR" || exit 1
    sha256sum -c SHA256SUMS
) || { hma_message 'SHA-256 校验失败，请重新下载完整模块包' 'SHA-256 verification failed. Download the complete module package again' >&2; exit 1; }
