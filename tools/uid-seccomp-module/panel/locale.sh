#!/system/bin/sh
# HMA_LANG is passed by the WebUI; installers use the device's primary language.
case "${HMA_LANG:-}" in
    zh|en) ;;
    *)
        hma_locale=$(getprop persist.sys.locale 2>/dev/null || true)
        [ -n "$hma_locale" ] || hma_locale=$(getprop persist.sys.language 2>/dev/null || true)
        [ -n "$hma_locale" ] || hma_locale=$(getprop ro.product.locale 2>/dev/null || true)
        case "$hma_locale" in zh|zh-*|zh_*) HMA_LANG=zh;; *) HMA_LANG=en;; esac
        ;;
esac
export HMA_LANG
hma_message() {
    if [ "$HMA_LANG" = zh ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi
}
