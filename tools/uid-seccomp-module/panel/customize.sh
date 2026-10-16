#!/system/bin/sh
. "$MODPATH/locale.sh" || abort 'Unable to load language resources'
[ "$ARCH" = arm64 ] || abort "$(hma_message '需要 arm64 设备' 'An arm64 device is required')"
[ "$API" -ge 33 ] || abort "$(hma_message '需要 Android 13 或以上版本' 'Android 13 or later is required')"
ui_print "$(hma_message '正在校验模块文件 SHA-256' 'Verifying module files with SHA-256')"
sh "$MODPATH/verify.sh" "$MODPATH" || abort "$(hma_message '文件完整性校验失败，已中止安装' 'File integrity check failed. Installation aborted')"
# Localize manager metadata only after verifying the original package bytes.
if [ "$HMA_LANG" = en ]; then
    while IFS= read -r line; do
        case "$line" in
            name=*) printf '%s\n' 'name=HMA++';;
            description=*) printf '%s\n' 'description=Avoid detection by filtering `getpriority(PRIO_USER)` calls in selected apps.';;
            *) printf '%s\n' "$line";;
        esac
    done < "$MODPATH/module.prop" > "$MODPATH/module.prop.localized"
    chmod 644 "$MODPATH/module.prop.localized"
    mv -f "$MODPATH/module.prop.localized" "$MODPATH/module.prop" || abort 'Failed to localize module metadata'
fi
sh "$MODPATH/control.sh" init || abort "$(hma_message '初始化配置失败' 'Failed to initialize configuration')"
ui_print "$(hma_message '已内置主 App 和应用列表 Demo 的包名' 'The main app and app visibility demo packages are included by default')"
ui_print "$(hma_message '可在模块 WebUI 中添加包名并启用过滤' 'Use the module WebUI to add package names and enable filtering')"
ui_print "$(hma_message '首次安装或更新原生组件后，请重启设备' 'Restart your device after installing or updating the native module')"
