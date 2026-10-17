# HMA++

作者：zeroedx。当前版本：0.2.8。

HMA++ 是一个 Zygisk 模块，通过过滤指定应用进程的 `getpriority(PRIO_USER)` 调用，规避“内核已分配 UID 但查询结果不存在”这一检测点。

过滤仅作用于配置选中的普通应用进程，默认包名为 `com.chunqiunativecheck` 和 `com.chunqiu.appvisibilitydemo`。模块面向 arm64、Android 13+（API 33）、Zygisk API 5，内置中英文 WebUI。

## 功能

- 对选中的普通应用进程过滤 `getpriority(PRIO_USER)`，规避 UID 分配相关检测。
- 在支持的平台 seccomp 策略上保持原有指令预算进行合并；结构不匹配或无法保持预算时放弃合并，绝不放大或削弱系统策略。
- 中英文 WebUI：开关过滤、添加 / 移除生效包名、保存并应用配置。
- 保存并应用只停止配置发生变化的目标应用，重新打开后生效；不清除应用数据。
- 兼容 KernelSU 的 WebUI 打开方式（`me.weishu.kernelsu`）。

## 兼容性

- 架构：arm64（`arm64-v8a`），安装脚本会拒绝非 arm64 设备。
- 系统：Android 13 及以上（API 33+）。
- 提供程序：Zygisk API 5；配合 KernelSU、Magisk 等支持 Zygisk 的模块管理器使用。
- 升级方式：0.2.8 与 0.2.7 使用相同模块 ID（`hma_plus_plus`），可直接覆盖升级，无需卸载。仅当从旧版 HMA-UIDfake 0.2.6（模块 ID `cq_uid_seccomp`）升级时，才需要先在 Root 模块管理器中卸载旧版，不要同时保留新旧版本。

## 安装

1. 若安装的是旧版 HMA-UIDfake 0.2.6，**先在 Root 模块管理器中卸载它**，确认旧模块已从列表中移除；从 0.2.7 升级则跳过此步。
2. 下载 `hma-plus-plus-0.2.8.zip`（或对应版本）及其 `.zip.sha256` 校验文件。
3. 在支持 Zygisk 的模块管理器中安装该 ZIP。
4. 重启设备。
5. 打开模块 WebUI，启用过滤并添加需要生效的包名，保存并应用。

首次安装或更新原生组件后需要重启设备。升级时模块会在安装阶段校验包内文件的 SHA-256，校验失败会中止安装。

## 使用说明

- 在 WebUI 中打开过滤开关，或从列表中添加 / 移除包名；改动后点击“保存并应用”。
- “保存并应用”只会停止配置发生变化的目标应用，重新打开后生效。列表之外的应用不受影响。
- 配置首行为 `enabled=1` 或 `enabled=0`，随后每行一个完整包名，最多 128 项。
- 应用数据不会被清除；关闭过滤后，选中的应用即恢复原状。

## 构建

需要 Python 3.10+ 和 Android NDK `27.3.13750724`。默认从 `%LOCALAPPDATA%/Android/Sdk` 查找 SDK；可用 `ANDROID_SDK_ROOT` / `ANDROID_HOME` 指定 SDK，或用 `ANDROID_NDK_HOME` 直接指定 NDK 根目录。

```powershell
git clone https://github.com/zeroedx/HMA-UIDfake.git
Set-Location HMA-UIDfake
python tools/uid-seccomp-module/build.py --module-only
```

只构建模块，无需 Java、Gradle 或额外的 Python 包。Zygisk API 5 头文件已随源码提供，构建时会校验其固定 SHA-256。

输出文件：

- `build/0.2.8/hma-plus-plus-0.2.8.zip`
- `build/0.2.8/hma-plus-plus-0.2.8.zip.sha256`

可用 `--output <目录>` 指定输出目录，或用 `--config <文件>` 指定默认配置。省略 `--module-only` 同样只构建模块。

## 测试

主机侧测试只需要 C++17 编译器和 Python 3，不构建 Android 模块，也不需要 NDK：

```sh
sh tools/uid-seccomp-module/tests/run_tests.sh
```

覆盖版本单一来源、Release 标签校验、seccomp 合并的预算与结构处理、模块生命周期回调安全等。

## 版本记录

- 0.2.8：同步上游 UID 过滤 0.2.8 修复。新增伴随进程（companion）与 seccomp 用户态通知路径：过滤器安装阶段完成通知连接与句柄交付，修复应用初始化阶段通知连接提前关闭、子进程规则继承未生效的问题；保留 HMA++ 自身的严格合并（预算不符即放弃，绝不放大或削弱系统策略）与 Provider 回调指针生命周期加固。
- 0.2.7：模块更名为 HMA++，作者 zeroedx；模块 ID 更换为 `hma_plus_plus`（旧版为 `cq_uid_seccomp`），**从旧版 HMA-UIDfake 0.2.6 安装前需先卸载**；合并审计修复：seccomp 合并改为预算失败即放弃、Provider 回调指针生命周期加固、版本与 Release 标签来源统一。
- 0.2.6：析构回调改为模块内部登记和清理，避免在 libc 的退出回调表中留下登记痕迹；发布 SO 移除 `atexit` 符号字符串，仅导出 Zygisk 入口。
- 0.2.5：在支持的平台策略上，保持合并前的 seccomp 指令预算，修复应用可安装过滤规则的额度差异。
- 0.2.4：合并系统 seccomp 策略时保持原有的 `NoNewPrivs` 状态和过滤器数量，移除模块启动日志。

## 源码

- `tools/uid-seccomp-module/module.cpp`、`filter.h`、`policy.h`、`broker.cpp`、`notification.h`、`fork_events.h`：原生模块。
- `tools/uid-seccomp-module/panel/`：安装、配置脚本及 WebUI 资源。
- `tools/uid-seccomp-module/build.py`：编译与 ZIP 打包。
- `tools/uid-seccomp-module/tests/`：主机侧回归测试。
- `third_party/zygisk/`：原始头文件、许可声明和来源校验信息。
- `third_party/local_cxa/`：本地析构回调实现，改编自 [5ec1cff/local_cxa_atexit_finalize_impl](https://github.com/5ec1cff/local_cxa_atexit_finalize_impl)。

## 致谢

- `broker.cpp`、`notification.h`、`fork_events.h` 及 0.2.8 的伴随进程 / 用户态通知修复移植自 [longze777/UID-](https://github.com/longze777/UID-)（作者 longze777，Apache-2.0），已按 HMA++ 的模块 ID、品牌与安全约束适配。各文件顶部保留来源与作者声明。

项目沿用 [Apache-2.0 许可证](LICENSE)；第三方代码保留其原始许可声明，本地析构实现的许可和署名同时收录在安装包的 `legal/` 目录。
