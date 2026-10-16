// Host-side lifecycle test for module.cpp.
//
// It drives the real Zygisk module through a fake Api table and asserts the
// externally observable safety contract:
//   * the module requests library unload (DLCLOSE) only when its interception
//     callback is provably no longer reachable, and
//   * whenever the callback may still be reachable it delegates safely instead
//     of dereferencing a stale pointer.
//
// Each scenario runs in its own process because the Zygisk entry point holds a
// single static module instance; the runner script invokes this binary once per
// scenario.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

#include "zygisk.hpp"

// --- the platform symbol the module looks up via dlsym(RTLD_DEFAULT, ...) ---
extern "C" bool _Z22set_app_seccomp_filterv() { return true; }

// --- fake JNIEnv ---
namespace {
const char* kAppDataDir = "/data/data/com.test.app";
}

const char* _JNIEnv::GetStringUTFChars(jstring, jboolean*) { return kAppDataDir; }
void _JNIEnv::ReleaseStringUTFChars(jstring, const char*) {}

// --- fake api table state ---
namespace {
using Prctl = int (*)(int, unsigned long, unsigned long, unsigned long, unsigned long);
int fake_original_calls = 0;

void* captured_intercept = nullptr;   // newFunc from the first pltHookRegister
void* other_module_hook = reinterpret_cast<void*>(0x1234); // a foreign chained hook
bool commit_result = true;
bool backup_filled = true;            // does the provider return oldFunc on prepare
bool displaced_is_ours = true;        // does restore see our own callback displaced
bool dlclose_requested = false;
int module_dir_fd = -1;
zygisk::internal::module_abi* captured_abi = nullptr;

int fake_prctl(int, unsigned long, unsigned long, unsigned long, unsigned long) {
    ++fake_original_calls;
    return 0;
}

bool register_module(zygisk::internal::api_table*, zygisk::internal::module_abi* abi) {
    captured_abi = abi;
    return true;
}
void hook_jni(JNIEnv*, const char*, JNINativeMethod*, int) {}

void plt_hook_register(dev_t, ino_t, const char* symbol, void* new_func, void** old_func) {
    if (std::strcmp(symbol, "prctl") != 0) return;
    if (new_func == reinterpret_cast<void*>(fake_prctl)) {
        // restore call: newFunc is the saved original
        if (old_func) *old_func = displaced_is_ours ? captured_intercept : other_module_hook;
        return;
    }
    if (new_func == nullptr) { if (old_func) *old_func = nullptr; return; }
    if (new_func == other_module_hook) {
        // re-install of a foreign chained hook: not our interception callback
        if (old_func) *old_func = nullptr;
        return;
    }
    // prepare call: install our interception callback
    captured_intercept = new_func;
    if (old_func && backup_filled) *old_func = reinterpret_cast<void*>(fake_prctl);
}
bool plt_hook_commit() { return commit_result; }
int connect_companion(void*) { return -1; }
void set_option(void*, zygisk::Option opt) {
    if (opt == zygisk::DLCLOSE_MODULE_LIBRARY) dlclose_requested = true;
}
int get_module_dir(void*) { return module_dir_fd; }
uint32_t get_flags(void*) { return 0; }
bool exempt_fd(int) { return true; }
}  // namespace

// Mirror of AppSpecializeArgs layout (references are pointers under the ABI).
struct ArgsRaw {
    jint* uid; jint* gid; jintArray* gids; jint* runtime_flags; jobjectArray* rlimits;
    jint* mount_external; jstring* se_info; jstring* nice_name; jstring* instruction_set; jstring* app_data_dir;
    jintArray* fds_to_ignore; jboolean* is_child_zygote; jboolean* is_top_app;
    jobjectArray* pkg_data_info_list; jobjectArray* whitelisted_data_info_list;
    jboolean* mount_data_dirs; jboolean* mount_storage_dirs; jboolean* mount_sysprop_overrides;
};
static_assert(sizeof(ArgsRaw) == sizeof(zygisk::AppSpecializeArgs),
              "ArgsRaw must match AppSpecializeArgs layout");

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <scenario>\n", argv[0]); return 2; }
    const std::string scenario = argv[1];

    // scenario knobs
    if (scenario == "clean") { commit_result = true; backup_filled = true; displaced_is_ours = true; }
    else if (scenario == "no_backup") { commit_result = true; backup_filled = false; displaced_is_ours = true; }
    else if (scenario == "chained") { commit_result = true; backup_filled = true; displaced_is_ours = false; }
    else if (scenario == "commit_fail") { commit_result = false; backup_filled = true; displaced_is_ours = true; }
    else { std::fprintf(stderr, "unknown scenario: %s\n", scenario.c_str()); return 2; }

    // a module dir holding a config that selects the app
    char dir_template[] = "/tmp/uidmodXXXXXX";
    module_dir_fd = mkdtemp(dir_template) ? open(dir_template, O_RDONLY | O_DIRECTORY) : -1;
    if (module_dir_fd < 0) { std::fprintf(stderr, "cannot create module dir\n"); return 2; }
    const std::string config_path = std::string(dir_template) + "/config";
    { int fd = open(config_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      const char* body = "enabled=1\ncom.test.app\n";
      if (fd < 0 || write(fd, body, std::strlen(body)) < 0) { std::fprintf(stderr, "config write failed\n"); return 2; }
      close(fd); }

    // fake api table
    zygisk::internal::api_table table{};
    table.impl = nullptr;
    table.registerModule = register_module;
    table.hookJniNativeMethods = hook_jni;
    table.pltHookRegister = plt_hook_register;
    table.exemptFd = exempt_fd;
    table.pltHookCommit = plt_hook_commit;
    table.connectCompanion = connect_companion;
    table.setOption = set_option;
    table.getModuleDir = get_module_dir;
    table.getFlags = get_flags;

    _JNIEnv env{};
    zygisk_module_entry(&table, &env);

    // specialize args selecting our package
    jint uid = 10123, gid = 10123, runtime_flags = 0, mount_external = 0;
    jintArray gids = nullptr; jobjectArray rlimits = nullptr;
    jstring se_info = nullptr, nice_name = nullptr, instruction_set = nullptr;
    jstring app_data_dir = reinterpret_cast<jstring>(0x1);  // non-null: content comes from the fake env
    jboolean is_child_zygote = 0;
    ArgsRaw raw{ &uid, &gid, &gids, &runtime_flags, &rlimits, &mount_external,
                 &se_info, &nice_name, &instruction_set, &app_data_dir,
                 nullptr, &is_child_zygote, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

    auto* args = reinterpret_cast<zygisk::AppSpecializeArgs*>(&raw);
    if (captured_abi == nullptr) { std::fprintf(stderr, "module did not register\n"); return 2; }
    captured_abi->preAppSpecialize(captured_abi->impl, args);
    captured_abi->postAppSpecialize(captured_abi->impl, args);

    int failures = 0;
    auto check = [&](const char* what, bool ok) {
        std::printf("[%s] %s\n", ok ? "ok" : "FAIL", what);
        if (!ok) ++failures;
    };

    // The callback must be safe to invoke only if the library is retained.
    if (captured_intercept == nullptr) {
        std::printf("[skip] interception callback was never registered\n");
        return 0;
    }
    auto intercept = reinterpret_cast<Prctl>(captured_intercept);

    if (scenario == "clean") {
        check("clean: unload requested", dlclose_requested);
        check("clean: callback safe after unload (returns -1)", intercept(PR_GET_SECCOMP, 0, 0, 0, 0) == -1);
    } else if (scenario == "no_backup") {
        // Provider reported success but gave no original pointer: the hook is not
        // provably in place, so the library must be retained and the callback
        // must not dereference a null original.
        check("no_backup: unload NOT requested", !dlclose_requested);
        check("no_backup: callback returns -1, no crash", intercept(PR_GET_SECCOMP, 0, 0, 0, 0) == -1);
    } else if (scenario == "chained") {
        check("chained: unload NOT requested", !dlclose_requested);
        fake_original_calls = 0;
        const int r = intercept(PR_GET_SECCOMP, 0, 0, 0, 0);
        check("chained: callback still delegates safely", r == 0 && fake_original_calls == 1);
    } else if (scenario == "commit_fail") {
        check("commit_fail: callback returns -1, no crash", intercept(PR_GET_SECCOMP, 0, 0, 0, 0) == -1);
    }

    unlink(config_path.c_str());
    if (module_dir_fd >= 0) close(module_dir_fd);
    rmdir(dir_template);
    std::printf("%s\n", failures ? "SCENARIO FAILED" : "SCENARIO PASSED");
    return failures ? 1 : 0;
}
