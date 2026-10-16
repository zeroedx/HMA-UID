#include <sys/types.h>
#include "zygisk.hpp"
#include "filter.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sstream>
#include <string>

class UidSeccomp final : public zygisk::ModuleBase {
    using Prctl = int (*)(int, unsigned long, unsigned long, unsigned long, unsigned long);
    inline static UidSeccomp* current_ = nullptr;
    zygisk::Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    std::string package_;
    bool active_ = false;
    int expected_uid_ = -1;
    Prctl original_prctl_ = nullptr;
    struct stat runtime_{};
    bool registered_ = false;
    bool hook_active_ = false;
    bool merged_ = false;

    static int intercept_prctl(int option, unsigned long second, unsigned long third,
                               unsigned long fourth, unsigned long fifth) {
        UidSeccomp* self = current_;
        if (!self || !self->original_prctl_) return -1;
        if (option == PR_SET_SECCOMP && second == SECCOMP_MODE_FILTER && third && !self->merged_) {
            const int saved_errno = errno;
            try {
                std::vector<sock_filter> code;
                if (uid_filter::merge(*reinterpret_cast<const sock_fprog*>(third), uint32_t(self->expected_uid_), code)) {
                    sock_fprog program{static_cast<unsigned short>(code.size()), code.data()};
                    const int result = self->original_prctl_(option, second,
                        reinterpret_cast<unsigned long>(&program), fourth, fifth);
                    if (result == 0) { self->merged_ = true; return result; }
                }
            } catch (...) {
                // Never prevent Android from installing its own sandbox policy.
            }
            errno = saved_errno;
        }
        return self->original_prctl_(option, second, third, fourth, fifth);
    }

    void prepare_platform_filter() {
        // This hook exists only between the two specialization callbacks in
        // the selected child. The framework applies its policy before setuid.
        Dl_info info{};
        void* symbol = dlsym(RTLD_DEFAULT, "_Z22set_app_seccomp_filterv");
        if (!symbol || !dladdr(symbol, &info) || !info.dli_fname || stat(info.dli_fname, &runtime_) != 0) return;
        current_ = this;
        api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl",
            reinterpret_cast<void*>(intercept_prctl), reinterpret_cast<void**>(&original_prctl_));
        registered_ = true;
        const bool committed = api_->pltHookCommit();
        // The provider may apply some entries even when commit reports failure,
        // so retention follows the resolved original pointer, not the result.
        hook_active_ = original_prctl_ != nullptr;
        // Drop the interception callback whenever it is not provably in place:
        // either the commit failed, or no original pointer was resolved. Leaving
        // current_ set would expose a dangling pointer after this library
        // unloads, and the callback would run with no original to fall back to.
        if (!committed || !hook_active_) current_ = nullptr;
    }

    bool restore_platform_filter() {
        if (!registered_) return !hook_active_;
        void* displaced = nullptr;
        api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl",
            reinterpret_cast<void*>(original_prctl_), &displaced);
        const bool committed = api_->pltHookCommit();
        if (displaced != reinterpret_cast<void*>(intercept_prctl)) {
            // Another module may have chained our callback. Preserve its hook and
            // keep this library mapped so its saved pointer stays valid. Never
            // drop current_ here: our callback remains reachable on that chain.
            if (displaced) {
                api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl", displaced, nullptr);
                api_->pltHookCommit();
            }
            return false;
        }
        if (!committed) return false;
        hook_active_ = false;
        current_ = nullptr;
        return true;
    }
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override { api_ = api; env_ = env; }
    void preServerSpecialize(zygisk::ServerSpecializeArgs*) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!args->app_data_dir || args->uid < 0 || args->uid % 100000 < 10000 || args->uid % 100000 > 19999) return;
        if (args->is_child_zygote && *args->is_child_zygote) return;
        const char* data = env_->GetStringUTFChars(args->app_data_dir, nullptr);
        if (!data) return;
        std::string path(data);
        env_->ReleaseStringUTFChars(args->app_data_dir, data);
        const auto slash = path.find_last_of('/');
        if (slash == std::string::npos || slash + 1 == path.size()) return;
        package_ = path.substr(slash + 1);
        if (package_.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") != std::string::npos) return;
        const int dir = api_->getModuleDir();
        if (dir < 0) return;
        if (faccessat(dir, "disable", F_OK, 0) == 0 || faccessat(dir, "remove", F_OK, 0) == 0) { close(dir); return; }
        const int fd = openat(dir, "config", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        close(dir);
        if (fd < 0) return;
        char buffer[32769];
        ssize_t used = 0;
        while (used < static_cast<ssize_t>(sizeof(buffer))) {
            const ssize_t count = read(fd, buffer + used, sizeof(buffer) - size_t(used));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) { used = -1; break; }
            if (count == 0) break;
            used += count;
        }
        close(fd);
        if (used <= 0 || used >= static_cast<ssize_t>(sizeof(buffer))) return;
        std::istringstream input(std::string(buffer, size_t(used)));
        std::string line;
        if (!std::getline(input, line) || line != "enabled=1") return;
        while (std::getline(input, line)) {
            if (line == package_) { active_ = true; expected_uid_ = args->uid; break; }
        }
        if (active_) prepare_platform_filter();
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        const bool restored = restore_platform_filter();
        // No callback may reference this library when Zygisk unloads it. If the
        // hook could not be cleanly removed (chained by another module), keep the
        // library mapped so our callback stays valid instead of dangling.
        if (restored) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
};
REGISTER_ZYGISK_MODULE(UidSeccomp)
