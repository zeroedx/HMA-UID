// Host-side tests for filter.h / policy.h.
//
// Covers the audit findings:
//   * a merge that cannot preserve the platform instruction budget must FAIL
//     (return false, leave output untouched) instead of growing the policy;
//   * the merge path never installs a filter and never touches NoNewPrivs;
//   * on an AOSP-shaped policy the merged program keeps the exact decisions.
#include <cstdio>
#include <vector>
#include <sys/resource.h>
#include <unistd.h>

#include "filter.h"
#include "bpf_interp.h"
#include "fixture_policy.h"

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++failures;
}
static const char* action(uint32_t r) {
    if (r == SECCOMP_RET_ALLOW) return "ALLOW";
    if ((r & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_TRAP) return "TRAP";
    if ((r & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO) return "ERRNO";
    return "OTHER";
}
static bool same(uint32_t got, uint32_t want, const char* label) {
    if (got == want) return true;
    std::printf("     %s: got %s want %s\n", label, action(got), action(want));
    return false;
}

int main() {
    const uint32_t self = 10123;
    const uint32_t peer = 10456;

    // ---- 1. AOSP-shaped policy: merge preserves every decision ----
    {
        auto plat = fixture::aosp_app_policy();
        sock_fprog prog{(unsigned short)plat.size(), plat.data()};
        std::vector<sock_filter> merged;
        const bool ok = uid_filter::merge(prog, self, merged);
        check("merge succeeds on AOSP-shaped policy", ok);
        if (ok) {
            check("merge does not grow the policy", merged.size() <= plat.size());
            seccomp_data d{};
            d.arch = AUDIT_ARCH_AARCH64;
            d.nr = 63;  check("merged: read allowed", same(run_filter(merged, d), SECCOMP_RET_ALLOW, "read"));
            d.nr = 999; check("merged: unknown nr trapped", same(run_filter(merged, d), SECCOMP_RET_TRAP, "nr999"));
            d = {}; d.arch = AUDIT_ARCH_AARCH64; d.nr = __NR_getpriority;
            d.args[0] = PRIO_USER; d.args[1] = self;
            check("merged: PRIO_USER self allowed", same(run_filter(merged, d), SECCOMP_RET_ALLOW, "self"));
            d.args[1] = peer;
            check("merged: PRIO_USER peer -> ESRCH",
                  same(run_filter(merged, d), SECCOMP_RET_ERRNO | ESRCH, "peer"));
            d.args[1] = 97;
            check("merged: PRIO_USER system allowed", same(run_filter(merged, d), SECCOMP_RET_ALLOW, "sys"));
            d.args[0] = PRIO_PROCESS; d.args[1] = peer;
            check("merged: PRIO_PROCESS allowed", same(run_filter(merged, d), SECCOMP_RET_ALLOW, "prio_proc"));
            // 32-bit arch: the platform traps a syscall it does not model, and the
            // rule (aarch64-only) must not interfere with that decision.
            d = {}; d.arch = AUDIT_ARCH_ARM; d.nr = 999;
            check("merged: 32-bit unknown nr trapped", same(run_filter(merged, d), SECCOMP_RET_TRAP, "arm999"));
        }
    }

    // ---- 2a. non-standard shape (no ARM branch): merge must FAIL, not grow ----
    {
        auto plat = single_arch_program({63, 141});
        sock_fprog prog{(unsigned short)plat.size(), plat.data()};
        std::vector<sock_filter> merged{BPF_STMT(BPF_RET | BPF_K, 0xCAFEBABE)}; // sentinel
        const bool ok = uid_filter::merge(prog, self, merged);
        check("merge rejects non-standard policy shape", !ok);
        check("merge leaves output untouched on failure",
              merged.size() == 1 && merged[0].k == 0xCAFEBABE);
    }

    // ---- 2b. familiar shape but the merge cannot fit the budget ----
    // A dual-arch policy whose compatibility tree allows a single syscall is far
    // too small to host the bitmap compaction plus the rule without growing the
    // policy; the merge must fail rather than install a larger filter.
    {
        auto plat = platform_program({500});
        sock_fprog prog{(unsigned short)plat.size(), plat.data()};
        std::vector<sock_filter> merged{BPF_STMT(BPF_RET | BPF_K, 0xCAFEBABE)}; // sentinel
        const bool ok = uid_filter::merge(prog, self, merged);
        check("merge fails when the budget cannot fit", !ok);
        check("budget failure leaves output untouched",
              merged.size() == 1 && merged[0].k == 0xCAFEBABE);
    }

    // ---- 3. merge path never mutates NoNewPrivs ----
    {
        const int before = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        auto plat = fixture::aosp_app_policy();
        sock_fprog prog{(unsigned short)plat.size(), plat.data()};
        std::vector<sock_filter> merged;
        uid_filter::merge(prog, self, merged);
        const int after = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        check("merge leaves NoNewPrivs unchanged", before == after);
    }

    // ---- 4. invalid self uid is rejected ----
    {
        auto plat = fixture::aosp_app_policy();
        sock_fprog prog{(unsigned short)plat.size(), plat.data()};
        std::vector<sock_filter> merged;
        check("merge rejects non-app uid", !uid_filter::merge(prog, 1000, merged));
        check("merge rejects null filter", !uid_filter::merge(sock_fprog{0, nullptr}, self, merged));
    }

    std::printf("\n%s (%d failures)\n", failures ? "FILTER TESTS FAILED" : "ALL FILTER TESTS PASSED", failures);
    return failures ? 1 : 0;
}
