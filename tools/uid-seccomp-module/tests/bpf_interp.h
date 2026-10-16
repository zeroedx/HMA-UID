// Minimal cBPF interpreter over struct seccomp_data, plus synthetic
// AOSP-shaped platform policies. Used only by the host-side tests.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

// ---- cBPF interpreter ----
inline uint32_t run_filter(const std::vector<sock_filter>& code, const seccomp_data& d) {
    uint32_t A = 0, X = 0;
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(&d);
    size_t pc = 0;
    for (int guard = 0; guard < 100000; ++guard) {
        const sock_filter& op = code[pc];
        switch (BPF_CLASS(op.code)) {
            case BPF_LD:
                if (BPF_MODE(op.code) == BPF_ABS) std::memcpy(&A, mem + op.k, 4);
                else A = op.k;
                ++pc; break;
            case BPF_ALU: {
                const uint32_t src = (BPF_SRC(op.code) == BPF_X) ? X : op.k;
                if (BPF_OP(op.code) == BPF_AND) A &= src;
                else if (BPF_OP(op.code) == BPF_RSH) A >>= (src & 31);
                ++pc; break;
            }
            case BPF_MISC:
                X = A; ++pc; break;
            case BPF_JMP: {
                if (BPF_OP(op.code) == BPF_JA) { pc += 1 + op.k; break; }
                bool yes = false;
                const uint32_t rhs = (BPF_SRC(op.code) == BPF_X) ? X : op.k;
                switch (BPF_OP(op.code)) {
                    case BPF_JEQ: yes = A == rhs; break;
                    case BPF_JGE: yes = A >= rhs; break;
                    case BPF_JGT: yes = A >  rhs; break;
                    case BPF_JSET: yes = (A & rhs) != 0; break;
                    default: break;
                }
                pc += 1 + (yes ? op.jt : op.jf);
                break;
            }
            case BPF_RET:
                return op.k;
            default:
                return 0xdeadbeef;
        }
    }
    return 0xdeadbeef;
}

// Dual-arch AOSP-like program: arch dispatch, then independent forward-only
// syscall-number trees for aarch64 and arm. `allowed` lists syscall numbers
// permitted in both trees; everything else traps.
inline std::vector<sock_filter> platform_program(const std::vector<uint32_t>& allowed) {
    std::vector<sock_filter> f;
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, arch)));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_AARCH64, 2, 0));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_ARM, 0, 0));
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
    auto tree = [&]() {
        f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)));
        const size_t n = allowed.size();
        for (size_t i = 0; i < n; ++i)
            f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, allowed[i],
                                 (uint8_t)(n - i), 0));
        f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
        f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW));
    };
    tree();
    const size_t arm_start = f.size();
    tree();
    f[2].jt = (uint8_t)(arm_start - 3);
    return f;
}

// Single-arch platform: no ARM dispatch branch. merge_with_budget must reject
// this shape rather than grow the policy.
inline std::vector<sock_filter> single_arch_program(const std::vector<uint32_t>& allowed) {
    std::vector<sock_filter> f;
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, arch)));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_AARCH64, 1, 0));
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(seccomp_data, nr)));
    const size_t n = allowed.size();
    for (size_t i = 0; i < n; ++i)
        f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, allowed[i], (uint8_t)(n - i), 0));
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW));
    return f;
}
