// Host-side protocol test for the companion notification path ported in 0.2.8.
//
// It exercises the two mechanisms the fix depends on, without installing any
// real seccomp filter:
//   * the arming handshake (Hello + ready byte) the companion performs before
//     the filter is installed, and
//   * the SCM_RIGHTS delivery of the listener handle across the socketpair.
#include <cstdio>
#include <cstring>
#include <thread>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "notification.h"

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    // ---- 1. arming handshake: module side sends Hello, companion replies 'R' ----
    {
        int pair[2];
        check("socketpair created", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        const uint32_t uid = 10123;
        bool companion_ok = false;
        std::thread companion([&] {
            uid_filter::notification::Hello hello{};
            if (!uid_filter::notification::transfer(pair[1], &hello, sizeof(hello), false)) return;
            char ready = 'R';
            if (!uid_filter::notification::transfer(pair[1], &ready, 1, true)) return;
            companion_ok = hello.version == 1 && hello.uid == uid
                && hello.pid == uint32_t(getpid());
        });
        const bool armed = uid_filter::notification::prepare(pair[0], uid);
        companion.join();
        check("prepare() completed the arming handshake", armed);
        check("companion received the correct Hello", companion_ok);
        close(pair[0]); close(pair[1]);
    }

    // ---- 2. handle delivery: listener fd crosses the socketpair via SCM_RIGHTS ----
    {
        int pair[2];
        check("socketpair created (fd delivery)", socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        const int listener = open("/dev/null", O_RDONLY | O_CLOEXEC);
        check("listener source fd opened", listener >= 0);
        check("send_listener() reports success",
              uid_filter::notification::send_listener(pair[0], listener));
        // Companion side: receive the byte plus the SCM_RIGHTS handle.
        char byte = 0;
        alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
        iovec payload{&byte, 1};
        msghdr message{};
        message.msg_iov = &payload; message.msg_iovlen = 1;
        message.msg_control = control; message.msg_controllen = sizeof(control);
        const ssize_t n = recvmsg(pair[1], &message, MSG_CMSG_CLOEXEC);
        auto* header = CMSG_FIRSTHDR(&message);
        check("listener byte delivered", n == 1 && byte == 'F');
        check("SCM_RIGHTS header present",
              header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
              && header->cmsg_len == CMSG_LEN(sizeof(int)));
        int received = -1;
        if (header) std::memcpy(&received, CMSG_DATA(header), sizeof(received));
        struct stat info{};
        check("delivered fd is a valid open descriptor",
              received >= 0 && fstat(received, &info) == 0);
        if (listener >= 0) close(listener);
        if (received >= 0) close(received);
        close(pair[0]); close(pair[1]);
    }

    std::printf("\n%s (%d failures)\n",
                failures ? "NOTIFICATION TESTS FAILED" : "ALL NOTIFICATION TESTS PASSED",
                failures);
    return failures ? 1 : 0;
}
