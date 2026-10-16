/*
 * Copyright (C) 2020 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// Adapted for HMA++ by zeroedx, 2026-10-10, from 5ec1cff's
// local_cxa_atexit_finalize_impl, commit b269136606d6f230089fbf47a0b219f7f2ccef3c.
// Changes: handle allocation failure, retain DSO identity, remove each entry
// before invoking it, and support repeated/reentrant finalization safely.
#include <cstdlib>
#include <pthread.h>

namespace {
struct Entry {
    void (*function)(void*);
    void* argument;
    void* dso;
    Entry* next;
};

// Constant initialization: registrations may precede C++ global constructors.
Entry* entries = nullptr;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
}

extern "C" __attribute__((visibility("hidden")))
int __cxa_atexit(void (*function)(void*), void* argument, void* dso) {
    if (!function) return -1;
    auto* entry = static_cast<Entry*>(std::malloc(sizeof(Entry)));
    if (!entry) return -1;
    entry->function = function;
    entry->argument = argument;
    entry->dso = dso;
    pthread_mutex_lock(&mutex);
    entry->next = entries;
    entries = entry;
    pthread_mutex_unlock(&mutex);
    return 0;
}

extern "C" __attribute__((visibility("hidden")))
void __cxa_finalize(void* dso) {
    for (;;) {
        pthread_mutex_lock(&mutex);
        Entry** slot = &entries;
        while (*slot && dso && (*slot)->dso != dso) slot = &(*slot)->next;
        Entry* entry = *slot;
        if (!entry) {
            pthread_mutex_unlock(&mutex);
            return;
        }
        *slot = entry->next;
        pthread_mutex_unlock(&mutex);

        const auto function = entry->function;
        void* const argument = entry->argument;
        std::free(entry);
        // User callbacks may register more callbacks or finalize recursively.
        // No stale list pointer or registry lock survives across the call.
        function(argument);
    }
}
