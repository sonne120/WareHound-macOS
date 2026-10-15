#pragma once

#include <cstdint>
#include <thread>
#include <string>

#if defined(_WIN32)
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
#else
  #include <pthread.h>
  #include <unistd.h>
  #if defined(__APPLE__)
    #include <mach/mach.h>
    #include <mach/thread_policy.h>
  #else
    #include <sched.h>
  #endif
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #include <immintrin.h>
  #define SNIFF_CPU_PAUSE() _mm_pause()
#elif defined(__aarch64__) || defined(_M_ARM64)
  #define SNIFF_CPU_PAUSE() asm volatile("yield" ::: "memory")
#else
  #define SNIFF_CPU_PAUSE() std::this_thread::yield()
#endif

namespace sniff::platform {
inline bool pin_current_thread_to_core(int core_id) noexcept {
    if (core_id < 0) return false;
#if defined(_WIN32)
    DWORD_PTR mask = static_cast<DWORD_PTR>(1ull) << core_id;
    DWORD_PTR prev = SetThreadAffinityMask(GetCurrentThread(), mask);
    if (prev == 0) return false;
    SetThreadIdealProcessor(GetCurrentThread(), static_cast<DWORD>(core_id));
    return true;
#elif defined(__APPLE__)
    thread_affinity_policy_data_t policy = { static_cast<integer_t>(core_id) };
    thread_port_t mach_thread = pthread_mach_thread_np(pthread_self());
    return thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
                             (thread_policy_t)&policy, 1) == KERN_SUCCESS;
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    return pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) == 0;
#endif
}

inline void set_current_thread_name(const std::string& name) noexcept {
#if defined(_WIN32)
    // SetThreadDescription requires Windows 10 1607+.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return;
    std::wstring wname(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, wname.data(), wlen);
    SetThreadDescription(GetCurrentThread(), wname.c_str());
#elif defined(__APPLE__)
    pthread_setname_np(name.c_str());
#else
    // Linux thread names are limited to 16 bytes incl. NUL.
    std::string trimmed = name.substr(0, 15);
    pthread_setname_np(pthread_self(), trimmed.c_str());
#endif
}

inline unsigned hardware_concurrency_logical() noexcept {
    unsigned n = std::thread::hardware_concurrency();
    return n == 0 ? 1u : n;
}

inline void cpu_pause() noexcept {
    SNIFF_CPU_PAUSE();
}
}
