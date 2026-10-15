// TODO: real huge pages (MAP_HUGETLB / MEM_LARGE_PAGES); currently aligned new[].
#pragma once

#include <cstddef>
#include <cstdlib>
#include <new>

namespace sniff::platform {
inline void* aligned_alloc_bytes(std::size_t bytes, std::size_t alignment = 64) {
#if defined(_WIN32)
    void* p = _aligned_malloc(bytes, alignment);
    if (!p) throw std::bad_alloc{};
    return p;
#else
    // posix_memalign requires alignment to be a multiple of sizeof(void*).
    void* p = nullptr;
    if (posix_memalign(&p, alignment, bytes) != 0 || !p) throw std::bad_alloc{};
    return p;
#endif
}

inline void aligned_free_bytes(void* p) noexcept {
#if defined(_WIN32)
    _aligned_free(p);
#else
    std::free(p);
#endif
}
}
