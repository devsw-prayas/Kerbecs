# Kerbecs

**Kerbecs** is a region level address sanitizer for C++. It detects use-after-free, double-free, buffer overflows, use-before-init, thread-ownership violations, and more, without compiler instrumentation — you opt in explicitly by routing allocations through it.

> **Kerbecs is a DLL-only build.** It must be compiled as a shared library and linked dynamically by consumers.



## Features

- **`Region`** — a wrapper around any allocator you supply; the only type callers reason about
- **`ShadowedMemory<T>`** — a resolved-once handle with raw-pointer parity (deref, `->`, implicit `T*`, comparison, bounds-checked arithmetic)
- **Shadow bitmap** — 1 bit per user byte tracks poisoned/unpoisoned/tombstoned state at byte granularity
- **Quarantine with automatic draining** — freed blocks sit in a ring buffer for a real use-after-free detection window; an internal background thread advances the epoch and drains it, no consumer-managed thread required
- **Thread-ownership enforcement** — `Flexible` (default, cross-thread destroy allowed) or `Strict` (same-thread-only) per `Region`
- **Three block layouts** — `NormalLayout`, `EnhancedLayout` (checksummed metadata + canaries), `StaticLayout` (for static/global objects)
- **Violation stack** — every detection site pushes a `Violation` onto a thread-local stack you can drain, instead of routing through a callback
- **Lazy page commit** — a large VA range is reserved upfront; physical pages commit only on first touch



## Requirements

- C++20 or later
- MSVC, Clang, or GCC
- CMake 3.20+
- Windows or Linux (x86-64)



## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

Consuming via `add_subdirectory`:

```cmake
add_subdirectory(Kerbecs)
target_link_libraries(MyApp PRIVATE Kerbecs)
```

Zone sizes and capacities are compile-time constants set in `CMakeLists.txt`; two of them are exposed as CMake cache variables you can override without editing the file:

| Cache variable | Default | Description |
|---|---|---|
| `KERBECS_QUARANTINE_CAPACITY` | `4096` | Quarantine ring buffer slot count (must be a power of two) |
| `KERBECS_REGION_TABLE_CAPACITY` | `1024` | Region-lookup table slot count for wild-pointer resolution |

All VA reservations are virtual only — no physical memory is committed upfront; the real RAM cost is only what your allocations touch.



## Usage

### Creating a Region

`Region` is the type every caller interacts with. It wraps an allocator you provide, and vends `ShadowedMemory<T>` handles for anything allocated through it.

```cpp
#include "Region.h"
#include "KerbecsAllocators.h"

// Your own allocator - can be malloc, a pool, an arena, anything satisfying AllocatorConcept.
struct MyAllocator {
    void* allocate(size_t bytes, size_t align) noexcept;
    void  deallocate(void* p, size_t bytes) noexcept;
};

MyAllocator alloc;
Kerbecs::NormalRegion<MyAllocator> region(alloc, /*size*/ 64ULL * 1024 * 1024, /*registryCapacity*/ 4096);

if (!region.initialized()) {
    // Zone reservation or registration failed - check Kerbecs::popViolation()
}
```

`NormalRegion<A>` is a convenience alias for `Region<Layout::NormalLayout, ThreadPolicy::Flexible, A>` — fixing the layout and thread policy, leaving only the allocator to name. `EnhancedRegion<A>` and `StaticRegion<A>` are the same idea for the other two layouts; append `Strict` to any of them for same-thread-only destroy enforcement (`NormalRegionStrict<A>`, etc.).

### Startup and shutdown

Call `Kerbecs::Runtime::initShadowzone()` once, before constructing any `Region`, and `Kerbecs::Runtime::teardownShadowzone()` once, after every `Region` has been destroyed:

```cpp
#include "KerbecsRuntime.h"

Kerbecs::Runtime::initShadowzone();
// ... create Regions, allocate, run your program ...
Kerbecs::Runtime::teardownShadowzone();
```

`initShadowzone()` reserves the VA range and starts the internal drain thread that advances the epoch and drains the quarantine automatically — no consumer-managed thread required. `teardownShadowzone()` stops and joins that thread, force-flushes the quarantine, and releases the VA reservation. Skipping it leaves the drain thread still running (and still joinable) when the process exits — the `std::thread` destructor calls `std::terminate()` on a joinable thread, so an untorn-down process will abort on exit instead of shutting down cleanly.

### Allocating, constructing, destroying

```cpp
auto handle = region.allocate<MyType>();        // reserves + poisons the block
region.construct(handle, /* ctor args */ 42);   // unpoisons, placement-news

*handle;                                        // ordinary pointer semantics
handle->doSomething();
MyType* raw = handle;                           // implicit decay, like a raw T*

region.destroy(handle);                         // dtor + tombstone + enters quarantine
```

For arrays, pass a count to `allocate`:

```cpp
auto arr = region.allocate<float>(128);
region.construct(arr, 1.0f);       // constructs element 0
region.construct(arr + 1, 2.0f);   // constructs element 1 (bounds-checked)
```

A destroyed block is not immediately freed — it sits in the shared quarantine queue for at least two epochs before its memory is physically released. Epoch advancement and quarantine draining are handled entirely by an internal background thread; there is no consumer-managed epoch thread to write.

### Static and global objects

For process- or module-lifetime objects, use the `KERBECS_PERSISTENT` and `KERBECS_GLOBAL` macros:

```cpp
#include "KerbecsStatic.h"

// Process-lifetime object, backed by StaticRegion<StaticAllocator>:
KERBECS_PERSISTENT(MyConfig, g_Config, "global_config", /* ctor args */);

// Module-lifetime singleton, backed by StaticRegion<GlobalAllocator>:
KERBECS_GLOBAL(MySystem, g_RenderSystem, "render_system");
```

Both macros construct their object through a shared, process-wide `Region` (one per macro kind) and tear it down automatically at static-deinit time via RAII.

### Querying violations

Every detection site — allocation failures, alignment/overflow checks, use-after-free traps — pushes a `Violation` onto a thread-local stack. Drain it after any call that returns `false` or an empty handle:

```cpp
Kerbecs::Violation v{};
while (Kerbecs::popViolation(v)) {
    // v.m_Kind, v.m_Address, v.m_BlockBase, v.m_BlockSize, v.m_ThreadID, v.m_Timestamp
}
```

`popViolation` is LIFO and fixed-capacity (32 entries per thread) — a burst of violations past that evicts the oldest still-unpopped entry rather than growing or blocking.



## Violation types

| Violation | Trigger |
|---|---|
| `DoubleFree` | `destroy()` called on an already-destroyed block |
| `UseAfterFree` | Access to a block whose generation no longer matches |
| `UseBeforeInit` | Access to a fully poisoned (never constructed) region |
| `BufferOverflow` | Handle arithmetic (`operator+`) moved outside the block's bounds |
| `OverlapDetected` | Two tracked allocations share the same block base |
| `LeakDetected` | Live allocation still outstanding when a `Region` is destroyed |
| `MetadataCorruption` | Checksum or mirror mismatch in `EnhancedMetaData` |
| `AlignmentViolation` | `construct<T>()` pointer is not aligned to `alignof(T)` |
| `SizeOverflow` | A block-size computation overflowed |
| `WildPointer` | Address not found in the `Region`'s `AllocationRegistry` |
| `ThreadOwnership` | `destroy()` called from a different thread under a `Strict` `Region` |
| `QuarantineSaturation` | Quarantine ring buffer full — fail fast |
| `RetiredBoundaryViolation` | Non-owner thread accessed a block currently retiring |



## License

MIT License. Copyright (c) 2025 StormWeaver.
