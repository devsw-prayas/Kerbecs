# Kerbecs

**Kerbecs** is a HPC-grade concurrent AddressSanitizer for C++. It detects memory safety violations — use-after-free, double-free, buffer overflows, use-before-init, leaks, thread ownership violations, and more — through a policy-based shadow pointer system backed by a lazy-commit virtual memory zone.

Unlike compiler-instrumented sanitizers (ASan, Valgrind), Kerbecs is a pure library designed for high-throughput concurrent workloads. You wrap allocations explicitly using `ShadowPtr` and the provided macros, making it suitable for environments where compiler instrumentation isn't available or practical — HPC runtimes, game engines, custom allocators.

> **Kerbecs is a DLL-only build.** It must be compiled as a shared library and linked dynamically by consumers. Static linking is not supported.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Building](#building)
- [Integration](#integration)
  - [Zone initialization](#zone-initialization)
  - [Epoch thread (required)](#epoch-thread-required)
  - [Teardown](#teardown)
- [Usage](#usage)
  - [Initializing the zone](#initializing-the-zone)
  - [Allocating and constructing](#allocating-and-constructing)
  - [Destroying](#destroying)
  - [Static and global objects](#static-and-global-objects)
  - [Custom policies](#custom-policies)
- [Architecture](#architecture)
- [Violation types](#violation-types)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Shadow bitmap** — 1 bit per user byte tracks poisoned/unpoisoned/tombstoned state at byte granularity
- **Three block layouts** — `NormalLayout` (redzones + metadata), `EnhancedLayout` (redzones + canaries + checksummed metadata), `StaticLayout` (redzones + canaries, no in-block metadata)
- **Quarantine queue** — freed blocks are held in a deferred ring buffer before physical release, enabling use-after-free detection across a configurable window
- **Allocation registry** — lock-free hash map tracking every live block, with a full state machine: `Live → Retiring → Quarantine → Dead`
- **Thread ownership enforcement** — destroy must be called from the allocating thread
- **Leak detection** — scans the node pool at teardown and traps if any live allocations remain
- **Policy-based design** — layout, shadow map, logger, hash accumulator, and allocator are all injected via C++20 concepts; bring your own or use the provided defaults
- **Lazy page commit** — reserves a large VA range upfront; physical pages are committed only on first touch
- **Windows and Linux** — memory primitives use `VirtualAlloc`/`mmap` respectively

---

## Requirements

- C++20 or later
- MSVC, Clang, or GCC
- CMake 3.20+
- Windows 10+ or Linux (x86-64)

---

## Building

Kerbecs **must** be built as a shared library. The provided `CMakeLists.txt` at the repo root handles everything:

```cmake
cmake_minimum_required(VERSION 3.20)
project(Kerbecs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

file(GLOB_RECURSE KERBECS_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/Public/*.h")
file(GLOB_RECURSE KERBECS_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/Private/*.cpp")

add_library(Kerbecs SHARED ${KERBECS_HEADERS} ${KERBECS_SOURCES})

target_include_directories(Kerbecs PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public)

set_target_properties(Kerbecs PROPERTIES FOLDER "Base")

target_precompile_headers(Kerbecs PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Public/Kerbecs.h)

target_compile_definitions(Kerbecs PUBLIC
    SHADOWZONE_SIZE=1500
    GLOBALZONE_SIZE=500
    STATICZONE_SIZE=500
    REGISTRY_CAPACITY=128
    QUARANTINE_CAPACITY=256
    KERBECS_SHARED
    KERBECS_BUILDING_RUNTIME
)
```

To build from the command line:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

### Compile definitions

All zone sizes and capacities are set at compile time via the definitions above. You can override them by passing `-D` flags to CMake or by modifying the `CMakeLists.txt` directly before building:

| Definition | Default | Description |
|---|---|---|
| `SHADOWZONE_SIZE` | `1500` | Shadow bitmap zone size in GiB |
| `GLOBALZONE_SIZE` | `500` | Global allocator zone size in GiB |
| `STATICZONE_SIZE` | `500` | Static allocator zone size in GiB |
| `REGISTRY_CAPACITY` | `128` | Max tracked allocations in the registry node pool |
| `QUARANTINE_CAPACITY` | `256` | Quarantine ring buffer slot count |

> **Note:** All zone sizes are virtual address reservations — no physical memory is committed upfront. The actual RAM cost is only what your allocations touch.

### Consuming Kerbecs via `add_subdirectory`

If you embed Kerbecs as a subdirectory in your own CMake project, `KERBECS_SHARED` is already declared `PUBLIC` in the target, so consumers inherit the correct `__declspec(dllimport)` / visibility attributes automatically:

```cmake
add_subdirectory(Kerbecs)
target_link_libraries(MyApp PRIVATE Kerbecs)
```

---

## Integration

Link against the built DLL/SO and add `src/Public` to your include path.

### Zone initialization

Call `initShadowzone()` once before any `ShadowPtr` or macro APIs are used:

```cpp
#include "MemoryZone.h"

Kerbecs::MemoryZone::initShadowzone();
```

### Epoch thread (required)

The quarantine queue only releases blocks when their epoch is old enough — specifically when `slot.m_Epoch + 2 <= currentEpoch`. **Kerbecs never advances the epoch or flushes the quarantine itself.** You must launch a dedicated thread that does both at whatever cadence suits your application:

```cpp
#include "MemoryZone.h"

std::thread g_EpochThread([] {
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        auto& zone = Kerbecs::MemoryZone::instance();

        // Advance the epoch so queued blocks age out.
        zone.m_Epoch.fetch_add(1, std::memory_order_acq_rel);

        // Flush all quarantine entries eligible at the new epoch.
        const uint64_t epoch = zone.m_Epoch.load(std::memory_order_acquire);
        zone.m_Quarantine.flushEligible(
            zone.m_Registry.poolSegment(),
            epoch);
    }
});
```

A block destroyed at epoch N becomes eligible for physical release at epoch N+2. The flush interval controls how long the use-after-free detection window lasts — shorter intervals mean faster reclamation but a smaller safety window.

### Teardown

Stop your epoch thread first, then call `teardownShadowzone()`:

```cpp
running = false;
g_EpochThread.join();

Kerbecs::MemoryZone::teardownShadowzone();
```

`teardownShadowzone()` does a final unconditional drain of the quarantine (passing `SIZE_MAX` as the epoch, so all remaining entries are flushed regardless of age), then scans the registry node pool for any blocks still in `Live`, `Retiring`, or `Quarantine` state. Each one is counted as a leak violation. If any leaks are found it fires `KERBECS_TRAP()` before releasing the VA reservation.

---

## Usage

### Allocating and constructing

`ShadowPtr` is the core handle type. It is templated on five policy types:

```
ShadowPtr<LayoutPolicy, ShadowMap, Logger, HashAccumulator, Allocator>
```

**The allocator is not provided by Kerbecs.** You supply your own type that satisfies `AllocatorConcept` — it allocates the raw block that `ShadowPtr` will manage. Kerbecs wraps it in a `MemorySupport` helper and uses it to both allocate the block and to dealloc it later via a type-erased thunk stored in the quarantine queue.

```cpp
// Your own allocator - can be malloc, a pool, an arena, anything.
struct MyAllocator {
    void* allocate(size_t bytes, size_t align) noexcept {
        return ::operator new(bytes, std::align_val_t{align}, std::nothrow);
    }
    void deallocate(void* p, size_t /*bytes*/) noexcept {
        ::operator delete(p);
    }
};
static_assert(Kerbecs::Enforcement::AllocatorConcept<MyAllocator>);
```

Wire everything together and allocate:

```cpp
#include "ShadowPtr.h"
#include "ShadowMap.h"
#include "MemoryZone.h"
#include "MemorySupport.h"

using MyShadowPtr = Kerbecs::Shadow::ShadowPtr<
    Kerbecs::Layout::NormalLayout,
    Kerbecs::KerbecsShadowMap,
    MyLogger,
    Kerbecs::Checksums::XorHashAccumulator,
    MyAllocator
>;

MyAllocator myAlloc;
Kerbecs::Shadow::Internal::MemorySupport<MyAllocator> allocSupport{ &myAlloc };
MyLogger myLogger;

MyShadowPtr handle;
handle.m_Map           = &Kerbecs::MemoryZone::instance().m_Map;
handle.m_Logger        = &myLogger;
handle.m_UserAllocator = &allocSupport;
handle.m_Name          = "my_int";

Kerbecs::Shadow::shadowAllocate<int>(&handle);      // allocates block via MyAllocator, poisons payload
Kerbecs::Shadow::shadowConstruct<int>(&handle, 42); // unpoisons, placement-news
```

For arrays, pass a count:

```cpp
Kerbecs::Shadow::shadowAllocate<float>(&handle, 128);         // 128 floats
Kerbecs::Shadow::shadowConstructAt<float>(&handle, 0, 1.0f);  // construct element 0
Kerbecs::Shadow::shadowConstructAt<float>(&handle, 1, 2.0f);  // construct element 1
```

### Destroying

```cpp
Kerbecs::Shadow::shadowDestroy<int>(&handle);
// Runs the dtor, tombstones the shadow region, begins the quarantine cycle.
// The block is NOT immediately freed - it enters the quarantine queue.
```

Destroying from the wrong thread fires a `ThreadOwnership` violation. Destroying an already-destroyed object fires `DoubleFree`.

### Checking memory state

```cpp
auto state = Kerbecs::Shadow::shadowGetMemoryState<int>(&handle);

switch (state) {
    case Kerbecs::Shadow::Utils::MemoryState::CONSTRUCTED:   break; // safe to use
    case Kerbecs::Shadow::Utils::MemoryState::UNINITIALIZED: break; // never constructed
    case Kerbecs::Shadow::Utils::MemoryState::DESTROYED:     break; // use-after-free
    case Kerbecs::Shadow::Utils::MemoryState::CORRUPTED:     break; // overflow / wild pointer
}
```

### Static and global objects

For objects with static or module-level lifetime, use the `KERBECS_PERSISTENT` and `KERBECS_GLOBAL` macros. These require four type macros to be defined before including `KerbecsStatic.h`:

```cpp
#define KERBECS_SHADOW_MAP_TYPE  Kerbecs::KerbecsShadowMap
#define KERBECS_LOGGER_TYPE      MyViolationLogger
#define KERBECS_HASH_TYPE        Kerbecs::Checksums::XorHashAccumulator
#define KERBECS_ALLOCATOR_TYPE   Kerbecs::Allocators::StaticAllocator

#include "KerbecsStatic.h"

// Process-lifetime object allocated from the StaticZone:
KERBECS_PERSISTENT(MyConfig, g_Config, "global_config", /* ctor args */);

// Module-level singleton allocated from the GlobalZone:
KERBECS_GLOBAL(MySystem, g_RenderSystem, "render_system");
```

Both macros generate an RAII init struct that runs at static initialization time and a `KerbecsDestructor` that calls `shadowDestroy` at scope exit. The zone is auto-initialized on first use if `initShadowzone()` hasn't been called yet.

`KERBECS_PERSISTENT` — backed by `StaticAllocator` (StaticZone). For objects that must live for the entire process lifetime.

`KERBECS_GLOBAL` — backed by `GlobalAllocator` (GlobalZone). For module-level singletons with a controlled but finite lifetime.

### Custom policies

All five policy slots on `ShadowPtr` are enforced via C++20 concepts. You can substitute any of them:

**Custom logger** — must satisfy `LoggerConcept`:
```cpp
struct MyLogger {
    void report(const Kerbecs::Violation& v) noexcept {
        // v.m_Kind, v.m_Name, v.m_Address, v.m_AllocSite, v.m_FreeSite, etc.
    }
};
```

**Custom shadow map** — must satisfy `ShadowMapConcept`:
```cpp
struct MyShadowMap {
    void   poison(void* p, size_t n) noexcept;
    void   unpoison(void* p, size_t n) noexcept;
    size_t countPoisoned(void* p, size_t n) noexcept;
    void*  toShadow(void* p, size_t n) noexcept;
};
```

**Custom allocator** — must satisfy `AllocatorConcept`:
```cpp
struct MyAllocator {
    void* allocate(size_t bytes, size_t align) noexcept;
    void  deallocate(void* p, size_t bytes) noexcept;
};
```

**Custom hash accumulator** — must satisfy `HashAccumulatorConcept`:
```cpp
struct MyHasher {
    void     add(uint64_t v) noexcept;
    uint64_t finalize() noexcept;
    void     reset() noexcept;
};
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     KerbecsMemoryZone                        │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐ │
│  │ ShadowZone  │  │ GlobalZone  │  │     StaticZone       │ │
│  │  (bitmap)   │  │  (globals)  │  │  (persistent objs)   │ │
│  └─────────────┘  └─────────────┘  └──────────────────────┘ │
│                                                              │
│  AllocationRegistry     QuarantineQueue     KerbecsStats     │
└──────────────────────────────────────────────────────────────┘
```

### Virtual address layout

The zone reserves a single contiguous VA range split into three regions, none of which are committed at init. Pages are committed lazily by the bump allocators on first touch. The preferred base address is `0x0000100000000000`.

```
[ ShadowZone | GlobalZone | StaticZone ]
```

These three regions are **internal to Kerbecs** — user allocations do not come from here:

- **ShadowZone** — the shadow bitmap. Every user address maps into this region at 1:8 scale. Kerbecs writes poison/unpoison/tombstone bits here; users never allocate from it directly.
- **GlobalZone** — backing store for `KERBECS_GLOBAL` macro allocations only.
- **StaticZone** — backing store for `KERBECS_PERSISTENT` macro allocations only.

User heap allocations are served entirely by the allocator you provide to `ShadowPtr`. Kerbecs only tracks and shadows them — it does not supply the backing memory.

### Shadow bitmap

The shadow bitmap maps user addresses at 1:8 scale (1 bit per user byte, `SHADOW_SCALE = 3`). Every allocation starts with its payload region fully poisoned (`0xFA`). `shadowConstruct` unpoisons the object's bytes; `shadowDestroy` tombstones them (`0xDD`). The bitmap is stored in the `ShadowZone` and accessed via `KerbecsShadowMap`.

### Block layouts

Three layouts are available, selected as the first template parameter of `ShadowPtr`:

| Layout | Guard structure | Metadata | Use case |
|---|---|---|---|
| `NormalLayout` | Leading + trailing redzones | `NormalMetaData` (size, allocator hash) | General heap allocations |
| `EnhancedLayout` | Redzones + canaries on both sides | `EnhancedMetaData` (+ thread hash + checksum) | High-security or long-lived objects |
| `StaticLayout` | Redzones + canaries, no in-block metadata | Handle itself is the metadata | Static / global objects via macros |

Redzone bytes are `0xFE`; canary words are `0xDEADBEEFCAFEBABE`.

### Allocation registry

A lock-free hash map with per-bucket spinlocks for insert. Each `RegistryNode` tracks the block base, user pointer, sizes, allocator ID, thread ID, alloc/free stack traces, and a live object count.

State machine per node:

```
Empty → Live → Retiring → Quarantine → Dead
```

- `beginRetiring` CAS-transitions `Live → Retiring` and acquires the dtor lock
- `endRetiring` transitions either back to `Live` (if objects remain) or to `Quarantine` (if count reaches zero)
- `retire` transitions `Quarantine → Dead` when the quarantine queue flushes the block

### Quarantine queue

A ring buffer of fixed-size slots (`QUARANTINE_CAPACITY`). Each slot stores the block base, size, epoch stamp, allocator pointer, and a type-erased dealloc thunk. A block enqueued at epoch N is only eligible for release when `N + 2 <= currentEpoch`.

**Kerbecs never advances the epoch or calls `flushEligible` on its own.** Both are the consumer's responsibility, typically done on a dedicated background thread (see [Epoch thread](#epoch-thread-required)). `flushEligible` is protected by an internal spinlock so only one flush runs at a time.

### Bump allocators

Three zone-local `BumpAllocatorBase` subclasses (`ShadowzoneAllocator`, `StaticAllocator`, `GlobalAllocator`). All are lock-free via CAS on an atomic cursor. `deallocate` is a no-op; memory is bulk-released at teardown via `Memory::release` on the full VA range.

---

## Violation types

Violations are reported through the injected `Logger` as a `Violation` struct containing the kind, faulting address, block base, size, alloc/free/access stack traces, thread ID, and a TSC timestamp.

| Violation | Trigger |
|---|---|
| `DoubleFree` | `shadowDestroy` called on an already-tombstoned object |
| `UseAfterFree` | Access to a block in `Quarantine` state |
| `UseBeforeInit` | Access to a fully poisoned (never constructed) region |
| `BufferOverflow` | Redzone or canary pattern corrupted at destroy time |
| `OverlapDetected` | Two tracked allocations share the same block base |
| `LeakDetected` | Live node found during `teardownShadowzone` scan |
| `MetadataCorruption` | Checksum or mirror mismatch in `EnhancedMetaData` |
| `AlignmentViolation` | `construct<T>()` pointer is not aligned to `alignof(T)` |
| `SizeOverflow` | `blockSize<T>()` multiplication wrapped |
| `WildPointer` | Address not found in `AllocationRegistry` |
| `ThreadOwnership` | `shadowDestroy` called from a different thread than the allocating one |
| `QuarantineSaturation` | Quarantine ring buffer full — fail fast |
| `RetiredBoundaryViolation` | Non-owner thread accessed a block in `Retiring` state — fail fast |

---

## Contributing

Contributions are welcome. Please keep the following in mind:

- The project requires C++20. Avoid features not broadly supported across MSVC, Clang, and GCC.
- All new allocator, layout, shadow map, logger, and hasher types must satisfy their respective concepts (`AllocatorConcept`, `LayoutPolicyConcept`, etc.) — add a `static_assert` confirming this alongside the type definition.
- Kerbecs is a DLL-only build. Do not add code paths that assume static linkage.
- `noexcept` is expected on all hot paths. Violations are reported through the logger, not via exceptions.
- Keep the core subsystems (registry, quarantine, shadow bitmap, zone) decoupled. Cross-subsystem access should go through `MemoryZone::instance()`.

To report a bug, open an issue with a minimal reproducer and the violation output from your logger.

---

## License

MIT License. Copyright (c) 2025 StormWeaver. See [LICENSE](LICENSE) for the full text.