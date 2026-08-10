/*
* Copyright (c) 2025 StormWeaver
*
* This file is part of the Kerbecs Address Sanitizer API
*
* Licensed under the MIT License. You may obtain a copy of the License at
* https://opensource.org/licenses/MIT
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
*/

#pragma once
#include "Kerbecs.h"
#include "KerbecsDiagnostics.h"
#include "KerbecsStats.h"
#include "KerbecsAllocators.h"
#include "MemorySupport.h"
#include "QuarantineQueue.h"
#include <chrono>
#include <thread>

// KerbecsRuntime: Engine-internal VA-partition manager.
// Regions request zone-backed storage (shadowzoneAllocate/metadataZoneAllocate/registerRegion).
// AllocationRegistry is owned per-Region; KerbecsRuntime owns only shared state:
// QuarantineQueue + epoch and global stats.
namespace Kerbecs::Runtime {
	constexpr uintptr_t MEMORY_ZONE_ADDRESS = 0x0000100000000000; // preferred VA base

	constexpr uint8_t  POISONED = 0xFA;
	constexpr uint8_t  UNPOISONED = 0x0A;
	constexpr uint8_t  REDZONE = 0xFE;
	constexpr uint8_t  TOMBSTONE = 0xDD;
	constexpr uint64_t GUARD_CANARY = 0xDEADBEEFCAFEBABEULL;
	constexpr size_t   SHADOW_SCALE = 3; // 1 bit per user byte - shadow is 1/8 user size

	constexpr size_t REDZONE_SIZE = 16;
	constexpr size_t CANARY_SIZE = 8;

	// Drain thread cadence: each tick bumps m_Epoch by 1 and does a non-forced
	// flushEligible pass, so a block enqueued at epoch N becomes eligible for
	// release after roughly 2 * DRAIN_INTERVAL_MS.
	constexpr auto DRAIN_INTERVAL = std::chrono::milliseconds(50);

	// [Size: 32 bytes]
	struct KERBECS_RUNTIME_API alignas(32) NormalMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
	};

	// [Size: 48 bytes]
	struct KERBECS_RUNTIME_API alignas(64) EnhancedMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
		size_t m_ThreadHash;
		size_t m_Checksum;
	};

	// AccessInfo: Fixed, Layout-agnostic target for ShadowedMemory<T>::m_MetaPtr
	// in MetadataZone. Discouples ShadowedMemory<T> reads from Region Layout template parameters,
	// allowing O(1) bounds and generation checks without knowing the Region's Layout type.
	struct KERBECS_RUNTIME_API alignas(16) AccessInfo final {
		size_t                m_UserSize;   // payload byte size - ShadowedMemory<T>::operator+ bounds check
		std::atomic<uint64_t> m_Generation; // mirrors the owning RegistryNode::m_Generation - O(1) staleness check, no registry lookup needed. Atomic: written by Region::destroy while concurrently read (lock-free) by ShadowedMemory::_check() on other threads.
	};

	// KerbecsRuntime
	//
	// Singleton owning the entire Kerbecs VA reservation and the subsystems
	// that stay genuinely process-wide.
	//
	// VA layout (all reserved in one contiguous block, none committed upfront):
	//   [ShadowZone][GlobalZone][StaticZone][MetadataZone]
	//
	// All four zones are lazy-committed. Each allocator calls
	// commitPageIfNeeded on every page boundary it crosses. No upfront
	// commit calls are made in init().
	//
	//   m_ShadowzoneAllocator  -> bumps inside m_ShadowZone (shadow bitmap)
	//   m_StaticAllocator      -> bumps inside m_StaticZone (KERBECS_PERSISTENT)
	//   m_GlobalAllocator      -> bumps inside m_GlobalZone (KERBECS_GLOBAL)
	//   m_MetadataZoneAllocator-> bumps inside m_MetadataZone (per-allocation
	//                             metadata/guard poisoning)
	//
	// The quarantine self-allocates its own storage via Memory::allocate - it
	// does not carve from any zone. Each Region's own AllocationRegistry does
	// the same.
	struct alignas(128) KERBECS_RUNTIME_API KerbecsRuntime final {
		// Zone base pointers - set after reservation, never changed.
		void* m_MemoryZone = nullptr;   // base of entire reserved VA block
		void* m_ShadowZone = nullptr;   // shadow bitmap region
		void* m_GlobalZone = nullptr;   // backing for GlobalAllocator
		void* m_StaticZone = nullptr;   // backing for StaticAllocator
		void* m_MetadataZone = nullptr; // backing for MetadataZoneAllocator

		// Four lazy-commit bump allocators - one per zone.
		// Owned directly by the runtime. MemorySupport wrappers hold pointers
		// to these members and provide the type-erased thunk for quarantine.

		Allocators::ShadowzoneAllocator   m_ShadowzoneAllocatorImpl;
		Allocators::StaticAllocator       m_StaticAllocatorImpl;
		Allocators::GlobalAllocator       m_GlobalAllocatorImpl;
		Allocators::MetadataZoneAllocator m_MetadataZoneAllocatorImpl;

		Shadow::Internal::MemorySupport<Allocators::ShadowzoneAllocator>   m_ShadowzoneAllocator;
		Shadow::Internal::MemorySupport<Allocators::StaticAllocator>       m_StaticAllocator;
		Shadow::Internal::MemorySupport<Allocators::GlobalAllocator>       m_GlobalAllocator;
		Shadow::Internal::MemorySupport<Allocators::MetadataZoneAllocator> m_MetadataZoneAllocator;

		std::atomic<uint64_t> m_Epoch{ 0 };
		KerbecsStats m_Stats;

		// Shared across every Region - deliberately not per-Region.
		Quarantine::QuarantineQueue m_Quarantine;

		std::atomic<bool> m_Initialized{ false };
		std::atomic<bool> m_Shutdown{ false };

		// Owns the epoch/drain cadence internally - callers never manage a
		// background thread themselves. Started at the end of init(), stopped
		// and joined at the start of teardownShadowzone() before the queue
		// itself is force-flushed and shut down.
		std::thread       m_DrainThread;
		std::atomic<bool> m_DrainRunning{ false };

		KerbecsRuntime() = default;
		KerbecsRuntime(const KerbecsRuntime&) = delete;
		KerbecsRuntime& operator=(const KerbecsRuntime&) = delete;
		KerbecsRuntime(KerbecsRuntime&&) = delete;
		KerbecsRuntime& operator=(KerbecsRuntime&&) = delete;
		~KerbecsRuntime() = default;

		// No FreeCallback parameter - quarantine is self-contained.
		bool init() noexcept;

	private:
		void _drainLoop() noexcept;

	public:

		// Zone-backed storage requests made by Region during construction.
		// Region does not reserve, own, or constrain this VA -
		// it is pure instrumentation and bookkeeping around what it wraps.
		KERBECS_NODISCARD_MSG("Cannot discard allocated shadow blob pointer")
			void* shadowzoneAllocate(size_t v_Bytes) noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard allocated metadata block pointer")
			void* metadataZoneAllocate(size_t v_Bytes, size_t v_Align) noexcept;

		// Registers a Region with the Region-lookup table so
		// a bare/wild address can later be resolved back to the Region that
		// owns it. p_Region is stored opaquely (void*) here - the concrete
		// Region<Layout,ThreadPolicy,Allocator> type lives in Region.h, which
		// this header does not depend on; RegionRecord.h supplies the actual
		// lookup-table storage and is included only by KerbecsRuntime.cpp.
		//
		// p_RegionBase is optional (nullptr if omitted): AllocatorConcept only
		// requires allocate/deallocate, so a generic wrapped Allocator isn't
		// guaranteed to expose a contiguous VA range to range-check against.
		// Region passes its wrapped allocator's base when it has one (true
		// for all four default zone allocators); Regions registered with a
		// null base are simply unreachable via the coarse wild-pointer table -
		// per-block resolution through a known ShadowedMemory<T> handle is
		// unaffected either way, since that path never consults this table.
		bool registerRegion(
			void* p_Region,
			void* p_ShadowMapBase,
			void* p_MetadataMapBase,
			size_t v_Size,
			void* p_RegionBase = nullptr) noexcept;
	};

	// Heap-allocated singleton. Defined in KerbecsRuntime.cpp (not inline) so
	// the function-local static lives in exactly one place — the Kerbecs DLL.
	// KERBECS_FORCEINLINE is intentionally absent: inlining this into every
	// calling TU would give each module its own s_Instance copy.
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsRuntime& instance() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsStats& stats() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Quarantine::QuarantineQueue& quarantine() noexcept;

	// Defined in KerbecsRuntime.cpp — not inline, so instance() is always the DLL copy.
	KERBECS_RUNTIME_API bool initShadowzone() noexcept;
	KERBECS_RUNTIME_API bool teardownShadowzone() noexcept;

} // namespace Kerbecs::Runtime
