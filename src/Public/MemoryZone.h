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
#include <cstdint>
#include <atomic>
#include "Kerbecs.h"
#include "KerbecsDiagnostics.h"
#include "KerbecsStats.h"
#include "KerbecsAllocators.h"
#include "MemorySupport.h"
#include "AllocationRegistry.h"
#include "QuarantineQueue.h"

namespace Kerbecs::MemoryZone {
	constexpr uintptr_t MEMORY_ZONE_ADDRESS = 0x0000100000000000; // preferred VA base

	constexpr uint8_t  POISONED = 0xFA;
	constexpr uint8_t  UNPOISONED = 0x0A;
	constexpr uint8_t  REDZONE = 0xFE;
	constexpr uint8_t  TOMBSTONE = 0xDD;
	constexpr uint64_t GUARD_CANARY = 0xDEADBEEFCAFEBABEULL;
	constexpr size_t   SHADOW_SCALE = 3; // 1 bit per user byte - shadow is 1/8 user size

	constexpr size_t REDZONE_SIZE = 16;
	constexpr size_t CANARY_SIZE = 8;

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

	struct KERBECS_RUNTIME_API UserRange final {
		void* m_Start;
		void* m_End; // inclusive
	};

	// KerbecsMemoryZone
	//
	// Singleton owning the entire Kerbecs VA reservation and all subsystems.
	//
	// VA layout (all reserved in one contiguous block, none committed upfront):
	//   [ShadowZone][GlobalZone][StaticZone]
	//
	// All three zones are lazy-committed. Each allocator calls
	// commitPageIfNeeded on every page boundary it crosses. No upfront
	// commit calls are made in init().
	//
	// StaticRegion is removed. Its responsibilities are split:
	//   m_ShadowzoneAllocator -> bumps inside m_ShadowZone (shadow bitmap)
	//   m_StaticAllocator     -> bumps inside m_StaticZone (KERBECS_PERSISTENT)
	//   m_GlobalAllocator     -> bumps inside m_GlobalZone (KERBECS_GLOBAL)
	//
	// The registry and quarantine self-allocate their own storage via
	// Memory::allocate - they do not carve from any zone.
	// 
	struct alignas(128) KERBECS_RUNTIME_API KerbecsMemoryZone final {
		// Zone base pointers - set after reservation, never changed.
		void* m_MemoryZone = nullptr; // base of entire reserved VA block
		void* m_ShadowZone = nullptr; // shadow bitmap region
		void* m_GlobalZone = nullptr; // backing for GlobalAllocator
		void* m_StaticZone = nullptr; // backing for StaticAllocator

		// Three lazy-commit bump allocators - one per zone.
		// Owned directly by the zone. MemorySupport wrappers hold pointers
		// to these members and provide the type-erased thunk for quarantine.

		Allocators::ShadowzoneAllocator m_ShadowzoneAllocatorImpl;
		Allocators::StaticAllocator     m_StaticAllocatorImpl;
		Allocators::GlobalAllocator     m_GlobalAllocatorImpl;

		Shadow::Internal::MemorySupport<Allocators::ShadowzoneAllocator> m_ShadowzoneAllocator;
		Shadow::Internal::MemorySupport<Allocators::StaticAllocator>     m_StaticAllocator;
		Shadow::Internal::MemorySupport<Allocators::GlobalAllocator>     m_GlobalAllocator;

		std::atomic<uint64_t> m_Epoch{ 0 };
		// Global stats - all atomic counters.
		KerbecsStats m_Stats;

		// Live allocation tracking - self-allocating node pool.
		Tracing::AllocationRegistry m_Registry;

		// Deferred-free ring buffer - self-allocating slot array.
		Quarantine::QuarantineQueue m_Quarantine;

		std::atomic<bool> m_Initialized{ false };
		std::atomic<bool> m_Shutdown{ false };

		// Non-copyable, non-movable.
		KerbecsMemoryZone() = default;
		KerbecsMemoryZone(const KerbecsMemoryZone&) = delete;
		KerbecsMemoryZone& operator=(const KerbecsMemoryZone&) = delete;
		KerbecsMemoryZone(KerbecsMemoryZone&&) = delete;
		KerbecsMemoryZone& operator=(KerbecsMemoryZone&&) = delete;
		~KerbecsMemoryZone() = default;

		// No FreeCallback parameter - quarantine is self-contained.
		bool init() noexcept;
	};

	// Heap-allocated singleton to avoid static destructor ordering issues.
	KERBECS_FORCEINLINE KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsMemoryZone& instance() {
		static KerbecsMemoryZone* s_Instance = new KerbecsMemoryZone();
		return *s_Instance;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsStats& stats() {
		return instance().m_Stats;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Tracing::AllocationRegistry& registry() {
		return instance().m_Registry;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Quarantine::QuarantineQueue& quarantine() {
		return instance().m_Quarantine;
	}

	KERBECS_RUNTIME_API void*  mapToShadow(void* p_User, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API UserRange mapToUser(void* p_Shadow) noexcept;

	KERBECS_RUNTIME_API bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept;

	// No FreeCallback - removed entirely.
	KERBECS_FORCEINLINE KERBECS_RUNTIME_API bool initShadowzone() noexcept {
		return instance().init();
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API bool teardownShadowzone() noexcept {
		auto& zone = instance();

		if (zone.m_Shutdown.load(std::memory_order_acquire))
			return false;

		// Drain all quarantine entries regardless of epoch, then release
		// the quarantine's self-allocated slab.
		zone.m_Quarantine.flushEligible(
			zone.m_Registry.poolSegment(),
			SIZE_MAX);

		zone.m_Quarantine.shutdown();

		// ---- Leak detection ----
		// Scan the node pool for any blocks still Live, Retiring, or
		// Quarantine after the final flush. Each one is a leak - increment
		// the violation counter and trap after the scan so the full leak
		// count is visible in stats before the process halts.
		{
			const Tracing::NodePoolSegment seg = zone.m_Registry.poolSegment();
			bool leakFound = false;

			if (seg.m_Pool) {
				for (size_t i = 0; i < seg.m_Capacity; ++i) {
					const auto& node = seg.m_Pool[i];
					const auto state =
						node.m_State.load(std::memory_order_acquire);

					if (state == Tracing::Internal::AllocationState::Live ||
						state == Tracing::Internal::AllocationState::Retiring ||
						state == Tracing::Internal::AllocationState::Quarantine) {
						statsOnViolation(&zone.m_Stats);
						leakFound = true;
					}
				}
			}

			if (leakFound)
				KERBECS_TRAP();
		}

		// Release the registry node pool.
		zone.m_Registry.shutdown();

		// Release the main VA reservation.
		constexpr size_t totalBytes =
			(static_cast<size_t>(SHADOWZONE_SIZE) +
			 static_cast<size_t>(GLOBALZONE_SIZE) +
			 static_cast<size_t>(STATICZONE_SIZE)) * Memory::GIBI_BYTE;

		KERBECS_UNUSED(Memory::release(zone.m_MemoryZone, totalBytes));

		zone.m_MemoryZone = nullptr;
		zone.m_ShadowZone = nullptr;
		zone.m_GlobalZone = nullptr;
		zone.m_StaticZone = nullptr;

		zone.m_Initialized.store(false, std::memory_order_release);
		zone.m_Shutdown.store(true, std::memory_order_release);

		return true;
	}
} // namespace Kerbecs::MemoryZone