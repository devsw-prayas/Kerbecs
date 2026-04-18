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

	// Heap-allocated singleton. Defined in MemoryZone.cpp (not inline) so the
	// function-local static lives in exactly one place — the Kerbecs DLL.
	// KERBECS_FORCEINLINE is intentionally absent: inlining this into every
	// calling TU would give each module its own s_Instance copy.
	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsMemoryZone& instance() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsStats& stats() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Tracing::AllocationRegistry& registry() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Quarantine::QuarantineQueue& quarantine() noexcept;

	KERBECS_RUNTIME_API void*  mapToShadow(void* p_User, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API UserRange mapToUser(void* p_Shadow) noexcept;

	KERBECS_RUNTIME_API bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept;

	// Defined in MemoryZone.cpp — not inline, so instance() is always the DLL copy.
	KERBECS_RUNTIME_API bool initShadowzone() noexcept;
	KERBECS_RUNTIME_API bool teardownShadowzone() noexcept;

} // namespace Kerbecs::MemoryZone