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

	struct KERBECS_RUNTIME_API StaticRegion final {
		void* m_Base = nullptr;
		std::atomic<size_t>  m_Bump = 0;        // only atomic member
		size_t               m_Size = 0;

		// Non-copyable, non-movable
		StaticRegion() = default;
		StaticRegion(const StaticRegion&) = delete;
		StaticRegion& operator=(const StaticRegion&) = delete;
		StaticRegion(StaticRegion&&) = delete;
		StaticRegion& operator=(StaticRegion&&) = delete;

		KERBECS_NODISCARD_MSG("Cannot discard ptr to allocated memory") void* allocate(size_t v_Size, size_t v_Align) noexcept;
	};

	struct alignas(128) KERBECS_RUNTIME_API KerbecsMemoryZone final {
		void* m_MemoryZone = nullptr; // base of entire reserved VA block
		void* m_ShadowZone = nullptr; // shadow bitmap region (lazy commit)
		void* m_GlobalZone = nullptr; // registry, stats, violation queue
		void* m_StaticZone = nullptr; // bump-allocated persistent allocations

		StaticRegion m_StaticRegion;          // bump allocator over m_StaticZone
		KerbecsStats m_Stats;                 // global stats - atomic counters
		Tracing::AllocationRegistry  m_Registry;     // live allocation tracking
		Quarantine::QuarantineQueue     m_Quarantine;   // deferred-free ring buffer

		bool         m_Initialized = false;
		bool         m_Shutdown = false;

		// Non-copyable, non-movable
		KerbecsMemoryZone() = default;
		KerbecsMemoryZone(const KerbecsMemoryZone&) = delete;
		KerbecsMemoryZone& operator=(const KerbecsMemoryZone&) = delete;
		KerbecsMemoryZone(KerbecsMemoryZone&&) = delete;
		KerbecsMemoryZone& operator=(KerbecsMemoryZone&&) = delete;
		~KerbecsMemoryZone() = default;
		bool init(Quarantine::QuarantineQueue::FreeCallback p_FreeCallback) noexcept;
	};

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
	KerbecsMemoryZone& instance() {
		static KerbecsMemoryZone s_Instance;
		return s_Instance;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
	KerbecsStats& stats() {
		return instance().m_Stats;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Tracing::AllocationRegistry& registry() {
		return instance().m_Registry;
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Quarantine::QuarantineQueue& quarantine() {
		return instance().m_Quarantine;
	}

	 void* KERBECS_RUNTIME_API mapToShadow(void* p_User, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API UserRange  mapToUser(void* p_Shadow) noexcept;

	KERBECS_RUNTIME_API bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept;
	KERBECS_RUNTIME_API bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept;

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API bool initShadowzone(
		Quarantine::QuarantineQueue::FreeCallback p_FreeCallback) noexcept {
		return instance().init(p_FreeCallback);
	}

	KERBECS_FORCEINLINE KERBECS_RUNTIME_API bool teardownShadowzone() noexcept {
		auto& zone = instance();
		if (zone.m_Shutdown) return false;

		// Flush any remaining quarantine entries before releasing VA
		zone.m_Quarantine.flush();

		KERBECS_UNUSED(Memory::release(
			zone.m_MemoryZone,
			(static_cast<size_t>(SHADOWZONE_SIZE) +
				static_cast<size_t>(GLOBALZONE_SIZE) +
				static_cast<size_t>(STATICZONE_SIZE)) * Memory::GIBI_BYTE));

		zone.m_MemoryZone = nullptr;
		zone.m_ShadowZone = nullptr;
		zone.m_GlobalZone = nullptr;
		zone.m_StaticZone = nullptr;
		zone.m_Initialized = false;
		zone.m_Shutdown = true;

		return true;
	}

}
