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

namespace Kerbecs::Runtime {
	constexpr uintptr_t MEMORY_ZONE_ADDRESS = 0x0000100000000000;

	constexpr uint8_t  POISONED = 0xFA;
	constexpr uint8_t  UNPOISONED = 0x0A;
	constexpr uint8_t  REDZONE = 0xFE;
	constexpr uint8_t  TOMBSTONE = 0xDD;
	constexpr uint64_t GUARD_CANARY = 0xDEADBEEFCAFEBABEULL;
	constexpr size_t   SHADOW_SCALE = 3;

	constexpr size_t REDZONE_SIZE = 16;
	constexpr size_t CANARY_SIZE = 8;

	constexpr auto DRAIN_INTERVAL = std::chrono::milliseconds(50);

	struct KERBECS_RUNTIME_API alignas(32) NormalMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
	};

	struct KERBECS_RUNTIME_API alignas(64) EnhancedMetaData final {
		size_t m_TotalSize;
		size_t m_TotalCommitted;
		size_t m_TotalPoisoned;
		size_t m_AllocatorHash;
		size_t m_ThreadHash;
		size_t m_Checksum;
	};

	struct KERBECS_RUNTIME_API alignas(16) AccessInfo final {
		size_t                m_UserSize;
		std::atomic<uint64_t> m_Generation;
	};

	struct alignas(128) KERBECS_RUNTIME_API KerbecsRuntime final {
		void* m_MemoryZone = nullptr;
		void* m_ShadowZone = nullptr;
		void* m_GlobalZone = nullptr;
		void* m_StaticZone = nullptr;
		void* m_MetadataZone = nullptr;

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

		Quarantine::QuarantineQueue m_Quarantine;

		std::atomic<bool> m_Initialized{ false };
		std::atomic<bool> m_Shutdown{ false };

		std::thread       m_DrainThread;
		std::atomic<bool> m_DrainRunning{ false };

		KerbecsRuntime() = default;
		KerbecsRuntime(const KerbecsRuntime&) = delete;
		KerbecsRuntime& operator=(const KerbecsRuntime&) = delete;
		KerbecsRuntime(KerbecsRuntime&&) = delete;
		KerbecsRuntime& operator=(KerbecsRuntime&&) = delete;
		~KerbecsRuntime() = default;

		bool init() noexcept;

	private:
		void _drainLoop() noexcept;

	public:

		KERBECS_NODISCARD_MSG("Cannot discard allocated shadow blob pointer")
			void* shadowzoneAllocate(size_t v_Bytes) noexcept;

		KERBECS_NODISCARD_MSG("Cannot discard allocated metadata block pointer")
			void* metadataZoneAllocate(size_t v_Bytes, size_t v_Align) noexcept;

		bool registerRegion(
			void* p_Region,
			void* p_ShadowMapBase,
			void* p_MetadataMapBase,
			size_t v_Size,
			void* p_RegionBase = nullptr) noexcept;
	};

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsRuntime& instance() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		KerbecsStats& stats() noexcept;

	KERBECS_RUNTIME_API
		KERBECS_NODISCARD_MSG("Cannot discard singleton reference")
		Quarantine::QuarantineQueue& quarantine() noexcept;

	KERBECS_RUNTIME_API bool initShadowzone() noexcept;
	KERBECS_RUNTIME_API bool teardownShadowzone() noexcept;

} // namespace Kerbecs::Runtime
