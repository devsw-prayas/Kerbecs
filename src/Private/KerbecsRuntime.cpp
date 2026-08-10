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

#include "Kerbecs.h"
#include "KerbecsMemory.h"
#include "KerbecsRuntime.h"
#include "RegionRecord.h"

#include "KerbecsDiagnostics.h"

namespace Kerbecs::Runtime {

	KerbecsRuntime& instance() noexcept {
		static KerbecsRuntime* s_Instance = new KerbecsRuntime();
		return *s_Instance;
	}

	KerbecsStats& stats() noexcept {
		return instance().m_Stats;
	}

	Quarantine::QuarantineQueue& quarantine() noexcept {
		return instance().m_Quarantine;
	}

	bool initShadowzone() noexcept {
		return instance().init();
	}

	bool teardownShadowzone() noexcept {
		auto& zone = instance();

		bool expected = false;
		if (!zone.m_Shutdown.compare_exchange_strong(
			expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
			return false;

		zone.m_DrainRunning.store(false, std::memory_order_release);
		if (zone.m_DrainThread.joinable())
			zone.m_DrainThread.join();

		zone.m_Quarantine.flushEligible(SIZE_MAX, true);
		zone.m_Quarantine.shutdown();

		Tracing::shutdownRegionTable();

		constexpr size_t totalBytes =
			(static_cast<size_t>(SHADOWZONE_SIZE) +
			 static_cast<size_t>(GLOBALZONE_SIZE) +
			 static_cast<size_t>(STATICZONE_SIZE) +
			 static_cast<size_t>(METADATAZONE_SIZE)) * Memory::GIBI_BYTE;

		KERBECS_UNUSED(Memory::release(zone.m_MemoryZone, totalBytes));

		zone.m_MemoryZone = nullptr;
		zone.m_ShadowZone = nullptr;
		zone.m_GlobalZone = nullptr;
		zone.m_StaticZone = nullptr;
		zone.m_MetadataZone = nullptr;

		zone.m_Initialized.store(false, std::memory_order_release);

		return true;
	}

	bool KerbecsRuntime::init() noexcept {
		static std::mutex s_InitMutex;
		std::lock_guard<std::mutex> lock(s_InitMutex);

		if (m_Initialized.load(std::memory_order_acquire))
			return true;

		constexpr size_t shadowBytes =
			static_cast<size_t>(SHADOWZONE_SIZE) * Memory::GIBI_BYTE;

		constexpr size_t globalBytes =
			static_cast<size_t>(GLOBALZONE_SIZE) * Memory::GIBI_BYTE;

		constexpr size_t staticBytes =
			static_cast<size_t>(STATICZONE_SIZE) * Memory::GIBI_BYTE;

		constexpr size_t metadataBytes =
			static_cast<size_t>(METADATAZONE_SIZE) * Memory::GIBI_BYTE;

		constexpr size_t totalBytes =
			shadowBytes + globalBytes + staticBytes + metadataBytes;

		m_MemoryZone = Memory::reserveAt(
			std::bit_cast<void*>(MEMORY_ZONE_ADDRESS),
			totalBytes);

		if (!m_MemoryZone)
			return false;

		auto* base = static_cast<std::byte*>(m_MemoryZone);

		m_ShadowZone = base;
		m_GlobalZone = base + shadowBytes;
		m_StaticZone = base + shadowBytes + globalBytes;
		m_MetadataZone = base + shadowBytes + globalBytes + staticBytes;

		m_ShadowzoneAllocatorImpl.init(m_ShadowZone, shadowBytes);
		m_GlobalAllocatorImpl.init(m_GlobalZone, globalBytes);
		m_StaticAllocatorImpl.init(m_StaticZone, staticBytes);
		m_MetadataZoneAllocatorImpl.init(m_MetadataZone, metadataBytes);

		m_ShadowzoneAllocator = Shadow::Internal::MemorySupport<Allocators::ShadowzoneAllocator>{ &m_ShadowzoneAllocatorImpl };
		m_StaticAllocator = Shadow::Internal::MemorySupport<Allocators::StaticAllocator>{ &m_StaticAllocatorImpl };
		m_GlobalAllocator = Shadow::Internal::MemorySupport<Allocators::GlobalAllocator>{ &m_GlobalAllocatorImpl };
		m_MetadataZoneAllocator = Shadow::Internal::MemorySupport<Allocators::MetadataZoneAllocator>{ &m_MetadataZoneAllocatorImpl };

		if (!m_Quarantine.init(QUARANTINE_CAPACITY, &m_Stats) || !Tracing::initRegionTable()) {
			m_Quarantine.shutdown();
			Tracing::shutdownRegionTable();
			KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));
			m_MemoryZone = nullptr;
			m_ShadowZone = nullptr;
			m_GlobalZone = nullptr;
			m_StaticZone = nullptr;
			m_MetadataZone = nullptr;
			m_Shutdown.store(false, std::memory_order_relaxed);
			m_Initialized.store(false, std::memory_order_release);
			return false;
		}

		m_Shutdown.store(false, std::memory_order_relaxed);
		m_Initialized.store(true, std::memory_order_release);

		m_DrainRunning.store(true, std::memory_order_relaxed);
		m_DrainThread = std::thread(&KerbecsRuntime::_drainLoop, this);

		return true;
	}

	void KerbecsRuntime::_drainLoop() noexcept {
		while (m_DrainRunning.load(std::memory_order_relaxed)) {
			std::this_thread::sleep_for(DRAIN_INTERVAL);
			if (!m_DrainRunning.load(std::memory_order_relaxed))
				break;

			m_Epoch.fetch_add(1, std::memory_order_acq_rel);
			m_Quarantine.flushEligible(SIZE_MAX, false);
		}
	}

	void* KerbecsRuntime::shadowzoneAllocate(size_t v_Bytes) noexcept {
		return m_ShadowzoneAllocatorImpl.allocate(v_Bytes, alignof(std::max_align_t));
	}

	void* KerbecsRuntime::metadataZoneAllocate(size_t v_Bytes, size_t v_Align) noexcept {
		return m_MetadataZoneAllocatorImpl.allocate(v_Bytes, v_Align);
	}

	bool KerbecsRuntime::registerRegion(
		void* p_Region,
		void* p_ShadowMapBase,
		void* p_MetadataMapBase,
		size_t v_Size,
		void* p_RegionBase) noexcept {
		return Tracing::registerRegionRecord(
			p_Region, p_ShadowMapBase, p_MetadataMapBase, p_RegionBase, v_Size);
	}

}

