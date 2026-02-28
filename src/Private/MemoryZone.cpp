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
#include "MemoryZone.h"
#include "KerbecsDiagnostics.h"

#include <bit>
#include <mutex>
#include <algorithm>

namespace Kerbecs::MemoryZone {


	bool KerbecsMemoryZone::init(Quarantine::QuarantineQueue::FreeCallback p_FreeCallback) noexcept {
		static std::mutex s_InitMutex;
		std::lock_guard<std::mutex> lock(s_InitMutex);

		if (m_Initialized) return true;
		if (m_Shutdown)    return false;

		constexpr size_t totalBytes =
			(static_cast<size_t>(SHADOWZONE_SIZE) +
				static_cast<size_t>(GLOBALZONE_SIZE) +
				static_cast<size_t>(STATICZONE_SIZE)) * Memory::GIBI_BYTE;

		m_MemoryZone = Memory::reserveAt(
			std::bit_cast<void*>(MEMORY_ZONE_ADDRESS),
			totalBytes);

		if (!m_MemoryZone) return false;


		auto* base = static_cast<std::byte*>(m_MemoryZone);
		m_ShadowZone = base;
		m_GlobalZone = base + static_cast<size_t>(SHADOWZONE_SIZE) * Memory::GIBI_BYTE;
		m_StaticZone = base + static_cast<size_t>(SHADOWZONE_SIZE + GLOBALZONE_SIZE) * Memory::GIBI_BYTE;


		constexpr size_t globalBytes = static_cast<size_t>(GLOBALZONE_SIZE) * Memory::GIBI_BYTE;
		if (!Memory::commit(m_GlobalZone, globalBytes, 0)) {
			KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));
			m_MemoryZone = m_ShadowZone = m_GlobalZone = m_StaticZone = nullptr;
			return false;
		}

		constexpr size_t staticBytes = static_cast<size_t>(STATICZONE_SIZE) * Memory::GIBI_BYTE;
		if (!Memory::commit(m_StaticZone, staticBytes, 0)) {
			KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));
			m_MemoryZone = m_ShadowZone = m_GlobalZone = m_StaticZone = nullptr;
			return false;
		}

		auto* globalBase = static_cast<std::byte*>(m_GlobalZone);
		size_t cursor = 0;

		// Registry slots
		constexpr size_t registryAlign = alignof(Tracing::RegistryEntry);
		cursor = Memory::alignUp(cursor, registryAlign);
		constexpr size_t registryBytes = REGISTRY_CAPACITY * sizeof(Tracing::RegistryEntry);

		KERBECS_ASSERT(cursor + registryBytes <= globalBytes);
		auto* registrySlots = reinterpret_cast<Tracing::RegistryEntry*>(globalBase + cursor);
		cursor += registryBytes;

		// Quarantine slots
		constexpr size_t quarantineAlign = alignof(Quarantine::QuarantineEntry);
		cursor = Memory::alignUp(cursor, quarantineAlign);
		constexpr size_t quarantineBytes = QUARANTINE_CAPACITY * sizeof(Quarantine::QuarantineEntry);

		KERBECS_ASSERT(cursor + quarantineBytes <= globalBytes);
		auto* quarantineSlots = reinterpret_cast<Quarantine::QuarantineEntry*>(globalBase + cursor);

		// -----------------------------------------------------------------
		// 5. Initialise registry and quarantine
		// -----------------------------------------------------------------

		if (!m_Registry.init(registrySlots, REGISTRY_CAPACITY)) {
			KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));
			m_MemoryZone = m_ShadowZone = m_GlobalZone = m_StaticZone = nullptr;
			return false;
		}

		if (!m_Quarantine.init(
			quarantineSlots,
			QUARANTINE_CAPACITY,
			&m_Registry,
			&m_Stats,
			p_FreeCallback)) {
			KERBECS_UNUSED(Memory::release(m_MemoryZone, totalBytes));
			m_MemoryZone = m_ShadowZone = m_GlobalZone = m_StaticZone = nullptr;
			return false;
		}

		m_StaticRegion.m_Base = m_StaticZone;
		m_StaticRegion.m_Size = staticBytes;
		m_StaticRegion.m_Bump.store(0, std::memory_order_relaxed);

		m_Shutdown = false;
		m_Initialized = true;
		return true;
	}


	void* StaticRegion::allocate(size_t v_Size, size_t v_Align) noexcept {
		if (!m_Base || v_Size == 0 || v_Align == 0) return nullptr;

		KERBECS_ASSERT((v_Align & (v_Align - 1)) == 0);

		size_t current = m_Bump.load(std::memory_order_relaxed);

		for (;;) {
			size_t aligned = Memory::alignUp(current, v_Align);
			size_t next = aligned + v_Size;

			if (next > m_Size) return nullptr;

			if (m_Bump.compare_exchange_weak(
				current, next,
				std::memory_order_release,
				std::memory_order_relaxed)) {
				statsOnStaticAlloc(&instance().m_Stats);
				return static_cast<std::byte*>(m_Base) + aligned;
			}
		}
	}

	void* mapToShadow(void* p_User, size_t v_Size) noexcept {
		if (!p_User || v_Size == 0) return nullptr;

		const auto& zone = instance();
		if (!zone.m_Initialized || !zone.m_ShadowZone) return nullptr;

		uintptr_t userStart = reinterpret_cast<uintptr_t>(p_User);
		uintptr_t userEnd = userStart + v_Size - 1;

		uintptr_t shadowBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
		uintptr_t shadowStart = (userStart >> SHADOW_SCALE) + shadowBase;
		uintptr_t shadowEnd = (userEnd >> SHADOW_SCALE) + shadowBase;
		uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(zone.m_GlobalZone);

		if (shadowStart < shadowBase || shadowStart >= shadowZoneEnd) return nullptr;
		if (shadowEnd < shadowBase || shadowEnd >= shadowZoneEnd) return nullptr;

		return std::bit_cast<void*>(shadowStart);
	}

	UserRange mapToUser(void* p_Shadow) noexcept {
		if (!p_Shadow) return { nullptr, nullptr };

		const auto& zone = instance();
		if (!zone.m_Initialized || !zone.m_ShadowZone) return { nullptr, nullptr };

		uintptr_t shadowAddr = reinterpret_cast<uintptr_t>(p_Shadow);
		uintptr_t shadowZoneBase = reinterpret_cast<uintptr_t>(zone.m_ShadowZone);
		uintptr_t shadowZoneEnd = shadowZoneBase + static_cast<size_t>(SHADOWZONE_SIZE) * Memory::GIBI_BYTE;

		if (shadowAddr < shadowZoneBase || shadowAddr >= shadowZoneEnd)
			return { nullptr, nullptr };

		uintptr_t userBase = (shadowAddr - shadowZoneBase) << SHADOW_SCALE;
		uintptr_t userEnd = userBase + ((1ULL << SHADOW_SCALE) - 1);

		return {
			std::bit_cast<void*>(userBase),
			std::bit_cast<void*>(userEnd)
		};
	}


	bool shadowPoison(void* p_UserPtr, size_t v_Size) noexcept {
		if (!p_UserPtr || v_Size == 0) return false;

		auto* shadow = static_cast<uint8_t*>(mapToShadow(p_UserPtr, v_Size));
		if (!shadow) return false;

		if (!Memory::commitPageIfNeeded(shadow)) return false;

		uintptr_t addr = reinterpret_cast<uintptr_t>(p_UserPtr);
		size_t    remaining = v_Size;

		size_t bitPos = addr & 0x7;
		size_t firstLen = std::min<size_t>(remaining, 8 - bitPos);
		for (size_t i = 0; i < firstLen; i++)
			shadow[0] |= static_cast<uint8_t>(1u << (bitPos + i));

		remaining -= firstLen;
		KERBECS_UNUSED(addr += firstLen);
		shadow += (firstLen + bitPos) >> 3;

		size_t fullBytes = remaining >> 3;
		for (size_t i = 0; i < fullBytes; i++) {
			if ((reinterpret_cast<uintptr_t>(&shadow[i]) & (Memory::PAGE_SIZE - 1)) == 0)
				KERBECS_UNUSED(Memory::commitPageIfNeeded(&shadow[i]));
			shadow[i] = 0xFF;
		}

		size_t tail = remaining & 0x7;
		if (tail > 0) {
			if ((reinterpret_cast<uintptr_t>(&shadow[fullBytes]) & (Memory::PAGE_SIZE - 1)) == 0)
				KERBECS_UNUSED(Memory::commitPageIfNeeded(&shadow[fullBytes]));
			for (size_t i = 0; i < tail; i++)
				shadow[fullBytes] |= static_cast<uint8_t>(1u << i);
		}

		return true;
	}

	bool shadowUnpoison(void* p_UserPtr, size_t v_Size) noexcept {
		if (!p_UserPtr || v_Size == 0) return false;

		auto* shadow = static_cast<uint8_t*>(mapToShadow(p_UserPtr, v_Size));
		if (!shadow) return false;

		if (Memory::queryPage(shadow) != Memory::PageState::Committed) return true;

		uintptr_t addr = reinterpret_cast<uintptr_t>(p_UserPtr);
		size_t    remaining = v_Size;

		// Segment 1: first partial shadow byte
		size_t bitPos = addr & 0x7;
		size_t firstLen = std::min<size_t>(remaining, 8 - bitPos);
		for (size_t i = 0; i < firstLen; i++)
			shadow[0] &= ~static_cast<uint8_t>(1u << (bitPos + i));

		remaining -= firstLen;
		addr += firstLen;
		shadow += (addr >> 3) - ((addr - firstLen) >> 3);

		// Segment 2: full shadow bytes
		size_t fullBytes = remaining >> 3;
		for (size_t i = 0; i < fullBytes; i++)
			shadow[i] = 0x00;

		// Segment 3: tail partial shadow byte
		size_t tail = remaining & 0x7;
		if (tail > 0) {
			for (size_t i = 0; i < tail; i++)
				shadow[fullBytes] &= ~static_cast<uint8_t>(1u << i);
		}

		return true;
	}

}