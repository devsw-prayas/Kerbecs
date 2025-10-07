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
#include  "Memory.h"
#include "MemoryZone.h"

#if defined(_WIN32)
#include <Windows.h>
#elif defined(__linux__)
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <sched.h>
#endif

namespace Kerbecs::MemoryZone {
	bool KerbecsMemoryZone::init() {
		size_t totalBytes = SHADOWZONE_SIZE * Memory::GIBI_BYTE + GLOBALZONE_SIZE * Memory::GIBI_BYTE;
		bool reserved = true;
#if defined(_WIN32)
		m_MemoryZone = VirtualAlloc(std::bit_cast<void*>(MEMORY_ZONE_ADDRESS), totalBytes, MEM_RESERVE, PAGE_NOACCESS);
		reserved = m_MemoryZone != nullptr;
#elif defined(__linux__)
		m_MemoryZone = mmap(std::bit_cast<void*>(MEMORY_ZONE_ADDRESS), totalBytes, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		reserved = m_MemoryZone != MAP_FAILED;
#endif
		if (!reserved) m_MemoryZone = Memory::reserve(totalBytes);
		if (!m_MemoryZone) return m_Initialized = false;
		m_ShadowZone = m_MemoryZone;
		m_GlobalZone = static_cast<std::byte*>(m_ShadowZone) + SHADOWZONE_SIZE * Memory::GIBI_BYTE;
		m_Shutdown = false;
		return m_Initialized = true;
	}

	void* mapToShadow(void* p_User, size_t v_Size) noexcept {
		if (!p_User || v_Size == 0) return nullptr;

		uintptr_t userStart = reinterpret_cast<uintptr_t>(p_User);
		uintptr_t userEnd = userStart + v_Size - 1;

		// Compute shadow addresses (scale + offset)
		uintptr_t shadowStart = (userStart >> SHADOW_SCALE) + reinterpret_cast<uintptr_t>(instance().m_ShadowZone);
		uintptr_t shadowEnd = (userEnd >> SHADOW_SCALE) + reinterpret_cast<uintptr_t>(instance().m_ShadowZone);

		// Bounds check against reserved shadowzone
		uintptr_t shadowZoneStart = reinterpret_cast<uintptr_t>(instance().m_ShadowZone);
		uintptr_t shadowZoneEnd = reinterpret_cast<uintptr_t>(instance().m_GlobalZone);

		if (shadowStart < shadowZoneStart || shadowEnd >= shadowZoneEnd) {
			return nullptr; // mapping would spill outside
		}

		return std::bit_cast<void*>(shadowStart);
	}

	UserRange mapToUser(void* p_Shadow) noexcept {
		if (!p_Shadow) return { nullptr, nullptr };

		uintptr_t shadowAddr = reinterpret_cast<uintptr_t>(p_Shadow);
		uintptr_t shadowZoneStart = reinterpret_cast<uintptr_t>(instance().m_ShadowZone);
		uintptr_t shadowZoneEnd = shadowZoneStart + SHADOWZONE_SIZE * Memory::GIBI_BYTE;

		// Bounds check
		if (shadowAddr < shadowZoneStart || shadowAddr >= shadowZoneEnd) {
			return { nullptr, nullptr }; // outside valid shadowzone
		}

		// Compute user range
		uintptr_t userBase = (shadowAddr - shadowZoneStart) << SHADOW_SCALE; // multiply by 8
		uintptr_t userEnd = userBase + ((1 << SHADOW_SCALE) - 1);           // base+7

		return { std::bit_cast<void*>(userBase), std::bit_cast<void*>(userEnd) };
	}

	bool shadowPoison(void* userPtr, size_t size) {
		if (!userPtr || size == 0) return false;

		auto* shadow = static_cast<uint8_t*>(MemoryZone::mapToShadow(userPtr, size));
		if (!shadow) return false;

		uintptr_t addr = reinterpret_cast<uintptr_t>(userPtr);

		// First partial shadow byte
		size_t bitPos = addr & 0x7;
		size_t firstLen = std::min<size_t>(size, 8 - bitPos);

		for (size_t i = 0; i < firstLen; i++) {
			shadow[0] |= (1u << (bitPos + i));
		}

		size -= firstLen;
		addr += firstLen;
		shadow += (addr >> 3) - ((addr - firstLen) >> 3);

		// Middle full shadow bytes
		size_t fullBytes = size >> 3;
		for (size_t i = 0; i < fullBytes; i++) {
			shadow[i] = 0xFF;  // poison all 8 bytes
		}

		// Tail
		size_t tail = size & 0x7;
		if (tail > 0) {
			for (size_t i = 0; i < tail; i++) {
				shadow[fullBytes] |= (1u << i);
			}
		}

		return true;
	}

	bool shadowUnpoison(void* userPtr, size_t size) {
		if (!userPtr || size == 0) return false;

		auto* shadow = static_cast<uint8_t*>(MemoryZone::mapToShadow(userPtr, size));
		if (!shadow) return false;

		uintptr_t addr = reinterpret_cast<uintptr_t>(userPtr);

		// First partial shadow byte
		size_t bitPos = addr & 0x7;
		size_t firstLen = std::min<size_t>(size, 8 - bitPos);

		for (size_t i = 0; i < firstLen; i++) {
			shadow[0] &= ~(1u << (bitPos + i));
		}

		size -= firstLen;
		addr += firstLen;
		shadow += (addr >> 3) - ((addr - firstLen) >> 3);

		// Middle full shadow bytes
		size_t fullBytes = size >> 3;
		for (size_t i = 0; i < fullBytes; i++) {
			shadow[i] = 0x00;  // unpoison all 8 bytes
		}

		// Tail
		size_t tail = size & 0x7;
		if (tail > 0) {
			for (size_t i = 0; i < tail; i++) {
				shadow[fullBytes] &= ~(1u << i);
			}
		}

		return true;
	}
}