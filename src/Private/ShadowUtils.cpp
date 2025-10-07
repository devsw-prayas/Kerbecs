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
#include "ShadowUtils.h"

#include "MemoryZone.h"

namespace Kerbecs::Utils {
	bool rawPoison(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, MemoryZone::POISONED, v_Length);
		return true;
	}

	bool rawUnPoison(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, MemoryZone::UNPOISONED, v_Length);
		return true;
	}

	bool rawRedzone(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, MemoryZone::REDZONE, v_Length);
		return true;
	}

	bool rawDeRedzone(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, 0, v_Length);
		return true;
	}

	bool rawCanary(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::byte* dst = static_cast<std::byte*>(p_Memory) + v_Start;

		size_t fullWords = v_Length / sizeof(uint64_t);
		size_t tail = v_Length % sizeof(uint64_t);

		for (size_t i = 0; i < fullWords; i++) {
			std::memcpy(dst + i * sizeof(uint64_t),
						&MemoryZone::GUARD_CANARY,
						sizeof(uint64_t));
		}

		if (tail > 0) {
			std::memcpy(dst + fullWords * sizeof(uint64_t),
						&MemoryZone::GUARD_CANARY,
						tail);
		}
		return true;
	}

	bool rawRemoveCanary(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, 0, v_Length);
		return true;
	}

	bool rawTombstone(void* p_Memory, size_t v_Start, size_t v_Length) {
		if (!p_Memory) return false;
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, MemoryZone::TOMBSTONE, v_Length);
		return true;
	}

	Utils::MemoryState KERBECS getMemoryState(void* p_User, size_t v_Length) {
		if (!p_User || v_Length == 0) return Utils::MemoryState::CORRUPTED;

		size_t poisoned = countShadowPoisons(p_User, v_Length);
		if (poisoned == v_Length) return Utils::MemoryState::UNINITIALIZED;
		if (poisoned > 0 && poisoned < v_Length) return Utils::MemoryState::CORRUPTED;

		if (verifyTombstone(p_User, v_Length)) return Utils::MemoryState::DESTROYED;

		return Utils::MemoryState::CONSTRUCTED;
	}

	size_t KERBECS countShadowPoisons(void* p_User, size_t v_Length) {
		if (!p_User || v_Length == 0) return 0;

		auto* shadow = static_cast<uint8_t*>(MemoryZone::mapToShadow(p_User, v_Length));
		if (!shadow) return 0;

		uintptr_t addr = reinterpret_cast<uintptr_t>(p_User);
		size_t poisonedCount = 0;

		// --- First partial shadow byte ---
		size_t bitPos = addr & 0x7;
		size_t firstLen = std::min<size_t>(v_Length, 8 - bitPos);
		for (size_t i = 0; i < firstLen; i++) {
			if (shadow[0] & (1u << (bitPos + i))) {
				poisonedCount++;
			}
		}

		v_Length -= firstLen;
		addr += firstLen;
		shadow += (addr >> 3) - ((addr - firstLen) >> 3);

		// --- Full shadow bytes ---
		size_t fullBytes = v_Length >> 3;
		for (size_t i = 0; i < fullBytes; i++) {
			poisonedCount += std::popcount(shadow[i]);
		}

		// --- Tail bits ---
		size_t tail = v_Length & 0x7;
		if (tail > 0) {
			for (size_t i = 0; i < tail; i++) {
				if (shadow[fullBytes] & (1u << i)) {
					poisonedCount++;
				}
			}
		}

		return poisonedCount;
	}

	bool KERBECS verifyTombstone(const void* p_Memory, size_t v_Length) {
		if (!p_Memory || v_Length == 0) return false;

		const std::byte* base = static_cast<const std::byte*>(p_Memory);
		for (size_t i = 0; i < v_Length; i++) {
			if (base[i] != static_cast<std::byte>(MemoryZone::TOMBSTONE)) {
				return false;
			}
		}
		return true;
	}

	bool KERBECS verifyRedzone(void* p_User, size_t v_Length) {
		if (!p_User || v_Length == 0) return false;

		const uint8_t* pBytes = static_cast<const uint8_t*>(p_User);

		for (size_t i = 0; i < v_Length; i++) {
			if (pBytes[i] != MemoryZone::REDZONE) {
				return false;
			}
		}

		return true;
	}

	bool KERBECS verifyCanaries(void* p_User, size_t v_Length) {
		if (!p_User || v_Length == 0) return false;

		const uint8_t* pBytes = static_cast<const uint8_t*>(p_User);

		for (size_t i = 0; i < v_Length; i++) {
			if (pBytes[i] != MemoryZone::GUARD_CANARY) {
				return false;
			}
		}

		return true;
	}
}