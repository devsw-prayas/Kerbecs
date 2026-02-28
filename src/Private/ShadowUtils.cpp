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

#include "KerbecsDiagnostics.h"
#include "MemoryZone.h"

namespace Kerbecs::Shadow::Utils {
	bool verifyTombstone(const void* p_Memory, size_t v_Length) {
		if (v_Length == 0) return true;
		if (!p_Memory) return false;

		KERBECS_STATIC_ASSERT(sizeof(MemoryZone::TOMBSTONE) == 1, "Invalid TOMBSTONE bit length");

		const std::byte* base = static_cast<const std::byte*>(p_Memory);
		for (size_t i = 0; i < v_Length; i++) {
			if (base[i] != static_cast<std::byte>(MemoryZone::TOMBSTONE))
				return false;
		}
		return true;
	}

	bool verifyRedzone(const void* p_User, size_t v_Length) {
		if (v_Length == 0) return true;
		if (!p_User) return false;

		KERBECS_STATIC_ASSERT(sizeof(MemoryZone::REDZONE) == 1, "Invalid REDZONE bit length");

		const uint8_t* base = static_cast<const uint8_t*>(p_User);
		for (size_t i = 0; i < v_Length; i++) {
			if (base[i] != static_cast<uint8_t>(MemoryZone::REDZONE))
				return false;
		}
		return true;
	}

	bool verifyCanaries(const void* p_User, size_t v_Length) {
		if (v_Length == 0) return true;
		if (!p_User) return false;

		KERBECS_STATIC_ASSERT(sizeof(MemoryZone::GUARD_CANARY) == sizeof(uint64_t), "Invalid CANARY bit length");

		const std::byte* base = static_cast<const std::byte*>(p_User);

		size_t fullWords = v_Length / sizeof(uint64_t);
		size_t tail = v_Length % sizeof(uint64_t);

		for (size_t i = 0; i < fullWords; i++) {
			uint64_t word;
			std::memcpy(&word, base + i * sizeof(uint64_t), sizeof(uint64_t));
			if (word != MemoryZone::GUARD_CANARY) return false;
		}

		if (tail > 0) {
			if (std::memcmp(base + fullWords * sizeof(uint64_t),
				&MemoryZone::GUARD_CANARY, tail) != 0)
				return false;
		}

		return true;
	}
}