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
#include "EnhancedShadowMemory.h"

namespace Kerbecs::Shadow::Enhanced {
	// ----- Poison / Unpoison -----

	bool KERBECS poison(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, 1);
		return Utils::rawPoison(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS unPoison(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowUnpoison(userBase, 1);
		return Utils::rawUnPoison(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS poisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, v_Length);
		return Utils::rawPoison(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS unPoisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowUnpoison(userBase, v_Length);
		return Utils::rawUnPoison(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Redzones -----

	bool KERBECS redzone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return Utils::rawRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS deRedzone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return Utils::rawDeRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS redzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return Utils::rawRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS deRedzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return Utils::rawDeRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Verify Redzones -----
	bool KERBECS verifyRedzone(ESHP po_EnhancedShadow) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		const std::byte* base = static_cast<const std::byte*>(po_EnhancedShadow->m_RawPtr);

		size_t leadingSize = po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading - po_EnhancedShadow->m_Offsets.m_RedzoneOffsetLeading;
		size_t trailingSize = po_EnhancedShadow->m_TotalSize - po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing;

		if (po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing + trailingSize > po_EnhancedShadow->m_TotalSize)
			return false;

		// Leading redzone
		for (size_t i = 0; i < leadingSize; i++) {
			if (base[po_EnhancedShadow->m_Offsets.m_RedzoneOffsetLeading + i] !=
				static_cast<std::byte>(MemoryZone::REDZONE)) return false;
		}


		// Trailing redzone
		for (size_t i = 0; i < trailingSize; i++) {
			if (base[po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing + i] !=
				static_cast<std::byte>(MemoryZone::REDZONE)) return false;
		}


		return true;
	}

	// ---- Verify Canaries
	bool KERBECS verifyCanaries(ESHP po_EnhancedShadow) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		const std::byte* base = static_cast<const std::byte*>(po_EnhancedShadow->m_RawPtr);

		size_t leadingSize = po_EnhancedShadow->m_Offsets.m_UserDataOffset
			- po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading;
		size_t trailingSize = po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing
			- po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing;

		auto checkRegion = [&](size_t offset, size_t length) {
			const std::byte* region = base + offset;
			size_t fullWords = length / sizeof(uint64_t);
			size_t tail = length % sizeof(uint64_t);

			for (size_t i = 0; i < fullWords; i++) {
				uint64_t word;
				std::memcpy(&word, region + i * sizeof(uint64_t), sizeof(uint64_t));
				if (word != MemoryZone::GUARD_CANARY) return false;
			}

			if (tail > 0) {
				if (std::memcmp(region + fullWords * sizeof(uint64_t),
					&MemoryZone::GUARD_CANARY,
					tail) != 0) {
					return false;
				}
			}
			return true;
			};

		return checkRegion(po_EnhancedShadow->m_Offsets.m_CanaryOffsetLeading, leadingSize) &&
			checkRegion(po_EnhancedShadow->m_Offsets.m_CanaryOffsetTrailing, trailingSize);
	}


	// ----- Tombstones -----

	bool KERBECS tombstone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, 1);
		return Utils::rawTombstone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS tombstoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, v_Length);
		return Utils::rawTombstone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS initMetadata(ESHP po_EnhancedShadow, size_t v_AllocatorID, size_t v_ThreadID) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		auto* leading = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
			static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) +
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading
		);
		auto* trailing = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
			static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) +
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing
		);

		size_t allocatorHash = MemoryZone::splitMix64(v_AllocatorID);
		size_t threadHash = MemoryZone::splitMix64(v_ThreadID);
		size_t checksum = MemoryZone::splitMix64(
			allocatorHash ^ threadHash ^ reinterpret_cast<uintptr_t>(po_EnhancedShadow->m_RawPtr)
		);

		// Fill leading metadata
		leading->m_TotalSize = po_EnhancedShadow->m_TotalSize;
		leading->m_TotalCommitted = po_EnhancedShadow->m_TotalSize;
		leading->m_TotalPoisoned = po_EnhancedShadow->m_TotalSize;
		leading->m_AllocatorHash = allocatorHash;
		leading->m_ThreadHash = threadHash;
		leading->m_Checksum = checksum;

		// Copy into trailing metadata (mirror)
		*trailing = *leading;

		return true;
	}

	size_t KERBECS countShadowPoisons(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr || !po_EnhancedShadow->m_ShadowzoneMappingPtr) return 0;

		auto* shadow = static_cast<uint8_t*>(po_EnhancedShadow->m_ShadowzoneMappingPtr);

		uintptr_t addr = reinterpret_cast<uintptr_t>(po_EnhancedShadow->m_RawPtr) + v_Offset;
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

	bool KERBECS verifyTombstone(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		const std::byte* base = static_cast<const std::byte*>(po_EnhancedShadow->m_RawPtr);
		for (size_t i = 0; i < v_Length; i++) {
			if (base[v_Offset + i] != static_cast<std::byte>(MemoryZone::TOMBSTONE)) {
				return false;
			}
		}
		return true;
	}

	bool KERBECS verifyMetadata(
	ESHP po_EnhancedShadow,
	size_t expectedAllocatorID,
	size_t expectedThreadID,
	Utils::ThreadPolicy policy = Utils::ThreadPolicy::Flexible) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		auto* leading = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
			static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) +
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetLeading
		);

		auto* trailing = reinterpret_cast<MemoryZone::EnhancedMetaData*>(
			static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr) +
			po_EnhancedShadow->m_Offsets.m_MetaDataOffsetTrailing
		);

		// 1. Leading vs trailing consistency
		if (std::memcmp(leading, trailing, sizeof(MemoryZone::EnhancedMetaData)) != 0) {
			return false;
		}

		// 2. Size check
		if (leading->m_TotalSize != po_EnhancedShadow->m_TotalSize) return false;

		// 3. Allocator check
		size_t expectedAllocatorHash = MemoryZone::splitMix64(expectedAllocatorID);
		if (leading->m_AllocatorHash != expectedAllocatorHash) return false;

		// 4. Thread check
		size_t expectedThreadHash = MemoryZone::splitMix64(expectedThreadID);
		if (policy == Utils::ThreadPolicy::Strict) {
			if (leading->m_ThreadHash != expectedThreadHash) return false;
		} else {
			// Thread Mismatch allowed
		}

		// 5. Checksum check
		size_t expectedChecksum = MemoryZone::splitMix64(
		leading->m_AllocatorHash ^ leading->m_ThreadHash ^
		reinterpret_cast<uintptr_t>(po_EnhancedShadow->m_RawPtr)
		);
		if (leading->m_Checksum != expectedChecksum) return false;

		return true;
	}
}