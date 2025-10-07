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
#include "ShadowMemory.h"

namespace Kerbecs::Shadow {

	// ----- Poison / Unpoison -----
	bool KERBECS poison(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, 1);
		return Utils::rawPoison(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS unPoison(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowUnpoison(userBase, 1);
		return Utils::rawUnPoison(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS poisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, v_Length);

		return Utils::rawPoison(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS unPoisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowUnpoison(userBase, v_Length);

		return Utils::rawUnPoison(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Redzones -----
	bool KERBECS redzone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return Utils::rawRedzone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS deRedzone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return Utils::rawDeRedzone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS redzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return Utils::rawRedzone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS deRedzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return Utils::rawDeRedzone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// ---- Verify Redzones ---
	bool KERBECS verifyRedzone(SHP po_Shadow) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		const std::byte* base = static_cast<const std::byte*>(po_Shadow->m_RawPtr);

		// Leading redzone size = userDataOffset - redzoneOffsetLeading
		size_t leadingSize = po_Shadow->m_Offsets.m_UserDataOffset - po_Shadow->m_Offsets.m_RedzoneOffsetLeading;
		// Trailing redzone size = totalSize - redzoneOffsetTrailing
		size_t trailingSize = po_Shadow->m_TotalSize - po_Shadow->m_Offsets.m_RedzoneOffsetTrailing;

		// Bounds check
		if (po_Shadow->m_Offsets.m_RedzoneOffsetTrailing + trailingSize > po_Shadow->m_TotalSize)
			return false;

		// Check leading redzone
		for (size_t i = 0; i < leadingSize; i++) {
			if (base[po_Shadow->m_Offsets.m_RedzoneOffsetLeading + i] !=
				static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false;
			}
		}

		// Check trailing redzone
		for (size_t i = 0; i < trailingSize; i++) {
			if (base[po_Shadow->m_Offsets.m_RedzoneOffsetTrailing + i] !=
				static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false;
			}
		}

		return true;
	}

	// ---- Tombstone ----
	bool KERBECS tombstone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, 1);
		return Utils::rawTombstone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS tombstoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		void* userBase = static_cast<std::byte*>(po_Shadow->m_RawPtr) + v_Offset;
		MemoryZone::shadowPoison(userBase, v_Length);
		return Utils::rawTombstone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// Count number of poisoned bytes in the user range [offset, offset+length)
	size_t KERBECS countShadowPoisons(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr || !po_Shadow->m_ShadowzoneMappingPtr) return 0;

		auto* shadow = static_cast<uint8_t*>(po_Shadow->m_ShadowzoneMappingPtr);

		uintptr_t addr = reinterpret_cast<uintptr_t>(po_Shadow->m_RawPtr) + v_Offset;
		size_t poisonedCount = 0;

		// --- First partial shadow byte ---
		size_t bitPos = addr & 0x7;                       // offset inside shadow byte
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

	bool KERBECS initMetadata(SHP po_Shadow, size_t v_AllocatorID) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		auto* meta = reinterpret_cast<MemoryZone::NormalMetaData*>(
			static_cast<std::byte*>(po_Shadow->m_RawPtr) +
			po_Shadow->m_Offsets.m_MetaDataOffset
		);

		meta->m_TotalSize = po_Shadow->m_TotalSize;
		meta->m_TotalCommitted = po_Shadow->m_TotalSize; // initially whole block
		meta->m_TotalPoisoned = po_Shadow->m_TotalSize; // fully poisoned at init
		meta->m_AllocatorHash = MemoryZone::splitMix64(v_AllocatorID);

		return true;
	}

	bool KERBECS verifyTombstone(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		const std::byte* base = static_cast<const std::byte*>(po_Shadow->m_RawPtr);
		for (size_t i = 0; i < v_Length; i++) {
			if (base[v_Offset + i] != static_cast<std::byte>(MemoryZone::TOMBSTONE)) {
				return false; // some byte is not tombstone not destroyed
			}
		}
		return true;
	}

	bool KERBECS verifyMetadata(SHP po_Shadow, size_t v_ExpectedAllocatorID) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		auto* meta = reinterpret_cast<MemoryZone::NormalMetaData*>(
			static_cast<std::byte*>(po_Shadow->m_RawPtr) +
			po_Shadow->m_Offsets.m_MetaDataOffset
		);

		// Size check
		if (meta->m_TotalSize != po_Shadow->m_TotalSize) return false;

		// Allocator hash check
		if (meta->m_AllocatorHash != MemoryZone::splitMix64(v_ExpectedAllocatorID)) return false;

		// At this stage, we are not validating TotalCommitted/TotalPoisoned dynamically
		return true;
	}
}