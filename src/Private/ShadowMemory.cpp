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
		std::memset(static_cast<std::byte*>(p_Memory) + v_Start, MemoryZone::GUARD_CANARY, v_Length);
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

	// poison a single byte at offset
	bool KERBECS poison(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawPoison(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	// unpoison a single byte at offset
	bool KERBECS unPoison(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawUnPoison(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	// poison a range
	bool KERBECS poisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawPoison(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// unpoison a range
	bool KERBECS unPoisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawUnPoison(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// redzone a single byte
	bool KERBECS redzone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawRedzone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	// clear redzone at a single byte
	bool KERBECS deRedzone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawDeRedzone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	// redzone a range
	bool KERBECS redzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawRedzone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// clear redzone over a range
	bool KERBECS deRedzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawDeRedzone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// verify that all redzones are intact (simple pattern check)
	bool KERBECS verifyRedzone(SHP po_Shadow) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;

		std::byte* base = static_cast<std::byte*>(po_Shadow->m_RawPtr);

		// check leading redzone
		for (size_t i = 0; i < po_Shadow->m_Offsets.m_UserDataOffset; ++i) {
			if (base[i] != static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false; // stomp detected
			}
		}

		// check trailing redzone
		size_t start = po_Shadow->m_Offsets.m_RedzoneOffsetTrailing;
		for (size_t i = 0; i < MemoryZone::REDZONE_SIZE; ++i) {
			if (base[start + i] != static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false; // stomp detected
			}
		}
		return true;
	}

	// tombstone a single byte
	bool KERBECS tombstone(SHP po_Shadow, size_t v_Offset) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawTombstone(po_Shadow->m_RawPtr, v_Offset, 1);
	}

	// tombstone a range
	bool KERBECS tombstoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length) {
		if (!po_Shadow || !po_Shadow->m_RawPtr) return false;
		return rawTombstone(po_Shadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Poison / Unpoison -----

	bool KERBECS poison(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawPoison(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS unPoison(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawUnPoison(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS poisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawPoison(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS unPoisonRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawUnPoison(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Redzones -----

	bool KERBECS redzone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS deRedzone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawDeRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS redzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	bool KERBECS deRedzoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawDeRedzone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

	// ----- Verify Redzones -----

	bool KERBECS verifyRedzone(ESHP po_EnhancedShadow) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;

		std::byte* base = static_cast<std::byte*>(po_EnhancedShadow->m_RawPtr);

		// leading redzone check
		for (size_t i = 0; i < MemoryZone::REDZONE_SIZE; ++i) {
			if (base[i] != static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false;
			}
		}

		// trailing redzone check
		size_t start = po_EnhancedShadow->m_Offsets.m_RedzoneOffsetTrailing;
		for (size_t i = 0; i < MemoryZone::REDZONE_SIZE; ++i) {
			if (base[start + i] != static_cast<std::byte>(MemoryZone::REDZONE)) {
				return false;
			}
		}

		return true;
	}

	// ----- Tombstones -----

	bool KERBECS tombstone(ESHP po_EnhancedShadow, size_t v_Offset) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawTombstone(po_EnhancedShadow->m_RawPtr, v_Offset, 1);
	}

	bool KERBECS tombstoneRange(ESHP po_EnhancedShadow, size_t v_Offset, size_t v_Length) {
		if (!po_EnhancedShadow || !po_EnhancedShadow->m_RawPtr) return false;
		return rawTombstone(po_EnhancedShadow->m_RawPtr, v_Offset, v_Length);
	}

}