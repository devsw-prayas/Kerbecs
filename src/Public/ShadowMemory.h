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
#include "Kerbecs.h"
#include "MemoryZone.h"

namespace Kerbecs::Shadow {
	typedef MemoryZone::Shadow* SHP;
	typedef MemoryZone::EnhancedShadow* ESHP;
	enum class KERBECS ShadowMode : uint8_t {
		NORMAL, ENHANCED
	};

	inline bool KERBECS init(SHP po_Shadow, void* p_Memory, size_t v_Size);
	inline SHP KERBECS allocate(size_t v_Bytes);
	inline bool KERBECS deallocate(SHP po_Shadow);

	template<typename T, typename...Args>
	bool KERBECS construct(SHP po_Shadow, Args&&...u_Args);

	template<typename T>
	bool KERBECS destroy(SHP po_Shadow);

	bool KERBECS poison(SHP po_Shadow, size_t v_Offset);
	bool KERBECS unPoison(SHP po_Shadow, size_t v_Offset);

	bool KERBECS poisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS unPoisonRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);

	bool KERBECS redzone(SHP po_Shadow, size_t v_Offset);
	bool KERBECS deRedzone(SHP po_Shadow, size_t v_Offset);

	bool KERBECS redzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS deRedzoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);

	bool KERBECS verifyRedzone(SHP po_Shadow);

	bool KERBECS tombstone(SHP po_Shadow, size_t v_Offset);
	bool KERBECS tombstoneRange(SHP po_Shadow, size_t v_Offset, size_t v_Length);


	inline bool KERBECS init(ESHP po_EnhancedShadow, void* p_Memory, size_t v_Size);
	inline ESHP KERBECS allocate(size_t v_Bytes);
	inline bool KERBECS deallocate(ESHP po_Shadow);

	template<typename T, typename...Args>
	bool KERBECS construct(ESHP po_Shadow, Args&&...u_Args);

	template<typename T>
	bool KERBECS destroy(ESHP po_Shadow);

	bool KERBECS poison(ESHP po_Shadow, size_t v_Offset);
	bool KERBECS unPoison(ESHP po_Shadow, size_t v_Offset);

	bool KERBECS poisonRange(ESHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS unPoisonRange(ESHP po_Shadow, size_t v_Offset, size_t v_Length);

	bool KERBECS redzone(ESHP po_Shadow, size_t v_Offset);
	bool KERBECS deRedzone(ESHP po_Shadow, size_t v_Offset);

	bool KERBECS redzoneRange(ESHP po_Shadow, size_t v_Offset, size_t v_Length);
	bool KERBECS deRedzoneRange(ESHP po_Shadow, size_t v_Offset, size_t v_Length);

	bool KERBECS verifyRedzone(ESHP po_Shadow);

	bool KERBECS tombstone(ESHP po_Shadow, size_t v_Offset);
	bool KERBECS tombstoneRange(ESHP po_Shadow, size_t v_Offset, size_t v_Length);
}
