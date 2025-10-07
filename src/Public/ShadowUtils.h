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

namespace Kerbecs::Utils {
	enum class KERBECS MemoryState : uint8_t {
		UNINITIALIZED, CONSTRUCTED, DESTROYED, CORRUPTED
	};

	enum class KERBECS ThreadPolicy : uint8_t {
		Strict,   // must be freed on the same thread that allocated
		Flexible  // cross-thread frees allowed (warn-only)
	};

	bool KERBECS rawPoison(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawRedzone(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawUnPoison(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawDeRedzone(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawCanary(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawRemoveCanary(void* p_Memory, size_t v_Start, size_t v_Length);
	bool KERBECS rawTombstone(void* p_Memory, size_t v_Start, size_t v_Length);
	size_t KERBECS countShadowPoisons(void* p_User, size_t v_Length);
	bool KERBECS verifyTombstone(const void* p_Memory, size_t v_Length);
	bool KERBECS verifyRedzone(void* p_User, size_t v_Length);
	bool KERBECS verifyCanaries(void* p_User, size_t v_Length);
	MemoryState KERBECS getMemoryState(void* p_User, size_t v_Length);

}
