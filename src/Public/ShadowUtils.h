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

namespace Kerbecs::Shadow::Utils {

	enum class KERBECS_RUNTIME_API MemoryState : uint8_t {
		UNINITIALIZED,
		CONSTRUCTED,
		DESTROYED,
		CORRUPTED
	};


	enum class KERBECS_RUNTIME_API ThreadPolicy : uint8_t {
		Strict,   // must be freed on the same thread that allocated
		Flexible  // cross-thread frees allowed (warn-only)
	};

	// DiagnosticAccess
	//
	// Controls whether a live access inside an engine-owned region (metadata,
	// guards) reports as EngineMemoryAccessViolation with real block info, or
	// stays the default UndefinedWildPointerAccess with block base/size
	// zeroed. Always present in both builds - deliberately not a build flag,
	// since a compile-time-invisible behavior difference is exactly what the
	// Philosophy Law forbids.
	enum class KERBECS_RUNTIME_API DiagnosticAccess : uint8_t {
		Restricted, // default - UndefinedWildPointerAccess always fires, block info zeroed
		Unlocked    // explicit opt-in - EngineMemoryAccessViolation fires with real block info
	};


	KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard validation check for tombstone")
	bool verifyTombstone(const void* p_Memory, size_t v_Length);

	KERBECS_RUNTIME_API KERBECS_NODISCARD_MSG("Cannot discard validation check for redzone ")
	bool verifyRedzone(const void* p_User, size_t v_Length);

	KERBECS_RUNTIME_API	KERBECS_NODISCARD_MSG("Cannot discard validation check for canaries")
	bool verifyCanaries(const void* p_User, size_t v_Length);

}
