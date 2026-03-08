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
#include <cstdint>

namespace Kerbecs {
	struct KERBECS_RUNTIME_API StackTrace {
		static constexpr size_t MAX_FRAMES = 16;
		void* m_Frames[MAX_FRAMES]{};
		size_t m_FrameCount = 0;
	};

	enum class KERBECS_RUNTIME_API ViolationKind : uint8_t {
		DoubleFree,          // destroy() called on already-destroyed block
		UseAfterFree,        // access to tombstoned or quarantined block
		UseBeforeInit,       // access to fully poisoned (never constructed) block
		BufferOverflow,      // redzone or canary pattern corrupted
		OverlapDetected,     // two tracked allocations overlap in VA
		LeakDetected,        // live allocation at shutdown
		MetadataCorruption,  // checksum or mirror mismatch in EnhancedMetaData
		AlignmentViolation,  // construct<T>() ptr % alignof(T) != 0
		SizeOverflow,        // blockSize<T>() multiplication overflowed
		WildPointer,         // access to address not in AllocationRegistry
		ThreadOwnership,      // destroy() called from wrong thread (Strict policy)
		QuarantineSaturation,     // quarantine ring buffer is full - fail fast
		RetiredBoundaryViolation,  // access to a Retiring block by a non-owner thread - fail fast
		None
	};

	struct KERBECS_RUNTIME_API Violation {
		ViolationKind m_Kind = ViolationKind::None;         // classification
		const char* m_Name = nullptr;         // named allocation tag (string literal, not owned)
		void* m_Address = nullptr;      // faulting address
		void* m_BlockBase = nullptr;    // start of the allocation block
		size_t        m_BlockSize{};    // total size of the allocation block
		StackTrace    m_AllocSite{};    // call stack at allocation time
		StackTrace    m_FreeSite{};     // call stack at free time (if applicable)
		StackTrace    m_AccessSite{};   // call stack at violation detection site
		uint64_t      m_Timestamp{};    // __rdtsc() at detection time
		uint32_t      m_ThreadID{};     // thread that triggered the violation
	};
} 